//! The HTTP JSON-RPC server.
//!
//! A thin transport over [`crate::rpc::handle`], which holds the actual logic
//! and does no I/O. Keeping them separate means the RPC surface stays testable
//! without a socket, and the transport can be replaced without touching
//! behaviour.
//!
//! Single-threaded and blocking by design. The sequencer owns mutable state and
//! orders transactions, so serving requests one at a time is not a limitation
//! to be engineered around — it is what ordering means. Throughput work belongs
//! in batch execution, not in parallel request handling.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tiny_http::{Header, Method, Response as HttpResponse, Server};

use crate::rpc::{handle, Request, Response};
use crate::sequencer::Sequencer;
use crate::store::Store;

/// How the node should run.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Address to listen on.
    pub listen: String,
    /// The chain this node serves.
    pub chain_id: String,
    /// Seconds between block production attempts.
    pub block_interval_secs: u64,
    /// How many transactions a block may contain.
    pub max_block_transactions: usize,
    /// Seconds between writing state to disk.
    pub persist_interval_secs: u64,
    /// Bearer token required on every request, if set.
    ///
    /// `None` means unauthenticated, which is correct for a local devnet and
    /// wrong for anything reachable from outside the machine.
    pub auth_token: Option<String>,
    /// Requests allowed per client per minute.
    pub rate_limit_per_minute: u32,
    /// Largest request body accepted, in bytes.
    pub max_body_bytes: usize,
}

/// A fixed-window request counter, keyed by client.
///
/// Deliberately simple: a token bucket per IP would be better behaved under
/// bursty load, but this is the difference between an endpoint that can be
/// trivially flooded and one that cannot, and it has no dependencies.
#[derive(Debug, Default)]
struct RateLimiter {
    /// Client to (window start, requests in window).
    seen: BTreeMap<String, (u64, u32)>,
}

impl RateLimiter {
    /// Records a request, returning whether it is within the limit.
    fn allow(&mut self, client: &str, now: u64, limit: u32) -> bool {
        let window = now / 60;

        // Bound memory first: a flood of distinct clients must not grow this
        // without limit, and dropping stale windows is exactly what a fixed
        // window permits.
        if self.seen.len() > 4_096 {
            self.seen.retain(|_, (w, _)| *w == window);
        }

        let entry = self.seen.entry(client.to_owned()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8545".to_owned(),
            chain_id: "sena-devnet-1".to_owned(),
            block_interval_secs: 2,
            max_block_transactions: 512,
            persist_interval_secs: 10,
            auth_token: None,
            rate_limit_per_minute: 600,
            max_body_bytes: 1 << 20,
        }
    }
}

/// Why the server stopped.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The listener could not be bound.
    #[error("cannot listen on {address}: {detail}")]
    Bind {
        /// The address that failed.
        address: String,
        /// Why.
        detail: String,
    },
    /// Persisting state failed.
    #[error("persisting state failed: {0}")]
    Store(#[from] crate::store::StoreError),
}

/// Returns the current Unix time in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Runs the node until `shutdown` is set.
///
/// The loop interleaves three jobs on one thread: serving requests, producing
/// blocks on an interval, and persisting periodically. Request handling uses a
/// short receive timeout so block production is never starved by an idle
/// connection.
///
/// # Errors
///
/// Returns [`ServerError`] if the address cannot be bound or a persist fails.
///
/// # Panics
///
/// Does not panic: the only `expect` is on a static header value.
pub fn run(
    sequencer: &mut Sequencer,
    store: &Store,
    genesis: &crate::genesis::GenesisConfig,
    config: &ServerConfig,
    shutdown: &Arc<AtomicBool>,
) -> Result<(), ServerError> {
    let server = Server::http(&config.listen).map_err(|e| ServerError::Bind {
        address: config.listen.clone(),
        detail: e.to_string(),
    })?;

    println!("sena-node listening on http://{}", config.listen);
    println!("  chain            {}", config.chain_id);
    println!("  block interval   {}s", config.block_interval_secs);
    println!("  challenge window {}s", sequencer.chain.challenge_window());
    println!("  state root       {}", sequencer.state.root());
    println!("  data directory   {}", store.path().display());
    println!(
        "  auth             {}",
        if config.auth_token.is_some() {
            "bearer token required"
        } else {
            "NONE (local use only)"
        }
    );
    println!(
        "  rate limit       {}/min per client",
        config.rate_limit_per_minute
    );

    let mut limiter = RateLimiter::default();
    let mut last_block = unix_now();
    let mut last_persist = unix_now();

    while !shutdown.load(Ordering::Relaxed) {
        // Keep the L1 clock in step with real time so challenge windows elapse.
        let now = unix_now();
        let _ = sequencer.chain.advance_to(now);

        if now.saturating_sub(last_block) >= config.block_interval_secs {
            last_block = now;
            match sequencer.produce(config.max_block_transactions) {
                Ok(Some((block, id))) => {
                    println!(
                        "block {} sealed: {} txs, {} steps, root {}, assertion {}",
                        block.height,
                        block.transactions.len(),
                        block.trace.len(),
                        block.post_state_root,
                        hex::encode(&id.0.as_bytes()[..8]),
                    );
                }
                Ok(None) => {}
                Err(error) => eprintln!("block production failed: {error}"),
            }
            finalize_due(sequencer);
        }

        if now.saturating_sub(last_persist) >= config.persist_interval_secs {
            last_persist = now;
            store.save(
                genesis,
                &sequencer.state,
                &sequencer.chain.snapshot(),
                &sequencer.blocks,
            )?;
        }

        match server.recv_timeout(Duration::from_millis(200)) {
            Ok(Some(mut request)) => {
                let response = serve(sequencer, config, &mut limiter, &mut request);
                let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .expect("static header is valid");
                let _ = request.respond(HttpResponse::from_string(response).with_header(header));
            }
            Ok(None) => {}
            Err(error) => eprintln!("request error: {error}"),
        }
    }

    // A final persist, so a clean shutdown never loses the last few blocks.
    store.save(
        genesis,
        &sequencer.state,
        &sequencer.chain.snapshot(),
        &sequencer.blocks,
    )?;
    println!("state persisted to {}", store.path().display());
    Ok(())
}

/// Finalizes every assertion whose challenge window has elapsed.
///
/// Walked oldest-first because an assertion cannot finalize ahead of its parent.
fn finalize_due(sequencer: &mut Sequencer) {
    let heights: Vec<u64> = (1..=sequencer.blocks.len() as u64).collect();
    for height in heights {
        if let Some(id) = sequencer.assertion_for(height) {
            if sequencer.chain.finalize(&id).is_ok() {
                println!("assertion for block {height} finalized on L1");
            }
        }
    }
}

fn serve(
    sequencer: &mut Sequencer,
    config: &ServerConfig,
    limiter: &mut RateLimiter,
    request: &mut tiny_http::Request,
) -> String {
    if *request.method() != Method::Post {
        return error_json("send a JSON-RPC request as an HTTP POST body");
    }

    // Authenticate before doing any work, so an unauthorised caller cannot make
    // the node parse a megabyte of JSON on their behalf.
    if let Some(expected) = &config.auth_token {
        let presented = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_owned())
            .unwrap_or_default();
        let offered = presented.strip_prefix("Bearer ").unwrap_or(&presented);
        // Length-independent comparison is unnecessary here: the token is a
        // shared secret over a local transport, not a per-message MAC.
        if offered != expected {
            return error_json("unauthorised: a valid bearer token is required");
        }
    }

    let client = request
        .remote_addr()
        .map_or_else(|| "unknown".to_owned(), |addr| addr.ip().to_string());
    if !limiter.allow(&client, unix_now(), config.rate_limit_per_minute) {
        return error_json("rate limit exceeded");
    }

    // A body larger than the cap is refused without being read into memory.
    if let Some(len) = request.body_length() {
        if len > config.max_body_bytes {
            return error_json(&format!(
                "request body of {len} bytes exceeds the {} byte limit",
                config.max_body_bytes
            ));
        }
    }

    let mut body = String::new();
    let cap = config.max_body_bytes as u64;
    let mut capped_reader = std::io::Read::take(request.as_reader(), cap);
    if std::io::Read::read_to_string(&mut capped_reader, &mut body).is_err() {
        return error_json("request body could not be read");
    }

    let parsed: Request = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(error) => return error_json(&format!("malformed request: {error}")),
    };

    let response = handle(sequencer, &config.chain_id, parsed);
    serde_json::to_string(&response)
        .unwrap_or_else(|_| error_json("response could not be serialised"))
}

fn error_json(message: &str) -> String {
    serde_json::to_string(&Response::Error {
        message: message.to_owned(),
    })
    .unwrap_or_else(|_| "{\"result\":\"error\",\"message\":\"internal\"}".to_owned())
}
