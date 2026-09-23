//! End-to-end beta test: a real node, over real HTTP, verified independently.
//!
//! Everything else in the suite tests a component. This drives the whole system
//! the way an integrator would — start a node, submit signed transactions over
//! HTTP, wait for a block, then rebuild the chain from the published batch data
//! alone and check it agrees.
//!
//! That last step is the one that matters. A node reporting its own state root
//! proves nothing; re-deriving the same root from published data, without
//! trusting anything the node said about its own execution, is what the whole
//! protocol is for.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, L2Address};
use sena_stf::gas::fee_for;
use sena_stf::{execute_batch, Authenticator, Payload, Transaction, RATE_SCALE};

use sena_fraudproof::{AssertionChain, PartyId};
use sena_node::genesis::{Allocation, GenesisConfig};
use sena_node::server::{run, ServerConfig};
use sena_node::store::Store;
use sena_node::{Request, Response, Sequencer};

const USDC: AssetId = AssetId(1);

fn signer(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

fn address_of(key: &SigningKey) -> L2Address {
    L2Address::from_bytes(key.verifying_key().to_bytes())
}

fn signed(key: &SigningKey, nonce: u64, to: L2Address, amount: u128) -> Transaction {
    let rate = RATE_SCALE;
    let mut tx = Transaction {
        sender: address_of(key),
        nonce,
        fee_asset: USDC,
        max_fee: fee_for(rate).unwrap(),
        fee_rate: rate,
        payload: Payload::Transfer {
            to,
            asset: USDC,
            amount,
        },
        authenticator: Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature,
    };
    tx
}

/// Claims a free port by binding and releasing it, so parallel test runs do not
/// collide on a fixed one.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("a port should be available")
        .local_addr()
        .expect("bound listener has an address")
        .port()
}

fn call(endpoint: &str, request: &Request) -> Response {
    let body = serde_json::to_value(request).expect("request serialises");
    ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .send_json(body)
        .expect("node should respond")
        .into_json()
        .expect("response should be JSON")
}

/// A node running in a background thread, stopped when this is dropped.
struct TestNode {
    endpoint: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestNode {
    fn start(config: &GenesisConfig, data_dir: std::path::PathBuf) -> Self {
        let port = free_port();
        let endpoint = format!("http://127.0.0.1:{port}");
        let shutdown = Arc::new(AtomicBool::new(false));

        let store = Store::open(&data_dir).expect("store opens");
        store.save_genesis(config).expect("genesis saves");

        let state = config.build_state().expect("genesis builds");
        let chain = AssertionChain::new(
            state.root(),
            config.challenge_window_secs,
            config.minimum_bond,
        );
        let mut sequencer = Sequencer::new(state, chain, PartyId(1), config.minimum_bond);

        let server_config = ServerConfig {
            listen: format!("127.0.0.1:{port}"),
            chain_id: config.chain_id.clone(),
            block_interval_secs: 1,
            max_block_transactions: 512,
            persist_interval_secs: 1,
            // Unauthenticated with a generous limit: these tests exercise the
            // protocol, and access control has its own tests below.
            auth_token: None,
            rate_limit_per_minute: 10_000,
            max_body_bytes: 1 << 20,
        };

        let flag = Arc::clone(&shutdown);
        let owned_config = config.clone();
        let handle = thread::spawn(move || {
            let _ = run(&mut sequencer, &store, &owned_config, &server_config, &flag);
        });

        let node = Self {
            endpoint,
            shutdown,
            handle: Some(handle),
        };
        node.wait_until_serving();
        node
    }

    fn wait_until_serving(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let body = serde_json::to_value(Request::GetChainInfo).expect("serialises");
            if ureq::post(&self.endpoint)
                .set("Content-Type", "application/json")
                .send_json(body)
                .is_ok()
            {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("node did not start serving within 10s");
    }

    /// Waits until the chain reaches `height`, returning how long it took.
    fn wait_for_height(&self, height: u64) -> Duration {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Response::ChainInfo {
                height: current, ..
            } = call(&self.endpoint, &Request::GetChainInfo)
            {
                if current >= height {
                    return started.elapsed();
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("chain did not reach height {height} within 20s");
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn dev_genesis(funded: &SigningKey) -> GenesisConfig {
    GenesisConfig::dev(vec![Allocation {
        address: address_of(funded),
        asset: 1,
        amount: 100_000_000,
    }])
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join("sena-beta-e2e")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn a_node_serves_rpc_and_seals_blocks() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let config = dev_genesis(&alice);
    let node = TestNode::start(&config, temp_dir("seals"));

    // The chain identifies itself before anything else, so a client can tell
    // whether it is talking to the network it thinks it is.
    match call(&node.endpoint, &Request::GetChainInfo) {
        Response::ChainInfo {
            chain_id,
            height,
            state_root,
            ..
        } => {
            assert_eq!(chain_id, "sena-devnet-1");
            assert_eq!(height, 0);
            assert_eq!(state_root, config.state_root().unwrap());
        }
        other => panic!("unexpected response: {other:?}"),
    }

    for nonce in 0..5 {
        let tx = signed(&alice, nonce, bob, 1_000);
        match call(&node.endpoint, &Request::SubmitTransaction(Box::new(tx))) {
            Response::Submitted { confirmation, .. } => {
                assert_eq!(confirmation, sena_node::Confirmation::Pending);
            }
            other => panic!("submission rejected: {other:?}"),
        }
    }

    let elapsed = node.wait_for_height(1);
    println!("block 1 sealed in {elapsed:?}");

    match call(&node.endpoint, &Request::GetAccount { address: bob }) {
        Response::Account { balances, .. } => assert_eq!(balances, vec![(1, 5_000)]),
        other => panic!("unexpected response: {other:?}"),
    }

    // 5 transfers of 1,000 plus 5 fees of 1,000.
    match call(
        &node.endpoint,
        &Request::GetAccount {
            address: address_of(&alice),
        },
    ) {
        Response::Account { nonce, balances } => {
            assert_eq!(nonce, 5);
            assert_eq!(balances, vec![(1, 100_000_000 - 10_000)]);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn published_batch_data_reproduces_the_asserted_root() {
    // The load-bearing test. A verifier takes only what the node published --
    // the transactions -- re-executes from genesis, and must reach the same
    // root the node asserted. Nothing the node claims about its own execution
    // is trusted.
    let alice = signer(3);
    let bob = address_of(&signer(4));
    let config = dev_genesis(&alice);
    let node = TestNode::start(&config, temp_dir("verify"));

    for nonce in 0..6 {
        let tx = signed(&alice, nonce, bob, 500 + u128::from(nonce));
        call(&node.endpoint, &Request::SubmitTransaction(Box::new(tx)));
    }
    node.wait_for_height(1);

    let (transactions, asserted_root, pre_root, trace_length) =
        match call(&node.endpoint, &Request::GetBlock { height: 1 }) {
            Response::Block {
                transactions,
                post_state_root,
                pre_state_root,
                trace_length,
                ..
            } => (transactions, post_state_root, pre_state_root, trace_length),
            other => panic!("unexpected response: {other:?}"),
        };

    assert!(
        !transactions.is_empty(),
        "the node must publish its batch data"
    );

    // Rebuild independently from genesis.
    let mut independent = config.build_state().expect("genesis builds");
    assert_eq!(
        independent.root(),
        pre_root,
        "the block must start from genesis"
    );

    let trace =
        execute_batch(&mut independent, &transactions).expect("published batch must execute");

    assert_eq!(
        independent.root(),
        asserted_root,
        "independent re-execution must reproduce the asserted root"
    );
    assert_eq!(
        trace.len() as u64,
        trace_length,
        "the asserted trace length must match what execution produces"
    );
    println!(
        "verified block 1 independently: {} txs, {} steps, root {asserted_root}",
        transactions.len(),
        trace.len()
    );
}

#[test]
fn a_node_resumes_from_disk_with_the_same_state() {
    // A node that forgets on restart is a demo. The snapshot records its own
    // root and is rejected if rebuilding does not reproduce it.
    let alice = signer(5);
    let bob = address_of(&signer(6));
    let config = dev_genesis(&alice);
    let data_dir = temp_dir("resume");

    let (root_before, height_before) = {
        let node = TestNode::start(&config, data_dir.clone());
        for nonce in 0..4 {
            call(
                &node.endpoint,
                &Request::SubmitTransaction(Box::new(signed(&alice, nonce, bob, 250))),
            );
        }
        node.wait_for_height(1);
        // Give the persist interval a chance to fire before shutdown.
        thread::sleep(Duration::from_millis(1_200));

        match call(&node.endpoint, &Request::GetChainInfo) {
            Response::ChainInfo {
                state_root, height, ..
            } => (state_root, height),
            other => panic!("unexpected response: {other:?}"),
        }
        // node stops here, persisting on the way out
    };

    let store = Store::open(&data_dir).expect("store reopens");
    let (state, chain, batches) = store
        .load(&config)
        .expect("saved state loads")
        .expect("there should be saved state");

    assert_eq!(
        state.root(),
        root_before,
        "restored state must match what was saved"
    );
    assert_eq!(
        batches.len() as u64,
        height_before,
        "batch data must survive too"
    );
    assert!(chain.challenge_window >= sena_fraudproof::CHALLENGE_WINDOW_FLOOR);

    // And the retained batch data still reproduces the state, which is what a
    // verifier would need after the node restarts.
    let mut rebuilt = config.build_state().expect("genesis builds");
    for batch in &batches {
        execute_batch(&mut rebuilt, batch).expect("retained batch executes");
    }
    assert_eq!(
        rebuilt.root(),
        root_before,
        "retained data must rebuild the state"
    );
}

#[test]
fn a_node_refuses_to_start_on_state_it_cannot_verify() {
    // A node whose job is to agree with everyone else must refuse to serve
    // state it cannot reproduce, rather than quietly serving something nobody
    // else believes.
    let alice = signer(7);
    let config = dev_genesis(&alice);
    let data_dir = temp_dir("corrupt");

    {
        let node = TestNode::start(&config, data_dir.clone());
        call(
            &node.endpoint,
            &Request::SubmitTransaction(Box::new(signed(&alice, 0, address_of(&signer(8)), 10))),
        );
        node.wait_for_height(1);
        thread::sleep(Duration::from_millis(1_200));
    }

    let state_file = data_dir.join("state.bin");
    let mut bytes = std::fs::read(&state_file).expect("state file exists");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&state_file, &bytes).expect("state file writable");

    let store = Store::open(&data_dir).expect("store opens");
    let error = store
        .load(&config)
        .expect_err("corrupt state must be refused");
    let message = error.to_string();
    assert!(
        message.contains("verification") || message.contains("root"),
        "the error should name the verification failure, got: {message}"
    );
}

#[test]
fn a_data_directory_cannot_be_reused_across_chains() {
    // Pointing a node at another chain's data directory silently would put it
    // on a fork of its own making.
    let alice = signer(9);
    let config = dev_genesis(&alice);
    let data_dir = temp_dir("mismatch");

    {
        let node = TestNode::start(&config, data_dir.clone());
        node.wait_until_serving();
        thread::sleep(Duration::from_millis(1_200));
    }

    // A different genesis: same shape, different allocation.
    let mut other = dev_genesis(&signer(10));
    other.chain_id = "sena-other-1".to_owned();

    let store = Store::open(&data_dir).expect("store opens");
    match store.load(&other) {
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains("genesis"),
                "the error should name the genesis mismatch, got: {message}"
            );
        }
        Ok(None) => panic!("there should be saved state to reject"),
        Ok(Some(_)) => panic!("a different chain's genesis must not be accepted"),
    }
}

// --- Access control ----------------------------------------------------------

/// Starts a node that requires a bearer token.
fn start_authenticated(
    config: &GenesisConfig,
    data_dir: std::path::PathBuf,
    token: &str,
) -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let port = free_port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let shutdown = Arc::new(AtomicBool::new(false));

    let store = Store::open(&data_dir).expect("store opens");
    store.save_genesis(config).expect("genesis saves");
    let state = config.build_state().expect("genesis builds");
    let chain = AssertionChain::new(
        state.root(),
        config.challenge_window_secs,
        config.minimum_bond,
    );
    let mut sequencer = Sequencer::new(state, chain, PartyId(1), config.minimum_bond);

    let server_config = ServerConfig {
        listen: format!("127.0.0.1:{port}"),
        chain_id: config.chain_id.clone(),
        block_interval_secs: 1,
        max_block_transactions: 512,
        persist_interval_secs: 60,
        auth_token: Some(token.to_owned()),
        rate_limit_per_minute: 5,
        max_body_bytes: 2_048,
    };

    let flag = Arc::clone(&shutdown);
    let owned = config.clone();
    let handle = thread::spawn(move || {
        let _ = run(&mut sequencer, &store, &owned, &server_config, &flag);
    });

    // Wait for it to accept connections.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ureq::post(&endpoint)
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(serde_json::to_value(Request::GetChainInfo).unwrap())
            .is_ok()
        {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    (endpoint, shutdown, handle)
}

/// Posts with an optional bearer token, returning the parsed response.
fn call_with_token(endpoint: &str, token: Option<&str>, request: &Request) -> Response {
    let body = serde_json::to_value(request).expect("serialises");
    let mut req = ureq::post(endpoint).set("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    req.send_json(body)
        .expect("node should respond")
        .into_json()
        .expect("response should be JSON")
}

#[test]
fn an_authenticated_node_refuses_requests_without_a_token() {
    let alice = signer(11);
    let config = dev_genesis(&alice);
    let (endpoint, shutdown, handle) =
        start_authenticated(&config, temp_dir("auth"), "correct-horse");

    // No token at all.
    match call_with_token(&endpoint, None, &Request::GetChainInfo) {
        Response::Error { message } => assert!(message.contains("unauthorised"), "{message}"),
        other => panic!("an unauthenticated request was served: {other:?}"),
    }

    // Wrong token.
    match call_with_token(&endpoint, Some("wrong"), &Request::GetChainInfo) {
        Response::Error { message } => assert!(message.contains("unauthorised"), "{message}"),
        other => panic!("a request with a wrong token was served: {other:?}"),
    }

    // Correct token.
    match call_with_token(&endpoint, Some("correct-horse"), &Request::GetChainInfo) {
        Response::ChainInfo { .. } => {}
        other => panic!("a correctly authenticated request was refused: {other:?}"),
    }

    shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn a_client_exceeding_the_rate_limit_is_refused() {
    // Without this an exposed endpoint is trivially flooded: every request
    // otherwise costs the node a JSON parse and a state read.
    let alice = signer(12);
    let config = dev_genesis(&alice);
    let (endpoint, shutdown, handle) = start_authenticated(&config, temp_dir("ratelimit"), "tok");

    let mut refused = 0;
    for _ in 0..12 {
        if let Response::Error { message } =
            call_with_token(&endpoint, Some("tok"), &Request::GetChainInfo)
        {
            if message.contains("rate limit") {
                refused += 1;
            }
        }
    }
    assert!(
        refused > 0,
        "the rate limit never engaged over 12 requests at a limit of 5"
    );

    shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn an_oversized_request_body_is_refused() {
    let alice = signer(13);
    let config = dev_genesis(&alice);
    let (endpoint, shutdown, handle) = start_authenticated(&config, temp_dir("bodycap"), "tok");

    let huge = "x".repeat(8_192);
    let response = ureq::post(&endpoint)
        .set("Authorization", "Bearer tok")
        .set("Content-Type", "application/json")
        .send_string(&huge);

    // Either refused with a message, or the connection rejected outright; both
    // are acceptable, silently parsing 8 KiB against a 2 KiB cap is not.
    if let Ok(resp) = response {
        let body: Response = resp.into_json().expect("JSON");
        match body {
            Response::Error { message } => {
                assert!(
                    message.contains("exceeds") || message.contains("malformed"),
                    "unexpected error: {message}"
                );
            }
            other => panic!("an oversized body was accepted: {other:?}"),
        }
    }

    shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn a_withdrawal_proof_is_refused_before_anything_finalizes() {
    // A proof against a non-finalized root would be rejected on chain, so the
    // node must not hand one out and let the user discover that as a failed
    // transaction.
    let alice = signer(14);
    let config = dev_genesis(&alice);
    let node = TestNode::start(&config, temp_dir("wproof"));

    match call(
        &node.endpoint,
        &Request::GetWithdrawalProof {
            address: address_of(&alice),
        },
    ) {
        Response::Error { message } => {
            assert!(message.contains("finalized"), "unexpected: {message}");
        }
        other => panic!("a proof was produced with nothing finalized: {other:?}"),
    }
}
