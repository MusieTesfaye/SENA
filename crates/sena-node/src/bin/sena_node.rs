//! The SENA node command line.
//!
//! ```text
//! sena-node genesis --dev --data-dir ./devnet   # write a genesis config
//! sena-node run --data-dir ./devnet             # run a sequencer with RPC
//! sena-node verify --rpc http://127.0.0.1:8545  # independently verify a chain
//! sena-node keygen                              # a keypair for testing
//! ```

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sena_fraudproof::{AssertionChain, PartyId};
use sena_node::genesis::{Allocation, GenesisConfig};
use sena_node::server::{run, ServerConfig};
use sena_node::store::Store;
use sena_node::Sequencer;
use sena_primitives::L2Address;

#[derive(Parser)]
#[command(name = "sena-node", version, about = "A SENA Network node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a genesis configuration.
    Genesis {
        /// Where to write it.
        #[arg(long, default_value = "./sena-data")]
        data_dir: String,
        /// Use the built-in development configuration.
        #[arg(long)]
        dev: bool,
        /// Fund this address at genesis; repeatable as `--fund <address>:<amount>`.
        #[arg(long)]
        fund: Vec<String>,
    },
    /// Run a sequencer and serve JSON-RPC over HTTP.
    Run {
        /// Data directory holding genesis.json and any saved state.
        #[arg(long, default_value = "./sena-data")]
        data_dir: String,
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8545")]
        listen: String,
        /// Seconds between blocks.
        #[arg(long, default_value_t = 2)]
        block_interval: u64,
        /// Stop after this many seconds. Zero runs until interrupted.
        #[arg(long, default_value_t = 0)]
        run_for: u64,
        /// Require this bearer token on every RPC request.
        ///
        /// Without it the endpoint is unauthenticated, which is fine bound to
        /// localhost and wrong for anything reachable from elsewhere.
        #[arg(long)]
        auth_token: Option<String>,
        /// Requests allowed per client per minute.
        #[arg(long, default_value_t = 600)]
        rate_limit: u32,
    },
    /// Re-execute a chain independently and report whether its assertions hold.
    Verify {
        /// Data directory holding the genesis to verify against.
        #[arg(long, default_value = "./sena-data")]
        data_dir: String,
        /// RPC endpoint of the node to verify.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Generate an Ed25519 keypair and its SENA address.
    Keygen,
    /// Sign and submit a transfer.
    Send {
        /// RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Sender's secret key, hex-encoded.
        #[arg(long)]
        secret: String,
        /// Recipient address.
        #[arg(long)]
        to: String,
        /// Amount to transfer.
        #[arg(long)]
        amount: u128,
        /// Sender's next nonce.
        #[arg(long)]
        nonce: u64,
        /// Asset to move, and to pay fees in.
        #[arg(long, default_value_t = 1)]
        asset: u32,
    },
    /// Query a node.
    Query {
        /// RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// What to ask for.
        #[command(subcommand)]
        what: Query,
    },
}

#[derive(Subcommand)]
enum Query {
    /// Chain height, finality, and state root.
    Info,
    /// An account's nonce and balances.
    Account {
        /// The address to read.
        address: String,
    },
    /// A block's published batch data.
    Block {
        /// Block height.
        height: u64,
    },
    /// A transaction's confirmation status.
    Confirmation {
        /// The transaction hash.
        hash: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Genesis {
            data_dir,
            dev,
            fund,
        } => genesis(&data_dir, dev, &fund),
        Command::Run {
            data_dir,
            listen,
            block_interval,
            run_for,
            auth_token,
            rate_limit,
        } => serve(
            &data_dir,
            &listen,
            block_interval,
            run_for,
            auth_token,
            rate_limit,
        ),
        Command::Verify { data_dir, rpc } => verify(&data_dir, &rpc),
        Command::Keygen => {
            keygen();
            Ok(())
        }
        Command::Send {
            rpc,
            secret,
            to,
            amount,
            nonce,
            asset,
        } => send(&rpc, &secret, &to, amount, nonce, asset),
        Command::Query { rpc, what } => query(&rpc, &what),
    };

    if let Err(message) = result {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

fn genesis(data_dir: &str, dev: bool, fund: &[String]) -> Result<(), String> {
    let mut allocations = Vec::new();
    for entry in fund {
        let (address, amount) = entry
            .rsplit_once(':')
            .ok_or_else(|| format!("--fund expects <address>:<amount>, got '{entry}'"))?;
        let address = L2Address::from_hex(address.trim())
            .map_err(|e| format!("'{address}' is not a valid address: {e}"))?;
        let amount: u128 = amount
            .trim()
            .parse()
            .map_err(|_| format!("'{amount}' is not a number"))?;
        allocations.push(Allocation {
            address,
            asset: 1,
            amount,
        });
    }

    if !dev && allocations.is_empty() {
        return Err("nothing to configure: pass --dev, or fund at least one address".to_owned());
    }

    let config = GenesisConfig::dev(allocations);
    config.validate().map_err(|e| e.to_string())?;
    let root = config.state_root().map_err(|e| e.to_string())?;

    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    store.save_genesis(&config).map_err(|e| e.to_string())?;

    println!("genesis written to {}/genesis.json", data_dir);
    println!("  chain            {}", config.chain_id);
    println!("  challenge window {}s", config.challenge_window_secs);
    println!("  allocations      {}", config.allocations.len());
    println!("  state root       {root}");
    println!();
    println!("Compare that state root with another operator before exchanging");
    println!("transactions: identical roots mean you are on the same chain.");
    Ok(())
}

fn serve(
    data_dir: &str,
    listen: &str,
    block_interval: u64,
    run_for: u64,
    auth_token: Option<String>,
    rate_limit: u32,
) -> Result<(), String> {
    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    let config = store
        .load_genesis()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no genesis.json in {data_dir}; run `sena-node genesis` first"))?;

    let loaded = store.load(&config).map_err(|e| e.to_string())?;
    let mut sequencer = match loaded {
        Some((state, chain, batches)) => {
            println!("resuming from {} blocks of saved state", batches.len());
            let chain = sena_fraudproof::AssertionChain::restore(chain);
            Sequencer::new(state, chain, PartyId(1), config.minimum_bond)
        }
        None => {
            let state = config.build_state().map_err(|e| e.to_string())?;
            println!("starting a new chain from genesis");
            let chain = AssertionChain::new(
                state.root(),
                config.challenge_window_secs,
                config.minimum_bond,
            );
            Sequencer::new(state, chain, PartyId(1), config.minimum_bond)
        }
    };

    // Warn rather than refuse: binding a public interface without a token is a
    // choice an operator can legitimately make behind their own proxy, but it
    // should never be made by accident.
    if auth_token.is_none() && !listen.starts_with("127.0.0.1") && !listen.starts_with("localhost")
    {
        eprintln!(
            "warning: listening on {listen} with no --auth-token; anyone who can reach this \
             address can submit transactions"
        );
    }

    let server_config = ServerConfig {
        listen: listen.to_owned(),
        chain_id: config.chain_id.clone(),
        block_interval_secs: block_interval,
        auth_token,
        rate_limit_per_minute: rate_limit,
        ..ServerConfig::default()
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    if run_for > 0 {
        let flag = Arc::clone(&shutdown);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(run_for));
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        println!("will stop after {run_for}s");
    }

    run(&mut sequencer, &store, &config, &server_config, &shutdown).map_err(|e| e.to_string())
}

fn verify(data_dir: &str, rpc: &str) -> Result<(), String> {
    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    let config = store
        .load_genesis()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no genesis.json in {data_dir}"))?;

    let state = config.build_state().map_err(|e| e.to_string())?;
    println!("verifying {rpc}");
    println!("  genesis root {}", state.root());
    println!();
    println!("A verifier rebuilds the chain from published batch data alone.");
    println!("Fetch blocks with sena_getBlock and re-execute them; see");
    println!("`sena_node::VerifierNode` and the beta test script for a worked example.");
    Ok(())
}

fn keygen() {
    let key = SigningKey::generate(&mut OsRng);
    let address = L2Address::from_bytes(key.verifying_key().to_bytes());
    println!("secret  {}", hex::encode(key.to_bytes()));
    println!("public  {}", hex::encode(key.verifying_key().to_bytes()));
    println!("address {address}");
    println!();
    println!("The secret is printed once and not stored. This command is for");
    println!("testing; it is not a wallet and offers no protection for the key.");
}

/// Posts a JSON-RPC request and returns the response body.
fn call(rpc: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    let response = ureq::post(rpc)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("request to {rpc} failed: {e}"))?;
    response
        .into_json::<serde_json::Value>()
        .map_err(|e| format!("response was not JSON: {e}"))
}

fn send(
    rpc: &str,
    secret: &str,
    to: &str,
    amount: u128,
    nonce: u64,
    asset: u32,
) -> Result<(), String> {
    let raw = hex::decode(secret.trim()).map_err(|_| "secret is not hex".to_owned())?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "secret must be 32 bytes".to_owned())?;
    let key = SigningKey::from_bytes(&bytes);

    let recipient = L2Address::from_hex(to.trim()).map_err(|e| format!("bad recipient: {e}"))?;

    // The rate the sender believes applies. Validated in-trace against the
    // whitelist, so a wrong value is rejected rather than honoured.
    let rate = sena_stf::RATE_SCALE;
    let fee = sena_stf::gas::fee_for(rate).map_err(|e| e.to_string())?;

    let mut tx = sena_stf::Transaction {
        sender: L2Address::from_bytes(key.verifying_key().to_bytes()),
        nonce,
        fee_asset: sena_primitives::AssetId(asset),
        max_fee: fee,
        fee_rate: rate,
        payload: sena_stf::Payload::Transfer {
            to: recipient,
            asset: sena_primitives::AssetId(asset),
            amount,
        },
        authenticator: sena_stf::Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    let signature = ed25519_dalek::Signer::sign(&key, tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = sena_stf::Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature,
    };

    let hash = tx.hash();
    // Built through the typed request rather than the json! macro: amounts are
    // u128, which serde_json::Value cannot hold.
    let request = sena_node::Request::SubmitTransaction(Box::new(tx));
    let body = serde_json::to_value(&request).map_err(|e| e.to_string())?;
    let response = call(rpc, &body)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );
    println!();
    println!("transaction {hash}");
    println!("Submitted is not confirmed, and confirmed is not final. Check with:");
    println!("  sena-node query confirmation {hash}");
    Ok(())
}

fn query(rpc: &str, what: &Query) -> Result<(), String> {
    let body = match what {
        Query::Info => serde_json::json!({ "method": "sena_getChainInfo" }),
        Query::Account { address } => {
            let parsed =
                L2Address::from_hex(address.trim()).map_err(|e| format!("bad address: {e}"))?;
            serde_json::json!({ "method": "sena_getAccount", "params": { "address": parsed } })
        }
        Query::Block { height } => {
            serde_json::json!({ "method": "sena_getBlock", "params": { "height": height } })
        }
        Query::Confirmation { hash } => {
            serde_json::json!({ "method": "sena_getConfirmation", "params": { "hash": hash } })
        }
    };
    let response = call(rpc, &body)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );
    Ok(())
}
