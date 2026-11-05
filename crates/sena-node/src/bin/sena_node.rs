//! The SENA node command line.
//!
//! ```text
//! sena-node genesis --dev --data-dir ./devnet   # write a genesis config
//! sena-node run --data-dir ./devnet             # run a sequencer with RPC
//! sena-node verify --rpc http://127.0.0.1:8545  # independently verify a chain
//! sena-node keygen                              # a keypair for testing
//! sena-node jwk-sync --key-file council.json    # follow Google's key rotations
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
    /// Print a genesis file's chain, transaction chain id and state root, as
    /// JSON, after validating it.
    InspectGenesis {
        /// Data directory holding genesis.json.
        #[arg(long, default_value = "./sena-data")]
        data_dir: String,
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
        /// This sequencer's L2 account, where tips are paid. Without it tips
        /// go to the fee vault with the base fee.
        #[arg(long)]
        fee_recipient: Option<String>,
        /// Let a web page at this origin call the node (CORS), e.g.
        /// `http://localhost:5173`; repeatable. Without it, browsers cannot.
        #[arg(long)]
        cors_origin: Vec<String>,
        /// Rate-limit by `X-Forwarded-For`, for a node reachable only through
        /// a reverse proxy that sets it. Never on a node clients reach directly.
        #[arg(long)]
        trust_forwarded_for: bool,
        /// Credit L1 deposits read from this Aptos fullnode REST endpoint,
        /// e.g. `http://127.0.0.1:8080/v1`. Needs `--deposits-contract`.
        #[arg(long, requires = "deposits_contract")]
        deposits_from: Option<String>,
        /// The address the SENA package and its chain live at on L1.
        #[arg(long, requires = "deposits_from")]
        deposits_contract: Option<String>,
        /// Seconds between reads of the L1 deposit log.
        #[arg(long, default_value_t = 15)]
        deposits_poll_secs: u64,
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
        /// Asset to move.
        #[arg(long, default_value_t = 1)]
        asset: u32,
        /// Whitelisted asset to pay the fee in; the moved asset if absent.
        #[arg(long)]
        fee_asset: Option<u32>,
        /// Tip per gas for the sequencer, in `PRICE_SCALE`ths of a unit.
        #[arg(long, default_value_t = 0)]
        tip: u128,
    },
    /// Sign and submit a withdrawal to Aptos L1: burn the amount on SENA and
    /// record that `--to` may claim it from the bridge once final.
    Withdraw {
        /// RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Sender's secret key, hex-encoded.
        #[arg(long)]
        secret: String,
        /// The Aptos address paid on L1.
        #[arg(long)]
        to: String,
        /// Amount to withdraw.
        #[arg(long)]
        amount: u128,
        /// Sender's next nonce.
        #[arg(long)]
        nonce: u64,
        /// Asset to withdraw; the fee is paid in it too.
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
    /// Post this sequencer's blocks to Aptos L1 as bonded assertions,
    /// defend them in disputes, and finalize them.
    Relay {
        /// L2 RPC endpoint of the sequencer.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Bearer token for the L2 RPC.
        #[arg(long)]
        rpc_token: Option<String>,
        #[command(flatten)]
        aptos: AptosArgs,
        /// Bond per assertion, in the bond asset's smallest unit.
        #[arg(long, default_value_t = 1_000_000)]
        bond: u128,
        /// Where progress is persisted.
        #[arg(long, default_value = "./sena-data/relayer.json")]
        state: String,
    },
    /// Keep the chain's accepted keyless JWKs in step with a provider's
    /// rotations, by council-signed `SetJwk` updates. For a test network
    /// whose council is this one key (threshold 1).
    /// Rename a fee asset (its symbol), as the council: a governance update
    /// that keeps the asset's rate, intrinsic gas and enabled flag.
    RenameAsset {
        /// L2 RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// JSON file with the council member's `secret` (hex).
        #[arg(long)]
        key_file: String,
        /// The asset to rename.
        #[arg(long)]
        asset: u32,
        /// Its new symbol.
        #[arg(long)]
        symbol: String,
        /// Asset the council pays the fee in.
        #[arg(long, default_value_t = 1)]
        fee_asset: u32,
    },
    JwkSync {
        /// L2 RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// JSON file with the council member's `secret` (hex). The same key
        /// sends the updates and pays their fees.
        #[arg(long)]
        key_file: String,
        /// The provider's issuer.
        #[arg(long, default_value = "https://accounts.google.com")]
        iss: String,
        /// The provider's JWKS endpoint.
        #[arg(long, default_value = "https://www.googleapis.com/oauth2/v3/certs")]
        jwks_url: String,
        /// Fee asset.
        #[arg(long, default_value_t = 1)]
        fee_asset: u32,
        /// Where accepted keys are remembered, to retire them once withdrawn.
        #[arg(long, default_value = "./sena-data/jwk-sync.json")]
        state: String,
        /// Seconds between rounds; zero runs one round and exits.
        #[arg(long, default_value_t = 3600)]
        interval: u64,
    },
    /// Watch Aptos L1, re-execute every assertion from the batch data
    /// published there, and challenge any that is wrong.
    Watch {
        /// Data directory holding the genesis to verify against.
        #[arg(long, default_value = "./sena-data")]
        data_dir: String,
        #[command(flatten)]
        aptos: AptosArgs,
        /// Bond per challenge, in the bond asset's smallest unit.
        #[arg(long, default_value_t = 1_000_000)]
        bond: u128,
        /// Where progress is persisted.
        #[arg(long, default_value = "./sena-data/watcher.json")]
        state: String,
        /// Poseidon steps per keyless-verdict transaction. The most expensive
        /// steps must fit one Aptos transaction's execution budget.
        #[arg(long, default_value_t = 12)]
        keyless_steps_per_tx: u64,
    },
}

/// How to reach and sign for Aptos L1.
#[derive(clap::Args)]
struct AptosArgs {
    /// Aptos fullnode REST endpoint.
    #[arg(long, default_value = "https://api.testnet.aptoslabs.com/v1")]
    aptos_url: String,
    /// Address the SENA package is published at.
    #[arg(long)]
    contract: String,
    /// Aptos CLI profile that signs (from `.aptos/config.yaml`).
    #[arg(long, default_value = "default")]
    profile: String,
    /// The profile's account address.
    #[arg(long)]
    account: String,
    /// Path to the `aptos` binary.
    #[arg(long, default_value = "aptos")]
    aptos_bin: String,
    /// Most gas units one transaction may use.
    #[arg(long, default_value_t = 2_000_000)]
    max_gas: u64,
    /// Seconds between rounds.
    #[arg(long, default_value_t = 10)]
    poll_interval: u64,
}

impl AptosArgs {
    fn client(&self) -> sena_node::l1::AptosCli {
        sena_node::l1::AptosCli {
            binary: self.aptos_bin.clone(),
            profile: self.profile.clone(),
            rest_url: self.aptos_url.clone(),
            contract: self.contract.clone(),
            account: self.account.clone(),
            max_gas: self.max_gas,
        }
    }
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
    /// Fetch and verify an account proof (ultralight mobile verification).
    Proof {
        /// The address to read.
        address: String,
        /// Target block height (defaults to current state).
        #[arg(long)]
        height: Option<u64>,
    },
    /// The proof `bridge::claim` needs for a withdrawal.
    Withdrawal {
        /// The account that withdrew.
        sender: String,
        /// The nonce of its withdrawing transaction.
        nonce: u64,
        /// Prove against this state root (a finalized assertion's); current if absent.
        #[arg(long)]
        state_root: Option<String>,
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
        Command::InspectGenesis { data_dir } => inspect_genesis(&data_dir),
        Command::Run {
            data_dir,
            listen,
            block_interval,
            run_for,
            auth_token,
            rate_limit,
            fee_recipient,
            cors_origin,
            trust_forwarded_for,
            deposits_from,
            deposits_contract,
            deposits_poll_secs,
        } => serve(
            &data_dir,
            run_for,
            fee_recipient.as_deref(),
            ServerConfig {
                listen,
                block_interval_secs: block_interval,
                auth_token,
                rate_limit_per_minute: rate_limit,
                cors_origins: cors_origin,
                trust_forwarded_for,
                deposits_from: deposits_from
                    .zip(deposits_contract)
                    .map(|(rest_url, contract)| sena_node::deposits::RestReader {
                        rest_url,
                        contract,
                    }),
                deposits_poll_secs,
                ..ServerConfig::default()
            },
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
            fee_asset,
            tip,
        } => send(
            &rpc,
            &secret,
            &Transfer {
                to,
                amount,
                nonce,
                asset,
                fee_asset: fee_asset.unwrap_or(asset),
                tip,
                withdraw: false,
            },
        ),
        Command::Withdraw {
            rpc,
            secret,
            to,
            amount,
            nonce,
            asset,
        } => send(
            &rpc,
            &secret,
            &Transfer {
                to,
                amount,
                nonce,
                asset,
                fee_asset: asset,
                tip: 0,
                withdraw: true,
            },
        ),
        Command::Query { rpc, what } => query(&rpc, &what),
        Command::Relay {
            rpc,
            rpc_token,
            aptos,
            bond,
            state,
        } => relay(rpc, rpc_token, &aptos, bond, state),
        Command::RenameAsset {
            rpc,
            key_file,
            asset,
            symbol,
            fee_asset,
        } => rename_asset(&rpc, &key_file, asset, symbol, fee_asset),
        Command::JwkSync {
            rpc,
            key_file,
            iss,
            jwks_url,
            fee_asset,
            state,
            interval,
        } => jwk_sync(rpc, &key_file, iss, jwks_url, fee_asset, state, interval),
        Command::Watch {
            data_dir,
            aptos,
            bond,
            state,
            keyless_steps_per_tx,
        } => watch(&data_dir, &aptos, bond, state, keyless_steps_per_tx),
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
    println!("  chain id         {}", config.transaction_chain_id());
    println!("  challenge window {}s", config.challenge_window_secs);
    println!("  allocations      {}", config.allocations.len());
    println!("  state root       {root}");
    println!();
    println!("Compare that state root with another operator before exchanging");
    println!("transactions: identical roots mean you are on the same chain.");
    Ok(())
}

fn inspect_genesis(data_dir: &str) -> Result<(), String> {
    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    let config = store
        .load_genesis()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no genesis.json in {data_dir}"))?;
    config.validate().map_err(|e| e.to_string())?;
    let root = config.state_root().map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({
            "chain": config.chain_id,
            "transaction_chain_id": config.transaction_chain_id(),
            "state_root": root.to_string(),
        })
    );
    Ok(())
}

fn serve(
    data_dir: &str,
    run_for: u64,
    fee_recipient: Option<&str>,
    server_config: ServerConfig,
) -> Result<(), String> {
    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    let config = store
        .load_genesis()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no genesis.json in {data_dir}; run `sena-node genesis` first"))?;

    let keyless = config.keyless_config().map_err(|e| e.to_string())?;
    match &keyless {
        Some(k) => println!("keyless accounts enabled ({})", k.name),
        None => println!("keyless accounts disabled (no `keyless` section in genesis)"),
    }
    let loaded = store.load(&config).map_err(|e| e.to_string())?;
    let sequencer = match loaded {
        Some((state, chain, batches)) => {
            println!("resuming: replaying {} saved blocks", batches.len());
            let genesis = config.build_state().map_err(|e| e.to_string())?;
            Sequencer::resume(
                genesis,
                sena_fraudproof::AssertionChain::restore(chain),
                PartyId(1),
                config.minimum_bond,
                keyless.clone(),
                config.transaction_chain_id(),
                &batches,
                state.root(),
            )?
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
    let mut sequencer = sequencer
        .with_keyless(keyless)
        .with_chain_id(config.transaction_chain_id())
        .with_network_salt(config.network_salt.as_bytes().to_vec())
        .with_fee_assets(
            config
                .gas_assets
                .iter()
                .map(|a| sena_primitives::AssetId(a.asset))
                .collect(),
        );
    if let Some(account) = fee_recipient {
        let account =
            L2Address::from_hex(account.trim()).map_err(|e| format!("bad --fee-recipient: {e}"))?;
        println!("tips go to {account}");
        sequencer = sequencer.with_fee_recipient(account);
    }

    // Warn rather than refuse: binding a public interface without a token is a
    // choice an operator can legitimately make behind their own proxy, but it
    // should never be made by accident.
    let listen = &server_config.listen;
    if server_config.auth_token.is_none()
        && !listen.starts_with("127.0.0.1")
        && !listen.starts_with("localhost")
    {
        eprintln!(
            "warning: listening on {listen} with no --auth-token; anyone who can reach this \
             address can submit transactions"
        );
    }

    let server_config = ServerConfig {
        chain_id: config.chain_id.clone(),
        ..server_config
    };
    for origin in &server_config.cors_origins {
        println!("browsers at {origin} may call this node");
    }

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

/// Runs `step` every `poll_interval` seconds until interrupted. A failed round
/// is reported and retried; L1 and the L2 node are expected to come and go.
fn rounds<R: std::fmt::Debug, E: std::fmt::Display>(
    poll_interval: u64,
    mut step: impl FnMut() -> Result<R, E>,
    quiet: impl Fn(&R) -> bool,
) -> Result<(), String> {
    loop {
        match step() {
            Ok(report) if quiet(&report) => {}
            Ok(report) => println!("{report:?}"),
            Err(e) => eprintln!("round failed: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(poll_interval));
    }
}

fn relay(
    rpc: String,
    rpc_token: Option<String>,
    aptos: &AptosArgs,
    bond: u128,
    state: String,
) -> Result<(), String> {
    let source = sena_node::RpcSource {
        url: rpc,
        auth_token: rpc_token,
    };
    let config = sena_node::RelayerConfig {
        bond,
        state_path: state.into(),
    };
    let mut relayer =
        sena_node::Relayer::new(aptos.client(), source, config).map_err(|e| e.to_string())?;
    println!("relaying to {} as {}", aptos.contract, aptos.account);
    rounds(
        aptos.poll_interval,
        || match relayer.step() {
            // A rejected assertion means this sequencer asserted something
            // false; carrying on would only post more on top of it.
            Err(sena_node::relayer::RelayError::Rejected(h)) => {
                eprintln!("assertion for block {h} was rejected on L1; halting");
                std::process::exit(2);
            }
            // Someone else holds our next assertion: building on it would
            // leave it undefended.
            Err(e @ sena_node::relayer::RelayError::NotOurs(..)) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
            other => other,
        },
        |r| *r == sena_node::relayer::StepReport::default(),
    )
}

fn watch(
    data_dir: &str,
    aptos: &AptosArgs,
    bond: u128,
    state: String,
    keyless_steps_per_tx: u64,
) -> Result<(), String> {
    let store = Store::open(data_dir).map_err(|e| e.to_string())?;
    let config = store
        .load_genesis()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no genesis.json in {data_dir}"))?;
    let keyless = config.keyless_config().map_err(|e| e.to_string())?;
    let genesis = config.build_state().map_err(|e| e.to_string())?;
    let watcher_config = sena_node::WatcherConfig {
        bond,
        state_path: state.into(),
        keyless_setup: sena_stf::KeylessConfig::l1_setup_id(keyless.as_deref()),
        keyless,
        keyless_steps_per_tx: keyless_steps_per_tx.max(1),
        chain_id: config.transaction_chain_id(),
    };
    let mut watcher = sena_node::Watcher::new(aptos.client(), watcher_config, genesis)
        .map_err(|e| e.to_string())?;
    println!(
        "watching {} from assertion {}",
        aptos.contract,
        watcher.state().cursor
    );
    rounds(
        aptos.poll_interval,
        || watcher.step(),
        |r| *r == sena_node::WatchReport::default(),
    )
}

fn council_key(key_file: &str) -> Result<SigningKey, String> {
    let file: serde_json::Value = serde_json::from_slice(
        &std::fs::read(key_file).map_err(|e| format!("reading {key_file}: {e}"))?,
    )
    .map_err(|e| format!("{key_file} is not JSON: {e}"))?;
    let secret: [u8; 32] = file["secret"]
        .as_str()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{key_file} needs a 32-byte hex \"secret\""))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn rename_asset(
    rpc: &str,
    key_file: &str,
    asset: u32,
    symbol: String,
    fee_asset: u32,
) -> Result<(), String> {
    let assets = call(rpc, &serde_json::json!({ "method": "sena_getFeeAssets" }))?;
    let current = assets["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["asset"] == asset))
        .ok_or_else(|| format!("asset {asset} is not a fee asset"))?;
    let rate: u128 = current["rate"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("unexpected asset record: {current}"))?;
    let record = sena_stf::WhitelistedAsset {
        asset: sena_primitives::AssetId(asset),
        symbol: symbol.clone(),
        rate,
        intrinsic_gas: current["intrinsic_gas"]
            .as_u64()
            .ok_or("no intrinsic gas")?,
        enabled: current["enabled"].as_bool().ok_or("no enabled flag")?,
    };
    sena_node::jwk_sync::govern(
        rpc,
        &council_key(key_file)?,
        fee_asset,
        sena_stf::GovernanceUpdate::SetGasAsset { record },
    )?;
    println!("asset {asset} is now {symbol}");
    Ok(())
}

fn jwk_sync(
    rpc: String,
    key_file: &str,
    iss: String,
    jwks_url: String,
    fee_asset: u32,
    state: String,
    interval: u64,
) -> Result<(), String> {
    let file: serde_json::Value = serde_json::from_slice(
        &std::fs::read(key_file).map_err(|e| format!("reading {key_file}: {e}"))?,
    )
    .map_err(|e| format!("{key_file} is not JSON: {e}"))?;
    let secret: [u8; 32] = file["secret"]
        .as_str()
        .and_then(|s| hex::decode(s.trim()).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{key_file} needs a 32-byte hex \"secret\""))?;
    let sync = sena_node::jwk_sync::JwkSyncConfig {
        rpc,
        iss,
        jwks_url,
        key: SigningKey::from_bytes(&secret),
        fee_asset,
        state: state.into(),
    };
    loop {
        match sync.round() {
            Ok(r) if r == sena_node::jwk_sync::SyncReport::default() => {
                println!("jwk-sync: up to date");
            }
            Ok(r) => println!(
                "jwk-sync: accepted {:?}, retired {:?}",
                r.accepted, r.retired
            ),
            // A failed round is retried next time; only a one-shot run fails.
            Err(e) if interval > 0 => eprintln!("jwk-sync: {e}"),
            Err(e) => return Err(e),
        }
        if interval == 0 {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
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

/// What `sena_gasPrice` quotes for an asset.
struct GasQuote {
    rate: u128,
    intrinsic_gas: u64,
    base_fee_per_gas: u128,
    max_fee_per_gas: u128,
}

fn gas_quote(rpc: &str, asset: u32) -> Result<GasQuote, String> {
    let response = call(
        rpc,
        &serde_json::json!({ "method": "sena_gasPrice", "params": { "asset": asset } }),
    )?;
    let num = |k: &str| -> Result<u128, String> {
        response[k]
            .as_str()
            .and_then(|v| v.parse().ok())
            .or_else(|| response[k].as_u64().map(u128::from))
            .ok_or_else(|| format!("no gas quote for asset {asset}: {response}"))
    };
    Ok(GasQuote {
        rate: num("rate")?,
        intrinsic_gas: u64::try_from(num("intrinsic_gas")?).map_err(|e| e.to_string())?,
        base_fee_per_gas: num("base_fee_per_gas")?,
        max_fee_per_gas: num("suggested_max_fee_per_gas")?,
    })
}

/// What `send` signs.
struct Transfer {
    to: String,
    amount: u128,
    nonce: u64,
    asset: u32,
    fee_asset: u32,
    tip: u128,
    /// `to` is an Aptos address and the payload a withdrawal to it.
    withdraw: bool,
}

/// An Aptos address's 32 bytes, from `0x`-hex of up to 64 digits.
fn aptos_address(text: &str) -> Result<[u8; 32], String> {
    let h = text.trim().trim_start_matches("0x");
    if h.is_empty() || h.len() > 64 {
        return Err(format!("not an Aptos address: {text}"));
    }
    let raw =
        hex::decode(format!("{h:0>64}")).map_err(|_| format!("not an Aptos address: {text}"))?;
    raw.try_into()
        .map_err(|_| format!("not an Aptos address: {text}"))
}

fn send(rpc: &str, secret: &str, t: &Transfer) -> Result<(), String> {
    let Transfer {
        ref to,
        amount,
        nonce,
        asset,
        fee_asset,
        tip,
        withdraw,
    } = *t;
    let raw = hex::decode(secret.trim()).map_err(|_| "secret is not hex".to_owned())?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "secret must be 32 bytes".to_owned())?;
    let key = SigningKey::from_bytes(&bytes);

    let payload = if withdraw {
        sena_stf::Payload::Withdraw {
            to: aptos_address(to)?,
            asset: sena_primitives::AssetId(asset),
            amount,
        }
    } else {
        sena_stf::Payload::Transfer {
            to: L2Address::from_hex(to.trim()).map_err(|e| format!("bad recipient: {e}"))?,
            asset: sena_primitives::AssetId(asset),
            amount,
        }
    };

    // The asset's rate and intrinsic gas, and the base fee, as the node quotes
    // them. All three are checked in the trace, so a wrong quote is refused
    // rather than honoured.
    let quote = gas_quote(rpc, fee_asset)?;
    // The chain the node serves: the transaction signs it, so it cannot be
    // replayed on another SENA network.
    let info = call(rpc, &serde_json::json!({ "method": "sena_getChainInfo" }))?;
    let chain_id = info["transaction_chain_id"]
        .as_u64()
        .ok_or_else(|| format!("the node did not report its chain id: {info}"))?;

    let mut tx = sena_stf::Transaction {
        chain_id,
        sender: L2Address::from_bytes(key.verifying_key().to_bytes()),
        nonce,
        fee_asset: sena_primitives::AssetId(fee_asset),
        fee_rate: quote.rate,
        fee_intrinsic_gas: quote.intrinsic_gas,
        gas_limit: 0,
        max_fee_per_gas: quote.max_fee_per_gas,
        max_priority_fee_per_gas: tip,
        payload,
        authenticator: sena_stf::Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    // Gas is known before execution: the limit is exactly what it uses.
    tx.gas_limit = sena_stf::gas_required(&tx).map_err(|e| e.to_string())?;
    println!(
        "gas {} at up to {} per gas ({} base) in asset {fee_asset}",
        tx.gas_limit, quote.max_fee_per_gas, quote.base_fee_per_gas
    );
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
        Query::Proof { address, height } => {
            let parsed =
                L2Address::from_hex(address.trim()).map_err(|e| format!("bad address: {e}"))?;
            let mut params = serde_json::json!({ "address": parsed });
            if let Some(h) = height {
                params["height"] = serde_json::json!(h);
            }
            serde_json::json!({ "method": "sena_getAccountProof", "params": params })
        }
        Query::Withdrawal {
            sender,
            nonce,
            state_root,
        } => {
            let parsed =
                L2Address::from_hex(sender.trim()).map_err(|e| format!("bad address: {e}"))?;
            let mut params = serde_json::json!({ "sender": parsed, "nonce": nonce });
            if let Some(root) = state_root {
                params["state_root"] = serde_json::json!(root.trim_start_matches("0x"));
            }
            serde_json::json!({ "method": "sena_getWithdrawalProof", "params": params })
        }
    };
    let response = call(rpc, &body)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );
    Ok(())
}
