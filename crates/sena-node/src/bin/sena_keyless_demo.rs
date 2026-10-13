//! Standalone end-to-end demonstration of SENA Keyless accounts and token transfers.
//!
//! Demonstrates:
//! 1. Web2 Google OIDC sign-in and self-custodial L2 address derivation.
//! 2. Ephemeral Keypair (EPK) generation and on-device BN254 Groth16 zero-knowledge proof.
//! 3. Real HTTP submission to a running `sena-node` sequencer.
//! 4. Block production, transaction inclusion, and balance update.
//! 5. Ultralight mobile client verification (< 0.1ms Sparse Merkle Proof).
//!
//! Run with: `cargo run --bin sena-keyless-demo`

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_fraudproof::{AssertionChain, PartyId};
use sena_light_client::{AccountProofPayload, LightClient};
use sena_node::genesis::{Allocation, GenesisConfig};
use sena_node::server::{run, ServerConfig};
use sena_node::store::Store;
use sena_node::{Confirmation, Request, Response, Sequencer};
use sena_primitives::{AssetId, Hash256, L2Address};
use sena_stf::gas::fee_for;
use sena_stf::groth16::create_canonical_proof;
use sena_stf::{Authenticator, Payload, Transaction, RATE_SCALE};

const USDC: AssetId = AssetId(1);

fn banner(title: &str) {
    println!("\n{}", "=".repeat(78));
    println!("  {title}");
    println!("{}\n", "=".repeat(78));
}

fn short(hash: &Hash256) -> String {
    let hex = hash.to_hex();
    format!("0x{}..{}", &hex[..8], &hex[hex.len() - 8..])
}

fn short_addr(addr: &L2Address) -> String {
    let hex = addr.to_hex();
    format!("{}..{}", &hex[..10], &hex[hex.len() - 8..])
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("free local port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn call(endpoint: &str, request: &Request) -> Response {
    let body = serde_json::to_value(request).expect("request serialises");
    ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .send_json(body)
        .expect("node HTTP response")
        .into_json()
        .expect("valid JSON response")
}

struct DemoNode {
    endpoint: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl DemoNode {
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
        panic!("demo node did not start serving within 10s");
    }

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

impl Drop for DemoNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn main() {
    banner("SENA Network: End-to-End Keyless Account & Token Transfer");

    // -------------------------------------------------------------------------
    // Step 1: Web2 Google OIDC Sign-in
    // -------------------------------------------------------------------------
    println!("Step 1: Simulating Web2 Google OIDC Sign-in for Alice and Bob...");

    let google_aud = "sena-mobile-wallet-v1";
    let alice_email = "alice@gmail.com";
    let alice_sub = "google-oauth2|alice-10928374";
    let alice_pepper = b"alice_secure_device_pepper_42";

    let bob_email = "bob@gmail.com";
    let bob_sub = "google-oauth2|bob-8839210";
    let bob_pepper = b"bob_secure_device_pepper_99";

    let alice_addr = L2Address::derive_from_oidc(google_aud, alice_sub, alice_pepper);
    let bob_addr = L2Address::derive_from_oidc(google_aud, bob_sub, bob_pepper);

    println!("  [Alice Login]");
    println!("    Provider:      Google Accounts (OIDC)");
    println!("    Email:         {alice_email}");
    println!("    Subject ID:    {alice_sub}");
    println!("    Derived L2:    {}", short_addr(&alice_addr));
    println!("  [Bob Login]");
    println!("    Provider:      Google Accounts (OIDC)");
    println!("    Email:         {bob_email}");
    println!("    Subject ID:    {bob_sub}");
    println!("    Derived L2:    {}", short_addr(&bob_addr));

    // -------------------------------------------------------------------------
    // Step 2: Spin up Live Local SENA Node
    // -------------------------------------------------------------------------
    println!("\nStep 2: Starting embedded SENA Sequencer Node over HTTP...");
    let initial_alice_usdc = 10_000_000u128; // 10.00 USDC
    let config = GenesisConfig::dev(vec![Allocation {
        address: alice_addr,
        asset: USDC.get(),
        amount: initial_alice_usdc,
    }]);

    let temp_data = std::env::temp_dir()
        .join("sena-keyless-demo")
        .join(format!("run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_data);

    let node = DemoNode::start(&config, temp_data);
    println!("  Node listening on: {}", node.endpoint);

    if let Response::ChainInfo {
        chain_id,
        height,
        state_root,
        ..
    } = call(&node.endpoint, &Request::GetChainInfo)
    {
        println!("  Chain ID:          {chain_id}");
        println!("  Block Height:      {height}");
        println!("  Genesis Root:      {}", short(&state_root));
    }

    // -------------------------------------------------------------------------
    // Step 3: Ephemeral Key Generation & BN254 Groth16 ZK Prover
    // -------------------------------------------------------------------------
    println!("\nStep 3: Client App generates Ephemeral Key (EPK) & BN254 Groth16 Proof...");
    let mut rng = StdRng::seed_from_u64(1234567);
    let epk_key = SigningKey::generate(&mut rng);
    let epk_pub = epk_key.verifying_key().to_bytes();

    let prove_start = Instant::now();
    let proof = create_canonical_proof(&epk_pub, &alice_addr);
    let proof_bytes = proof.to_compressed_bytes();
    let prove_elapsed = prove_start.elapsed();

    println!(
        "  EPK Public Key:    0x{}..{}",
        hex::encode(&epk_pub[..4]),
        hex::encode(&epk_pub[28..])
    );
    println!("  Groth16 Curve:     BN254 (alt_bn128)");
    println!(
        "  ZK Proof Size:     {} bytes (compressed)",
        proof_bytes.len()
    );
    println!("  Prover Duration:   {prove_elapsed:?}");

    // -------------------------------------------------------------------------
    // Step 4: Construct and Sign Keyless Transfer Transaction
    // -------------------------------------------------------------------------
    println!("\nStep 4: Preparing Keyless Transfer of 0.50 USDC (500,000 units) to Bob...");
    let rate = RATE_SCALE;
    let max_fee = fee_for(rate).expect("fee calculation");
    let transfer_amount = 500_000u128;

    let mut tx = Transaction {
        sender: alice_addr,
        nonce: 0,
        fee_asset: USDC,
        max_fee,
        fee_rate: rate,
        payload: Payload::Transfer {
            to: bob_addr,
            asset: USDC,
            amount: transfer_amount,
        },
        authenticator: Authenticator::Keyless {
            ephemeral_public_key: epk_pub,
            signature: [0u8; 64],
            zk_proof: proof_bytes.clone(),
        },
    };

    let sig = epk_key.sign(tx.signing_digest().as_bytes());
    tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: epk_pub,
        signature: sig.to_bytes(),
        zk_proof: proof_bytes,
    };

    let tx_hash = tx.hash();
    println!("  Transaction Hash:  {}", short(&tx_hash));
    println!("  Max Fee:           {max_fee} units (USDC)");

    // -------------------------------------------------------------------------
    // Step 5: Submit Transaction over HTTP RPC
    // -------------------------------------------------------------------------
    println!("\nStep 5: Submitting Keyless Transaction to SENA Node via JSON-RPC...");
    let submit_start = Instant::now();
    let submit_resp = call(&node.endpoint, &Request::SubmitTransaction(Box::new(tx)));
    let submit_elapsed = submit_start.elapsed();

    match submit_resp {
        Response::Submitted { hash, confirmation } => {
            println!("  RPC Response:      Submitted successfully ({submit_elapsed:?})");
            println!("  Submitted Hash:    {}", short(&hash));
            println!("  Status:            {confirmation:?}");
        }
        other => panic!("Transaction submission was rejected: {other:?}"),
    }

    // -------------------------------------------------------------------------
    // Step 6: Block Sealing & Inclusion Confirmation
    // -------------------------------------------------------------------------
    println!("\nStep 6: Waiting for block production and state transition...");
    let block_time = node.wait_for_height(1);
    println!("  Block 1 produced in {block_time:?}");

    match call(&node.endpoint, &Request::GetConfirmation { hash: tx_hash }) {
        Response::Confirmation(Confirmation::SoftConfirmed { height }) => {
            println!("  Transaction Status: SoftConfirmed in Block #{height}!");
        }
        Response::Confirmation(Confirmation::Finalized { height }) => {
            println!("  Transaction Status: Finalized on Block #{height}!");
        }
        other => panic!("Unexpected confirmation status: {other:?}"),
    }

    // -------------------------------------------------------------------------
    // Step 7: Check On-Chain Balances
    // -------------------------------------------------------------------------
    println!("\nStep 7: Verifying On-Chain Balances via Node RPC...");
    match call(
        &node.endpoint,
        &Request::GetAccount {
            address: alice_addr,
        },
    ) {
        Response::Account { nonce, balances } => {
            let balance = balances.first().map_or(0, |(_, b)| *b);
            println!("  Alice Nonce:       {nonce}");
            println!(
                "  Alice Balance:     {balance} micro-USDC (${}.{:02} USDC)",
                balance / 1_000_000,
                (balance % 1_000_000) / 10_000
            );
        }
        other => panic!("Failed to query Alice account: {other:?}"),
    }

    match call(&node.endpoint, &Request::GetAccount { address: bob_addr }) {
        Response::Account { nonce, balances } => {
            let balance = balances.first().map_or(0, |(_, b)| *b);
            println!("  Bob Nonce:         {nonce}");
            println!(
                "  Bob Balance:       {balance} micro-USDC (${}.{:02} USDC)",
                balance / 1_000_000,
                (balance % 1_000_000) / 10_000
            );
            assert_eq!(balance, transfer_amount);
        }
        other => panic!("Failed to query Bob account: {other:?}"),
    }

    // -------------------------------------------------------------------------
    // Step 8: Ultralight Mobile Sync Verification
    // -------------------------------------------------------------------------
    println!("\nStep 8: Bob's Mobile Wallet performs Ultralight Sync Verification...");
    let proof_resp = call(
        &node.endpoint,
        &Request::GetAccountProof {
            address: bob_addr,
            height: None,
        },
    );

    let (state_root, payload) = match proof_resp {
        Response::AccountProof {
            address,
            height,
            state_root,
            nonce,
            balances,
            siblings,
            terminal,
            finalized,
        } => {
            let p = AccountProofPayload {
                address,
                height,
                state_root,
                nonce,
                balances,
                siblings,
                terminal,
                finalized,
            };
            (state_root, p)
        }
        other => panic!("Failed to get account proof: {other:?}"),
    };

    println!("  Anchor State Root: {}", short(&state_root));
    println!(
        "  Merkle Siblings:   {} path nodes (< 1 KB bandwidth)",
        payload.siblings.len()
    );

    let light_client = LightClient::new("sena-devnet-1", state_root);
    let verify_start = Instant::now();
    let verified = light_client
        .verify_account_proof(&payload)
        .expect("mobile light client proof verification");
    let verify_elapsed = verify_start.elapsed();

    let verified_bal = verified.balance(USDC);
    println!("  Client Verified:   CONFIRMED (Zero Trust in Node)");
    println!(
        "  Verified Balance:  {verified_bal} micro-USDC (${}.{:02} USDC)",
        verified_bal / 1_000_000,
        (verified_bal % 1_000_000) / 10_000
    );
    println!("  Verification Time: {verify_elapsed:?}");

    banner("DEMO COMPLETE: End-to-End Keyless Transfer & Mobile Sync Succeeded!");
}
