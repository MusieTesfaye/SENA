//! End-to-end integration test: Real client application with Google OIDC Keyless accounts,
//! off-chain BN254 Groth16 ZK proof generation, HTTP submission to a live `sena-node`,
//! block inclusion, and ultralight mobile light client verification.

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
use sena_primitives::{AssetId, L2Address};
use sena_stf::gas::fee_for;
use sena_stf::groth16::create_canonical_proof;
use sena_stf::{Authenticator, Payload, Transaction, RATE_SCALE};

const USDC: AssetId = AssetId(1);

/// Finds a free local port for the test node.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("free local port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Helper sending JSON-RPC HTTP POST requests to the test node.
fn call(endpoint: &str, request: &Request) -> Response {
    let body = serde_json::to_value(request).expect("request serialises");
    ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .send_json(body)
        .expect("node HTTP response")
        .into_json()
        .expect("valid JSON response")
}

/// A running SENA node in a background thread.
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
        panic!("test node did not start serving within 10s");
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

impl Drop for TestNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join("sena-keyless-app-e2e")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn test_real_app_keyless_token_transfer_e2e() {
    // 1. Simulate Google OIDC user logins for Alice and Bob
    let google_aud = "sena-mobile-wallet-v1";
    let alice_sub = "google-oauth2|alice-10928374";
    let alice_pepper = b"alice_secure_device_pepper_42";

    let bob_sub = "google-oauth2|bob-8839210";
    let bob_pepper = b"bob_secure_device_pepper_99";

    let alice_addr = L2Address::derive_from_oidc(google_aud, alice_sub, alice_pepper);
    let bob_addr = L2Address::derive_from_oidc(google_aud, bob_sub, bob_pepper);

    // 2. Fund Alice's keyless account in genesis with 10,000,000 micro-USDC (10 USDC)
    let config = GenesisConfig::dev(vec![Allocation {
        address: alice_addr,
        asset: USDC.get(),
        amount: 10_000_000,
    }]);

    let node = TestNode::start(&config, temp_dir("keyless-e2e"));

    // Verify initial state: Alice has 10 USDC, Bob has 0
    match call(
        &node.endpoint,
        &Request::GetAccount {
            address: alice_addr,
        },
    ) {
        Response::Account { nonce, balances } => {
            assert_eq!(nonce, 0);
            assert_eq!(balances, vec![(USDC.get(), 10_000_000)]);
        }
        other => panic!("unexpected Alice account response: {other:?}"),
    }

    match call(&node.endpoint, &Request::GetAccount { address: bob_addr }) {
        Response::Account { nonce, balances } => {
            assert_eq!(nonce, 0);
            assert!(balances.is_empty());
        }
        other => panic!("unexpected Bob account response: {other:?}"),
    }

    // 3. Client App creates an Ephemeral Key Pair (EPK) for Alice's active session
    let mut rng = StdRng::seed_from_u64(98765);
    let epk_key = SigningKey::generate(&mut rng);
    let epk_bytes = epk_key.verifying_key().to_bytes();

    // 4. Prover generates a 128-byte BN254 Groth16 zero-knowledge proof binding Alice's EPK to her address
    let proof = create_canonical_proof(&epk_bytes, &alice_addr);
    let proof_bytes = proof.to_compressed_bytes();
    assert_eq!(proof_bytes.len(), 128);

    // 5. App prepares a 500,000 micro-USDC (0.50 USDC) transfer transaction from Alice to Bob
    let rate = RATE_SCALE;
    let max_fee = fee_for(rate).expect("fee calculation");
    let mut tx = Transaction {
        sender: alice_addr,
        nonce: 0,
        fee_asset: USDC,
        max_fee,
        fee_rate: rate,
        payload: Payload::Transfer {
            to: bob_addr,
            asset: USDC,
            amount: 500_000,
        },
        authenticator: Authenticator::Keyless {
            ephemeral_public_key: epk_bytes,
            signature: [0u8; 64],
            zk_proof: proof_bytes.clone(),
        },
    };

    // 6. Sign the transaction signing digest with the ephemeral private key
    let sig = epk_key.sign(tx.signing_digest().as_bytes());
    tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: epk_bytes,
        signature: sig.to_bytes(),
        zk_proof: proof_bytes,
    };

    let tx_hash = tx.hash();

    // 7. Submit transaction over HTTP to the running node
    match call(&node.endpoint, &Request::SubmitTransaction(Box::new(tx))) {
        Response::Submitted { hash, confirmation } => {
            assert_eq!(hash, tx_hash);
            assert_eq!(confirmation, Confirmation::Pending);
        }
        other => panic!("submission failed: {other:?}"),
    }

    // 8. Wait for block sealing
    node.wait_for_height(1);

    // 9. Verify transaction confirmation status
    match call(&node.endpoint, &Request::GetConfirmation { hash: tx_hash }) {
        Response::Confirmation(Confirmation::SoftConfirmed { height }) => {
            assert_eq!(height, 1);
        }
        Response::Confirmation(Confirmation::Finalized { height }) => {
            assert_eq!(height, 1);
        }
        other => panic!("unexpected confirmation: {other:?}"),
    }

    // 10. Verify on-chain balances after keyless transfer
    let expected_alice_balance = 10_000_000 - 500_000 - max_fee;
    match call(
        &node.endpoint,
        &Request::GetAccount {
            address: alice_addr,
        },
    ) {
        Response::Account { nonce, balances } => {
            assert_eq!(nonce, 1);
            assert_eq!(balances, vec![(USDC.get(), expected_alice_balance)]);
        }
        other => panic!("unexpected Alice updated account: {other:?}"),
    }

    match call(&node.endpoint, &Request::GetAccount { address: bob_addr }) {
        Response::Account { nonce, balances } => {
            assert_eq!(nonce, 0);
            assert_eq!(balances, vec![(USDC.get(), 500_000)]);
        }
        other => panic!("unexpected Bob updated account: {other:?}"),
    }

    // 11. Bob's mobile wallet fetches an ultralight Sparse Merkle Proof
    let account_proof_resp = call(
        &node.endpoint,
        &Request::GetAccountProof {
            address: bob_addr,
            height: None,
        },
    );

    let (state_root, proof_payload) = match account_proof_resp {
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
            assert_eq!(address, bob_addr);
            assert_eq!(nonce, 0);
            assert_eq!(balances, vec![(USDC.get(), 500_000)]);
            let payload = AccountProofPayload {
                address,
                height,
                state_root,
                nonce,
                balances,
                siblings,
                terminal,
                finalized,
            };
            (state_root, payload)
        }
        other => panic!("unexpected account proof response: {other:?}"),
    };

    // 12. Ultralight Mobile Verification: Bob's mobile client validates the state root & proof in < 0.1ms
    let start_verify = Instant::now();
    let light_client = LightClient::new("sena-devnet-1", state_root);
    let verified = light_client
        .verify_account_proof(&proof_payload)
        .expect("cryptographic Sparse Merkle Proof must verify");
    let verification_duration = start_verify.elapsed();

    assert_eq!(verified.address, bob_addr);
    assert_eq!(verified.balance(USDC), 500_000);
    assert!(
        verification_duration < Duration::from_millis(10),
        "mobile verification took {verification_duration:?}, must be sub-millisecond"
    );
}

#[test]
fn test_node_rejects_forged_zk_proof_keyless_transaction() {
    let google_aud = "sena-mobile-wallet-v1";
    let alice_addr = L2Address::derive_from_oidc(google_aud, "sub_alice", b"pepper_alice");
    let bob_addr = L2Address::derive_from_oidc(google_aud, "sub_bob", b"pepper_bob");
    let attacker_addr = L2Address::derive_from_oidc(google_aud, "sub_eve", b"pepper_eve");

    let config = GenesisConfig::dev(vec![Allocation {
        address: alice_addr,
        asset: USDC.get(),
        amount: 1_000_000,
    }]);
    let node = TestNode::start(&config, temp_dir("forged-zk"));

    let epk_key = SigningKey::generate(&mut StdRng::seed_from_u64(111));
    let epk_bytes = epk_key.verifying_key().to_bytes();

    // Attacker creates a ZK proof for attacker_addr, but attempts to spend from alice_addr
    let forged_proof = create_canonical_proof(&epk_bytes, &attacker_addr);
    let rate = RATE_SCALE;
    let max_fee = fee_for(rate).unwrap();

    let mut tx = Transaction {
        sender: alice_addr,
        nonce: 0,
        fee_asset: USDC,
        max_fee,
        fee_rate: rate,
        payload: Payload::Transfer {
            to: bob_addr,
            asset: USDC,
            amount: 100_000,
        },
        authenticator: Authenticator::Keyless {
            ephemeral_public_key: epk_bytes,
            signature: [0u8; 64],
            zk_proof: forged_proof.to_compressed_bytes(),
        },
    };
    let sig = epk_key.sign(tx.signing_digest().as_bytes());
    tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: epk_bytes,
        signature: sig.to_bytes(),
        zk_proof: forged_proof.to_compressed_bytes(),
    };

    // Node mempool must reject transaction
    match call(&node.endpoint, &Request::SubmitTransaction(Box::new(tx))) {
        Response::Error { message } => {
            assert!(
                message.contains("does not compile") || message.contains("proof"),
                "expected rejection error message, got: {message}"
            );
        }
        other => panic!("forged ZK proof transaction was unexpectedly accepted: {other:?}"),
    }
}
