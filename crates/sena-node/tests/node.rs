//! Node-level tests: admission, block production, verification, and the RPC
//! surface.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, Channel, HashedIdentifier, L2Address, NetworkSalt};
use sena_state::MerkleTrie;
use sena_stf::{
    apply, Authenticator, Instruction, Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};

use sena_fraudproof::{AssertionChain, PartyId, Status, DEFAULT_CHALLENGE_WINDOW};
use sena_node::{
    handle, Confirmation, Outcome, RejectReason, Request, Response, Sequencer, VerifierNode,
};

const USDC: AssetId = AssetId(1);
const RATE: u128 = RATE_SCALE;
const BOND: u128 = 1_000_000;

fn signer(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

fn address_of(key: &SigningKey) -> L2Address {
    L2Address::from_bytes(key.verifying_key().to_bytes())
}

fn signed(key: &SigningKey, nonce: u64, payload: Payload) -> Transaction {
    let mut tx = Transaction {
        sender: address_of(key),
        nonce,
        fee_asset: USDC,
        fee_rate: 0,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload,
        authenticator: Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    sena_stf::gas::fill_default_fees(&mut tx);
    let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature,
    };
    tx
}

fn genesis(accounts: &[(L2Address, u128)]) -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    apply(
        &mut trie,
        &Instruction::SetGasAsset {
            record: WhitelistedAsset {
                asset: USDC,
                symbol: "USDC".to_owned(),
                rate: RATE,
                intrinsic_gas: sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS,
                enabled: true,
            },
        },
    )
    .unwrap();
    for (address, amount) in accounts {
        apply(
            &mut trie,
            &Instruction::Credit {
                account: *address,
                asset: USDC,
                amount: *amount,
            },
        )
        .unwrap();
    }
    trie
}

fn node(state: MerkleTrie) -> Sequencer {
    let chain = AssertionChain::new(state.root(), DEFAULT_CHALLENGE_WINDOW, BOND);
    Sequencer::new(state, chain, PartyId(1), BOND)
}

// --- Admission ---------------------------------------------------------------

#[test]
fn a_valid_transaction_is_admitted() {
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 10,
        },
    );
    assert!(seq.submit(tx).is_ok());
    assert_eq!(seq.mempool.len(), 1);
}

#[test]
fn an_unfunded_transaction_is_refused_at_admission() {
    // Admission is consensus-relevant, not an optimisation: a batch containing
    // an unexecutable transaction is invalid in its entirety, so the sequencer
    // must never include one.
    let pauper = signer(1);
    let mut seq = node(genesis(&[]));
    let tx = signed(
        &pauper,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 10,
        },
    );
    assert!(matches!(
        seq.submit(tx),
        Err(RejectReason::WouldNotExecute { .. })
    ));
}

/// Whitelists `asset` for fees.
fn whitelist(trie: &mut MerkleTrie, asset: AssetId, rate: u128, intrinsic_gas: u64, on: bool) {
    let record = WhitelistedAsset {
        asset,
        symbol: format!("A{}", asset.get()),
        rate,
        intrinsic_gas,
        enabled: on,
    };
    apply(trie, &Instruction::SetGasAsset { record }).unwrap();
}

/// A transfer of `asset` paying its fee in `fee_asset`, declared at `rate`
/// and `intrinsic_gas`.
fn paying_in(
    key: &SigningKey,
    nonce: u64,
    asset: AssetId,
    fee_asset: AssetId,
    rate: u128,
    intrinsic_gas: u64,
) -> Transaction {
    let mut tx = signed(
        key,
        nonce,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset,
            amount: 10,
        },
    );
    tx.fee_asset = fee_asset;
    let max_fee =
        2 * sena_stf::gas::native_to_asset(sena_stf::gas::DEFAULT_BASE_FEE_FLOOR, rate).unwrap();
    sena_stf::gas::fill_fees(&mut tx, rate, intrinsic_gas, max_fee);
    let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature,
    };
    tx
}

#[test]
fn only_an_enabled_fee_asset_declared_as_whitelisted_is_admitted() {
    // The node's own admission, not just a wallet's quote, must refuse a fee
    // that the trace would reject: a disabled asset, an unlisted one, and a
    // listed one declared at the wrong rate or intrinsic gas.
    const USDT: AssetId = AssetId(2);
    const EURC: AssetId = AssetId(3);
    const DAI: AssetId = AssetId(4);
    const EURC_RATE: u128 = 925_000;
    let alice = signer(1);
    let mut trie = genesis(&[]);
    whitelist(&mut trie, USDT, RATE, 10_000, true);
    whitelist(&mut trie, EURC, EURC_RATE, 15_000, true);
    whitelist(&mut trie, DAI, RATE, 10_000, false);
    for asset in [USDC, USDT, EURC, DAI] {
        let credit = Instruction::Credit {
            account: address_of(&alice),
            asset,
            amount: 1_000_000,
        };
        apply(&mut trie, &credit).unwrap();
    }
    let mut seq = node(trie);

    let refused = [
        ("disabled", paying_in(&alice, 0, DAI, DAI, RATE, 10_000)),
        (
            "unlisted",
            paying_in(&alice, 0, USDC, AssetId(9), RATE, 10_000),
        ),
        ("wrong rate", paying_in(&alice, 0, USDT, EURC, RATE, 15_000)),
        (
            "wrong intrinsic gas",
            paying_in(&alice, 0, USDT, EURC, EURC_RATE, 10_000),
        ),
    ];
    for (why, tx) in refused {
        assert!(
            matches!(
                handle(
                    &mut seq,
                    "sena-test-1",
                    Request::SubmitTransaction(Box::new(tx))
                ),
                Response::Error { .. }
            ),
            "a {why} fee asset was admitted"
        );
    }
    assert!(seq.mempool.is_empty());

    // Correctly declared, every enabled stablecoin pays, including for a
    // transfer of another asset, and a disabled one can still be moved.
    seq.submit(paying_in(&alice, 0, USDT, EURC, EURC_RATE, 15_000))
        .unwrap();
    seq.submit(paying_in(&alice, 1, DAI, USDT, RATE, 10_000))
        .unwrap();
    seq.submit(paying_in(&alice, 2, USDC, USDC, RATE, 10_000))
        .unwrap();
    let (block, _) = seq.produce(100).unwrap().expect("a block");
    assert_eq!(block.transactions.len(), 3);
}

#[test]
fn admission_accounts_for_what_is_already_queued() {
    // The subtle case: each transaction is affordable alone, but not together.
    // Checking the candidate in isolation would let the batch become invalid.
    let alice = signer(1);
    let bob = address_of(&signer(2));
    // Enough for two fees but only one of the two transfers.
    let probe = signed(
        &alice,
        0,
        Payload::Transfer {
            to: bob,
            asset: USDC,
            amount: 1_000,
        },
    );
    let hold = sena_stf::fee_charge(&probe, &sena_stf::BatchContext::without_keyless(0))
        .unwrap()
        .hold;
    let funds = hold * 2 + 1_500;
    let mut seq = node(genesis(&[(address_of(&alice), funds)]));

    assert!(seq
        .submit(signed(
            &alice,
            0,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 1_000
            }
        ))
        .is_ok());
    assert!(
        seq.submit(signed(
            &alice,
            1,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 1_000
            }
        ))
        .is_err(),
        "the second transfer is unaffordable once the first is queued"
    );
}

#[test]
fn a_duplicate_transaction_is_refused() {
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 10,
        },
    );
    seq.submit(tx.clone()).unwrap();
    assert_eq!(seq.submit(tx), Err(RejectReason::Duplicate));
}

#[test]
fn a_repeated_nonce_is_refused_while_queued() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    seq.submit(signed(
        &alice,
        0,
        Payload::Transfer {
            to: bob,
            asset: USDC,
            amount: 1,
        },
    ))
    .unwrap();
    assert!(matches!(
        seq.submit(signed(
            &alice,
            0,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 2
            }
        )),
        Err(RejectReason::NonceQueued { nonce: 0 })
    ));
}

// --- Production --------------------------------------------------------------

#[test]
fn producing_a_block_advances_state_and_posts_an_assertion() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    let before = seq.state.root();

    seq.submit(signed(
        &alice,
        0,
        Payload::Transfer {
            to: bob,
            asset: USDC,
            amount: 500,
        },
    ))
    .unwrap();
    let (block, id) = seq
        .produce(100)
        .unwrap()
        .expect("a block should be produced");

    assert_eq!(block.height, 1);
    assert_eq!(block.pre_state_root, before);
    assert_eq!(seq.state.root(), block.post_state_root);
    assert_eq!(seq.chain.status(&id), Some(Status::Pending));
    assert!(seq.mempool.is_empty());
}

#[test]
fn an_empty_mempool_produces_nothing() {
    let mut seq = node(genesis(&[]));
    assert!(seq.produce(100).unwrap().is_none());
}

#[test]
fn a_block_is_not_final_until_its_window_elapses() {
    // REQ-CORE-005: soft confirmation and L1 finality are different things, and
    // the node reports them as different things.
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );
    let hash = tx.hash();
    seq.submit(tx).unwrap();
    let (_, id) = seq.produce(100).unwrap().unwrap();

    assert_eq!(
        seq.confirmation(&hash),
        Confirmation::SoftConfirmed { height: 1 }
    );
    assert_eq!(seq.finalized_height(), 0);

    seq.chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    seq.chain.finalize(&id).unwrap();

    assert_eq!(
        seq.confirmation(&hash),
        Confirmation::Finalized { height: 1 }
    );
    assert_eq!(seq.finalized_height(), 1);
}

#[test]
fn several_blocks_chain_together() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let mut seq = node(genesis(&[(address_of(&alice), 5_000_000)]));

    for nonce in 0..3 {
        seq.submit(signed(
            &alice,
            nonce,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 100,
            },
        ))
        .unwrap();
        seq.produce(1).unwrap().unwrap();
    }

    assert_eq!(seq.blocks.len(), 3);
    for window in seq.blocks.windows(2) {
        assert_eq!(
            window[0].post_state_root, window[1].pre_state_root,
            "each block must continue the last"
        );
    }
}

// --- Independent verification ------------------------------------------------

#[test]
fn a_verifier_reproduces_an_honest_sequencers_state() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let start = genesis(&[(address_of(&alice), 5_000_000)]);
    let mut seq = node(start.clone());
    let mut verifier = VerifierNode::new(start, PartyId(2), None);

    for nonce in 0..5 {
        seq.submit(signed(
            &alice,
            nonce,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 250,
            },
        ))
        .unwrap();
    }
    let (block, id) = seq.produce(100).unwrap().unwrap();
    let assertion = seq.chain.get(&id).unwrap().assertion.clone();

    assert_eq!(verifier.follow(&block, &assertion), Outcome::Accepted);
    assert_eq!(
        verifier.state.root(),
        seq.state.root(),
        "a verifier rebuilding from published data must reach the same state"
    );
}

#[test]
fn a_verifier_rejects_a_falsified_root_and_does_not_adopt_it() {
    let alice = signer(1);
    let start = genesis(&[(address_of(&alice), 5_000_000)]);
    let mut seq = node(start.clone());
    let mut verifier = VerifierNode::new(start.clone(), PartyId(2), None);

    seq.submit(signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    ))
    .unwrap();
    let (block, id) = seq.produce(100).unwrap().unwrap();

    let mut lying = seq.chain.get(&id).unwrap().assertion.clone();
    lying.post_state_root = sena_primitives::Hash256::digest(b"a root nobody computed");

    let outcome = verifier.follow(&block, &lying);
    assert!(outcome.warrants_challenge(), "got {outcome:?}");
    assert_eq!(
        verifier.state.root(),
        start.root(),
        "a verifier must not adopt the state it is disputing"
    );
}

#[test]
fn a_verifier_can_open_a_dispute_over_what_it_found() {
    let alice = signer(1);
    let start = genesis(&[(address_of(&alice), 5_000_000)]);
    let mut seq = node(start.clone());
    let mut verifier = VerifierNode::new(start, PartyId(2), None);

    for nonce in 0..4 {
        seq.submit(signed(
            &alice,
            nonce,
            Payload::Transfer {
                to: address_of(&signer(2)),
                asset: USDC,
                amount: 10,
            },
        ))
        .unwrap();
    }
    let (block, id) = seq.produce(100).unwrap().unwrap();

    let mut lying = seq.chain.get(&id).unwrap().assertion.clone();
    lying.post_state_root = sena_primitives::Hash256::digest(b"false");
    verifier.follow(&block, &lying);

    let dispute = verifier
        .open_dispute(id, &lying, DEFAULT_CHALLENGE_WINDOW, 0)
        .expect("a dispute should be available");
    assert_eq!(dispute.challenger, PartyId(2));
    assert_eq!(dispute.hi, lying.trace_length);
    assert_ne!(
        dispute.lo_commitment, dispute.hi_commitment,
        "the endpoints of a real dispute must differ"
    );
}

// --- RPC ---------------------------------------------------------------------

#[test]
fn rpc_reports_account_state() {
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 4_242)]));
    let response = handle(
        &mut seq,
        "sena-test-1",
        Request::GetAccount {
            address: address_of(&alice),
        },
    );
    match response {
        Response::Account { nonce, balances } => {
            assert_eq!(nonce, 0);
            assert_eq!(balances, vec![(USDC.get(), 4_242)]);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_reports_an_unknown_account_as_empty_rather_than_failing() {
    let mut seq = node(genesis(&[]));
    let response = handle(
        &mut seq,
        "sena-test-1",
        Request::GetAccount {
            address: L2Address::from_bytes([9; 32]),
        },
    );
    assert!(matches!(response, Response::Account { nonce: 0, .. }));
}

#[test]
fn rpc_resolves_a_social_identifier() {
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    let id = HashedIdentifier::new(Channel::Handle, "@alice", &NetworkSalt::new(*b"test-salt"));

    seq.submit(signed(
        &alice,
        0,
        Payload::BindIdentifier {
            channel: Channel::Handle,
            identifier: id,
        },
    ))
    .unwrap();
    seq.produce(100).unwrap().unwrap();

    match handle(
        &mut seq,
        "sena-test-1",
        Request::ResolveIdentifier { identifier: id },
    ) {
        Response::Resolved { address } => assert_eq!(address, Some(address_of(&alice))),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_resolves_an_unknown_identifier_to_nothing() {
    let mut seq = node(genesis(&[]));
    let id = HashedIdentifier::new(Channel::Handle, "@nobody", &NetworkSalt::new(*b"test-salt"));
    assert_eq!(
        handle(
            &mut seq,
            "sena-test-1",
            Request::ResolveIdentifier { identifier: id }
        ),
        Response::Resolved { address: None }
    );
}

#[test]
fn rpc_submission_reports_pending_rather_than_confirmed() {
    // A submitted transaction is not a confirmed one, and the response says so
    // rather than leaving the caller to infer it.
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );

    match handle(
        &mut seq,
        "sena-test-1",
        Request::SubmitTransaction(Box::new(tx)),
    ) {
        Response::Submitted { confirmation, .. } => {
            assert_eq!(confirmation, Confirmation::Pending);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_reports_an_assertions_remaining_window() {
    // REQ-FRAUD-027: the window is public, so anyone can see how long they have
    // to challenge -- and how long until a withdrawal is safe.
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    seq.submit(signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    ))
    .unwrap();
    let (_, id) = seq.produce(100).unwrap().unwrap();

    match handle(&mut seq, "sena-test-1", Request::GetAssertion { id }) {
        Response::AssertionStatus {
            status,
            window_remaining,
            withdrawable,
        } => {
            assert_eq!(status, Status::Pending);
            assert_eq!(window_remaining, DEFAULT_CHALLENGE_WINDOW);
            assert!(!withdrawable);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    seq.chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    seq.chain.finalize(&id).unwrap();

    match handle(&mut seq, "sena-test-1", Request::GetAssertion { id }) {
        Response::AssertionStatus {
            status,
            window_remaining,
            withdrawable,
        } => {
            assert_eq!(status, Status::Finalized);
            assert_eq!(window_remaining, 0);
            assert!(withdrawable);
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_reports_whether_the_current_root_is_withdrawable() {
    let alice = signer(1);
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    seq.submit(signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    ))
    .unwrap();
    let (_, id) = seq.produce(100).unwrap().unwrap();

    match handle(&mut seq, "sena-test-1", Request::GetStateRoot) {
        Response::StateRoot { withdrawable, .. } => {
            assert!(!withdrawable, "a pending root is not withdrawable against");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    seq.chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    seq.chain.finalize(&id).unwrap();

    match handle(&mut seq, "sena-test-1", Request::GetStateRoot) {
        Response::StateRoot { withdrawable, .. } => assert!(withdrawable),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_requests_round_trip_as_json() {
    // The surface is transport-agnostic, so the wire form is part of its
    // contract.
    let request = Request::GetAccount {
        address: L2Address::from_bytes([3; 32]),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("sena_getAccount"), "got {json}");
    assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), request);
}

#[test]
fn rpc_reports_an_unknown_assertion_as_an_error() {
    let mut seq = node(genesis(&[]));
    let response = handle(
        &mut seq,
        "sena-test-1",
        Request::GetAssertion {
            id: sena_fraudproof::AssertionId::GENESIS,
        },
    );
    assert!(matches!(response, Response::Error { .. }));
}

// --- Wire format -------------------------------------------------------------

#[test]
fn amounts_travel_as_strings_not_json_numbers() {
    // Found in beta testing: serde_json cannot encode u128 at all, and any
    // client whose JSON numbers are IEEE-754 doubles -- JavaScript included --
    // would silently round a balance above 2^53. An integrator would read a
    // wrong balance with no error raised anywhere.
    let alice = signer(1);
    let huge = u128::from(u64::MAX) * 1_000;
    let mut seq = node(genesis(&[(address_of(&alice), huge)]));

    let response = handle(
        &mut seq,
        "sena-test-1",
        Request::GetAccount {
            address: address_of(&alice),
        },
    );
    let json = serde_json::to_string(&response).expect("account must serialise");

    assert!(
        json.contains(&format!("\"{huge}\"")),
        "amount must be a string: {json}"
    );
    assert!(
        !json.contains(&format!(":{huge}")),
        "amount must not be a bare number: {json}"
    );

    // And it must survive the round trip exactly.
    let parsed: Response = serde_json::from_str(&json).expect("must round-trip");
    match parsed {
        Response::Account { balances, .. } => assert_eq!(balances, vec![(USDC.get(), huge)]),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn a_transaction_round_trips_through_json() {
    // The exact path a client takes: build, serialise, send, parse, execute.
    let alice = signer(1);
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: u128::MAX / 2,
        },
    );

    let request = Request::SubmitTransaction(Box::new(tx.clone()));
    let json = serde_json::to_string(&request).expect("request must serialise");
    let parsed: Request = serde_json::from_str(&json).expect("request must parse");

    match parsed {
        Request::SubmitTransaction(received) => {
            assert_eq!(*received, tx);
            assert_eq!(
                received.signing_digest(),
                tx.signing_digest(),
                "the signature must still verify after a JSON round trip"
            );
        }
        other => panic!("unexpected request: {other:?}"),
    }
}

#[test]
fn the_signing_digest_does_not_depend_on_json() {
    // What a user signs has to be reproducible by anything verifying the
    // signature, including a Move contract on Aptos L1. Hashing serde_json
    // output would make that a bet on two JSON encoders agreeing forever.
    let alice = signer(1);
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 7,
        },
    );

    let payload_bytes = tx.payload.encode();
    assert!(!payload_bytes.is_empty());
    // Binary, not text: a JSON encoding would start with '{'.
    assert_ne!(
        payload_bytes[0], b'{',
        "the payload encoding must be binary"
    );
}

#[test]
fn blocks_are_cut_to_fit_one_l1_transaction() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let mut sequencer = node(genesis(&[(address_of(&alice), 1_000_000_000)]));
    let transfer = |nonce| {
        signed(
            &alice,
            nonce,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 1,
            },
        )
    };
    let per_tx = transfer(0).encode().len();
    let count = sena_node::sequencer::MAX_BATCH_BYTES / per_tx + 10;
    for nonce in 0..count as u64 {
        sequencer.submit(transfer(nonce)).unwrap();
    }

    let (block, _) = sequencer.produce(usize::MAX).unwrap().unwrap();
    let size: usize = block.transactions.iter().map(|t| t.encode().len()).sum();
    assert!(size <= sena_node::sequencer::MAX_BATCH_BYTES);
    assert_eq!(
        block.transactions.len(),
        sena_node::sequencer::MAX_BATCH_BYTES / per_tx
    );
    // The rest stays queued, in order, for the next block.
    let (next, _) = sequencer.produce(usize::MAX).unwrap().unwrap();
    assert_eq!(next.transactions[0].nonce, block.transactions.len() as u64);
}

// --- Fees ----------------------------------------------------------------------

fn transfer(key: &SigningKey, nonce: u64, amount: u128) -> Transaction {
    signed(
        key,
        nonce,
        Payload::Transfer {
            to: address_of(&signer(77)),
            asset: USDC,
            amount,
        },
    )
}

fn balance(seq: &Sequencer, who: &L2Address) -> u128 {
    seq.state
        .get(&sena_stf::keys::account(who))
        .map_or(0, |b| sena_stf::Account::decode(b).unwrap().balance(USDC))
}

#[test]
fn tips_reach_the_sequencer_and_the_base_fee_the_vault() {
    let alice = signer(1);
    let operator = address_of(&signer(40));
    let mut seq = node(genesis(&[(address_of(&alice), 10_000_000)])).with_fee_recipient(operator);
    let mut tx = transfer(&alice, 0, 5);
    tx.max_priority_fee_per_gas = sena_stf::PRICE_SCALE / 100;
    let tx = {
        let s = alice.sign(tx.signing_digest().as_bytes()).to_bytes();
        tx.authenticator = Authenticator::Ed25519 {
            public_key: alice.verifying_key().to_bytes(),
            signature: s,
        };
        tx
    };
    let ctx = seq.batch_context(seq.next_timestamp());
    let charge = sena_stf::fee_charge(&tx, &ctx).unwrap();
    seq.submit(tx).unwrap();
    let (block, _) = seq.produce(16).unwrap().unwrap();
    assert_eq!(block.fee_recipient, operator);
    assert!(charge.tip > 0);
    assert_eq!(balance(&seq, &operator), charge.tip);
    assert_eq!(balance(&seq, &sena_stf::FEE_VAULT), charge.base);
    assert_eq!(
        balance(&seq, &address_of(&alice)),
        10_000_000 - 5 - charge.tip - charge.base
    );
}

#[test]
fn the_gas_price_rpc_quotes_the_next_batch() {
    let mut seq = node(genesis(&[]));
    let Response::GasPrice {
        rate,
        intrinsic_gas,
        base_fee_native,
        base_fee_per_gas,
        suggested_max_fee_per_gas,
        ..
    } = handle(&mut seq, "test", Request::GasPrice { asset: USDC })
    else {
        panic!("expected a gas price");
    };
    assert_eq!(rate, RATE);
    assert_eq!(intrinsic_gas, sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS);
    assert_eq!(base_fee_native, sena_stf::gas::DEFAULT_BASE_FEE_FLOOR);
    assert_eq!(base_fee_per_gas, base_fee_native); // one-to-one rate
    assert_eq!(suggested_max_fee_per_gas, 2 * base_fee_per_gas);
    assert!(matches!(
        handle(&mut seq, "test", Request::GasPrice { asset: AssetId(9) }),
        Response::Error { .. }
    ));
}

#[test]
fn a_batch_is_cut_to_the_fee_window() {
    let alice = signer(1);
    let mut state = genesis(&[(address_of(&alice), 10_000_000)]);
    let per_tx = sena_stf::gas_required(&transfer(&alice, 0, 1)).unwrap();
    // A window that fits five transfers: target 2.5, elastic limit 5.
    apply(
        &mut state,
        &Instruction::SetFeeMarket {
            floor: sena_stf::gas::DEFAULT_BASE_FEE_FLOOR,
            target: per_tx * 5 / 2,
        },
    )
    .unwrap();
    let mut seq = node(state).with_clock(|| 100);
    for nonce in 0..8 {
        seq.submit(transfer(&alice, nonce, 1)).unwrap();
    }
    let (first, _) = seq.produce(64).unwrap().unwrap();
    assert_eq!(first.transactions.len(), 5, "only a full window's worth");
    // The same second's window is full: nothing more until the next second.
    assert!(seq.produce(64).unwrap().is_none());
    assert_eq!(seq.mempool.len(), 3);
}

#[test]
fn a_fee_asset_cannot_take_more_than_its_share_of_a_window() {
    let alice = signer(1);
    let mut state = genesis(&[(address_of(&alice), 10_000_000)]);
    let per_tx = sena_stf::gas_required(&transfer(&alice, 0, 1)).unwrap();
    apply(
        &mut state,
        &Instruction::SetFeeMarket {
            floor: sena_stf::gas::DEFAULT_BASE_FEE_FLOOR,
            target: per_tx * 5,
        },
    )
    .unwrap();
    // USDC may use 30% of the 10-transfer window: three transfers.
    let limits = std::iter::once((USDC, 300)).collect();
    let mut seq = node(state).with_clock(|| 100).with_fee_asset_limits(limits);
    for nonce in 0..6 {
        seq.submit(transfer(&alice, nonce, 1)).unwrap();
    }
    let (block, _) = seq.produce(64).unwrap().unwrap();
    assert_eq!(block.transactions.len(), 3);
}

#[test]
fn rpc_lists_fee_assets_as_state_holds_them() {
    let mut trie = genesis(&[]);
    whitelist(&mut trie, AssetId(3), 925_000, 15_000, false);
    let mut seq = node(trie).with_fee_assets(vec![USDC, AssetId(3), AssetId(9)]);
    match handle(&mut seq, "sena-test-1", Request::GetFeeAssets) {
        Response::FeeAssets { assets } => {
            // Asset 9 has no record, so it is not listed.
            let listed: Vec<_> = assets
                .iter()
                .map(|a| (a.asset, a.rate, a.intrinsic_gas, a.enabled))
                .collect();
            assert_eq!(
                listed,
                vec![
                    (USDC, RATE, sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS, true),
                    (AssetId(3), 925_000, 15_000, false),
                ]
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_reports_an_accounts_sent_and_received_transactions() {
    let alice = signer(1);
    let bob = signer(2);
    let carol = address_of(&signer(3));
    let mut seq = node(genesis(&[
        (address_of(&alice), 1_000_000),
        (address_of(&bob), 1_000_000),
    ]));
    let to = |who: L2Address, amount| Payload::Transfer {
        to: who,
        asset: USDC,
        amount,
    };
    seq.submit(signed(&alice, 0, to(address_of(&bob), 5)))
        .unwrap();
    seq.submit(signed(&bob, 0, to(carol, 7))).unwrap();
    seq.produce(100).unwrap().expect("a block");
    let queued = signed(&alice, 1, to(carol, 9));
    seq.submit(queued.clone()).unwrap();

    let history = |seq: &mut Sequencer, who: L2Address| match handle(
        seq,
        "sena-test-1",
        Request::GetAccountTransactions {
            address: who,
            limit: None,
        },
    ) {
        Response::AccountTransactions { transactions } => transactions,
        other => panic!("unexpected response: {other:?}"),
    };

    // Bob received from Alice and sent to Carol, both in block 1.
    let bobs = history(&mut seq, address_of(&bob));
    assert_eq!(bobs.len(), 2);
    assert!(bobs
        .iter()
        .all(|t| t.confirmation == Confirmation::SoftConfirmed { height: 1 }));
    // His own transfer paid a fee; the one he received was paid by Alice.
    assert!(bobs.iter().all(|t| t.fee_paid == Some(1_025)));

    // Alice's queued transfer comes first, still pending.
    let alices = history(&mut seq, address_of(&alice));
    assert_eq!(alices.len(), 2);
    assert_eq!(alices[0].hash, queued.hash());
    assert_eq!(alices[0].confirmation, Confirmation::Pending);
    assert_eq!(alices[0].fee_paid, None);

    // Amounts and fees travel as strings.
    let json = serde_json::to_value(&alices[1]).unwrap();
    assert_eq!(json["fee_paid"], "1025");
}
