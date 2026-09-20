//! Node-level tests: admission, block production, verification, and the RPC
//! surface.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, Channel, HashedIdentifier, L2Address, NetworkSalt};
use sena_state::MerkleTrie;
use sena_stf::gas::fee_for;
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
        max_fee: fee_for(RATE).unwrap(),
        fee_rate: RATE,
        payload,
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

fn genesis(accounts: &[(L2Address, u128)]) -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    apply(
        &mut trie,
        &Instruction::SetGasAsset {
            record: WhitelistedAsset {
                asset: USDC,
                symbol: "USDC".to_owned(),
                rate: RATE,
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
    assert!(seq.mempool.submit(&seq.state, tx).is_ok());
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
        seq.mempool.submit(&seq.state, tx),
        Err(RejectReason::WouldNotExecute { .. })
    ));
}

#[test]
fn admission_accounts_for_what_is_already_queued() {
    // The subtle case: each transaction is affordable alone, but not together.
    // Checking the candidate in isolation would let the batch become invalid.
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let funds = fee_for(RATE).unwrap() * 2 + 1_500;
    let mut seq = node(genesis(&[(address_of(&alice), funds)]));

    assert!(seq
        .mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: bob,
                    asset: USDC,
                    amount: 1_000
                }
            )
        )
        .is_ok());
    assert!(
        seq.mempool
            .submit(
                &seq.state,
                signed(
                    &alice,
                    1,
                    Payload::Transfer {
                        to: bob,
                        asset: USDC,
                        amount: 1_000
                    }
                )
            )
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
    seq.mempool.submit(&seq.state, tx.clone()).unwrap();
    assert_eq!(
        seq.mempool.submit(&seq.state, tx),
        Err(RejectReason::Duplicate)
    );
}

#[test]
fn a_repeated_nonce_is_refused_while_queued() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let mut seq = node(genesis(&[(address_of(&alice), 1_000_000)]));
    seq.mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: bob,
                    asset: USDC,
                    amount: 1,
                },
            ),
        )
        .unwrap();
    assert!(matches!(
        seq.mempool.submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: bob,
                    asset: USDC,
                    amount: 2
                }
            )
        ),
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

    seq.mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: bob,
                    asset: USDC,
                    amount: 500,
                },
            ),
        )
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
    seq.mempool.submit(&seq.state, tx).unwrap();
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
        seq.mempool
            .submit(
                &seq.state,
                signed(
                    &alice,
                    nonce,
                    Payload::Transfer {
                        to: bob,
                        asset: USDC,
                        amount: 100,
                    },
                ),
            )
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
    let mut verifier = VerifierNode::new(start, PartyId(2));

    for nonce in 0..5 {
        seq.mempool
            .submit(
                &seq.state,
                signed(
                    &alice,
                    nonce,
                    Payload::Transfer {
                        to: bob,
                        asset: USDC,
                        amount: 250,
                    },
                ),
            )
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
    let mut verifier = VerifierNode::new(start.clone(), PartyId(2));

    seq.mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: address_of(&signer(2)),
                    asset: USDC,
                    amount: 1,
                },
            ),
        )
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
    let mut verifier = VerifierNode::new(start, PartyId(2));

    for nonce in 0..4 {
        seq.mempool
            .submit(
                &seq.state,
                signed(
                    &alice,
                    nonce,
                    Payload::Transfer {
                        to: address_of(&signer(2)),
                        asset: USDC,
                        amount: 10,
                    },
                ),
            )
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

    seq.mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::BindIdentifier {
                    channel: Channel::Handle,
                    identifier: id,
                },
            ),
        )
        .unwrap();
    seq.produce(100).unwrap().unwrap();

    match handle(&mut seq, Request::ResolveIdentifier { identifier: id }) {
        Response::Resolved { address } => assert_eq!(address, Some(address_of(&alice))),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn rpc_resolves_an_unknown_identifier_to_nothing() {
    let mut seq = node(genesis(&[]));
    let id = HashedIdentifier::new(Channel::Handle, "@nobody", &NetworkSalt::new(*b"test-salt"));
    assert_eq!(
        handle(&mut seq, Request::ResolveIdentifier { identifier: id }),
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

    match handle(&mut seq, Request::SubmitTransaction(Box::new(tx))) {
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
    seq.mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: address_of(&signer(2)),
                    asset: USDC,
                    amount: 1,
                },
            ),
        )
        .unwrap();
    let (_, id) = seq.produce(100).unwrap().unwrap();

    match handle(&mut seq, Request::GetAssertion { id }) {
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

    match handle(&mut seq, Request::GetAssertion { id }) {
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
    seq.mempool
        .submit(
            &seq.state,
            signed(
                &alice,
                0,
                Payload::Transfer {
                    to: address_of(&signer(2)),
                    asset: USDC,
                    amount: 1,
                },
            ),
        )
        .unwrap();
    let (_, id) = seq.produce(100).unwrap().unwrap();

    match handle(&mut seq, Request::GetStateRoot) {
        Response::StateRoot { withdrawable, .. } => {
            assert!(!withdrawable, "a pending root is not withdrawable against");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    seq.chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    seq.chain.finalize(&id).unwrap();

    match handle(&mut seq, Request::GetStateRoot) {
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
        Request::GetAssertion {
            id: sena_fraudproof::AssertionId::GENESIS,
        },
    );
    assert!(matches!(response, Response::Error { .. }));
}
