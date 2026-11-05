//! L1 deposits credited on the L2: read, credited once each in order, refused
//! from users, and caught when forged.

use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_fraudproof::{AssertionChain, PartyId, DEFAULT_CHALLENGE_WINDOW};
use sena_node::{Outcome, RejectReason, Sequencer, VerifierNode};
use sena_primitives::{AssetId, L2Address};
use sena_state::MerkleTrie;
use sena_stf::{
    apply, DepositRecord, Instruction, Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};

const USDC: AssetId = AssetId(1);
const BOND: u128 = 1_000_000;

fn genesis() -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    apply(
        &mut trie,
        &Instruction::SetGasAsset {
            record: WhitelistedAsset {
                asset: USDC,
                symbol: "USDC".to_owned(),
                rate: RATE_SCALE,
                intrinsic_gas: sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS,
                enabled: true,
            },
        },
    )
    .unwrap();
    trie
}

fn node(state: MerkleTrie) -> Sequencer {
    let chain = AssertionChain::new(state.root(), DEFAULT_CHALLENGE_WINDOW, BOND);
    Sequencer::new(state, chain, PartyId(1), BOND)
}

fn someone(seed: u64) -> L2Address {
    let key = ed25519_dalek::SigningKey::generate(&mut StdRng::seed_from_u64(seed));
    L2Address::from_bytes(key.verifying_key().to_bytes())
}

fn deposit(to: L2Address, amount: u128) -> DepositRecord {
    DepositRecord {
        recipient: to,
        asset: USDC,
        amount,
    }
}

fn balance(seq: &Sequencer, who: &L2Address) -> u128 {
    seq.state
        .get(&sena_stf::keys::account(who))
        .map_or(0, |b| sena_stf::Account::decode(b).unwrap().balance(USDC))
}

#[test]
fn recorded_deposits_are_credited_in_the_next_block() {
    let (alice, bob) = (someone(1), someone(2));
    let mut seq = node(genesis());
    seq.record_deposit(1, deposit(alice, 5_000)).unwrap();
    seq.record_deposit(2, deposit(bob, 7)).unwrap();

    let (block, _) = seq
        .produce(100)
        .unwrap()
        .expect("deposits alone make a block");
    assert_eq!(block.transactions.len(), 2);
    assert_eq!(balance(&seq, &alice), 5_000);
    assert_eq!(balance(&seq, &bob), 7);
    assert_eq!(seq.deposits_credited(), 2);
    assert_eq!(seq.next_deposit_to_read(), 3);

    // Nothing new: nothing credited again.
    assert!(seq.produce(100).unwrap().is_none());
    assert_eq!(balance(&seq, &alice), 5_000);
}

#[test]
fn deposits_wait_for_a_gap_to_fill() {
    let alice = someone(1);
    let mut seq = node(genesis());
    seq.record_deposit(2, deposit(alice, 20)).unwrap();
    assert!(
        seq.produce(100).unwrap().is_none(),
        "deposit 2 cannot go before 1"
    );
    seq.record_deposit(1, deposit(alice, 10)).unwrap();
    seq.produce(100).unwrap().unwrap();
    assert_eq!(balance(&seq, &alice), 30);
    assert_eq!(seq.deposits_credited(), 2);
}

#[test]
fn a_contradictory_reading_of_l1_is_refused() {
    let mut seq = node(genesis());
    seq.record_deposit(1, deposit(someone(1), 10)).unwrap();
    seq.record_deposit(1, deposit(someone(1), 10)).unwrap(); // the same, again
    assert!(seq.record_deposit(1, deposit(someone(1), 11)).is_err());
    assert!(seq.record_deposit(0, deposit(someone(1), 1)).is_err());
}

#[test]
fn users_cannot_submit_deposits() {
    let mut seq = node(genesis());
    seq.record_deposit(1, deposit(someone(1), 10)).unwrap();
    let forged = Transaction::deposit(sena_stf::TEST_CHAIN_ID, 1, someone(1), USDC, 10);
    assert!(matches!(
        seq.submit(forged),
        Err(RejectReason::WouldNotExecute { .. })
    ));
}

#[test]
fn a_verifier_accepts_deposits_it_read_from_l1_and_nothing_else() {
    let alice = someone(1);
    let start = genesis();
    let mut seq = node(start.clone());
    seq.record_deposit(1, deposit(alice, 900)).unwrap();
    let (block, id) = seq.produce(100).unwrap().unwrap();
    let assertion = seq.chain.get(&id).unwrap().assertion.clone();

    // A verifier that has not read deposit 1 cannot execute the block...
    let mut blind = VerifierNode::new(start.clone(), PartyId(2), None);
    assert!(matches!(
        blind.follow(&block, &assertion),
        Outcome::Unexecutable { .. }
    ));

    // ...one that read it agrees...
    let mut honest = VerifierNode::new(start.clone(), PartyId(2), None);
    honest.record_deposit(1, deposit(alice, 900));
    assert_eq!(honest.follow(&block, &assertion), Outcome::Accepted);

    // ...and one that read what L1 actually holds catches an inflated credit.
    let mut forged_block = block.clone();
    forged_block.transactions[0] =
        Transaction::deposit(sena_stf::TEST_CHAIN_ID, 1, alice, USDC, 900_000);
    let mut watcher = VerifierNode::new(start, PartyId(3), None);
    watcher.record_deposit(1, deposit(alice, 900));
    let outcome = watcher.follow(&forged_block, &assertion);
    assert!(outcome.warrants_challenge(), "got {outcome:?}");
}

#[test]
fn deposit_payloads_never_compile_inside_user_transactions() {
    let log: std::collections::BTreeMap<u64, DepositRecord> = [(1, deposit(someone(1), 10))].into();
    let ctx = sena_stf::BatchContext {
        deposits: Some(&log),
        ..sena_stf::BatchContext::without_keyless(1)
    };
    let mut tx = Transaction::deposit(sena_stf::TEST_CHAIN_ID, 1, someone(1), USDC, 10);
    assert!(sena_stf::compile(&tx, &ctx).is_ok());
    tx.sender = someone(9);
    assert!(sena_stf::compile(&tx, &ctx).is_err());
    let quote = sena_stf::gas_required(&Transaction {
        payload: Payload::Deposit {
            id: 1,
            recipient: someone(1),
            asset: USDC,
            amount: 10,
        },
        ..Transaction::deposit(sena_stf::TEST_CHAIN_ID, 1, someone(1), USDC, 10)
    });
    assert!(
        quote.is_err(),
        "a deposit is not something a wallet can quote"
    );
}

#[test]
fn a_restarted_sequencer_replays_its_deposit_blocks() {
    let alice = someone(1);
    let start = genesis();
    let mut seq = node(start.clone());
    seq.record_deposit(1, deposit(alice, 42)).unwrap();
    let (block, _) = seq.produce(100).unwrap().unwrap();
    let stored = sena_node::store::StoredBatch {
        timestamp: block.timestamp,
        base_fee: block.base_fee,
        fee_recipient: block.fee_recipient,
        transactions: block.transactions.clone(),
        post_state_root: block.post_state_root,
    };
    let resumed = Sequencer::resume(
        start,
        seq.chain.clone(),
        PartyId(1),
        BOND,
        None,
        sena_stf::TEST_CHAIN_ID,
        &[stored],
        seq.state.root(),
    )
    .expect("resumes");
    assert_eq!(resumed.deposits_credited(), 1);
    assert_eq!(resumed.next_deposit_to_read(), 2);
}

// --- Withdrawals ----------------------------------------------------------------

fn signed_withdraw(key: &ed25519_dalek::SigningKey, nonce: u64, amount: u128) -> Transaction {
    use ed25519_dalek::Signer;
    let mut tx = Transaction {
        chain_id: sena_stf::TEST_CHAIN_ID,
        sender: L2Address::from_bytes(key.verifying_key().to_bytes()),
        nonce,
        fee_asset: USDC,
        fee_rate: 0,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload: Payload::Withdraw {
            to: [0xA7; 32],
            asset: USDC,
            amount,
        },
        authenticator: sena_stf::Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    sena_stf::gas::fill_default_fees(&mut tx);
    tx.authenticator = sena_stf::Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature: key.sign(tx.signing_digest().as_bytes()).to_bytes(),
    };
    tx
}

#[test]
fn a_withdrawal_burns_on_l2_and_leaves_a_provable_record() {
    let key = ed25519_dalek::SigningKey::generate(&mut StdRng::seed_from_u64(7));
    let alice = L2Address::from_bytes(key.verifying_key().to_bytes());
    let mut seq = node(genesis());
    seq.record_deposit(1, deposit(alice, 1_000_000)).unwrap();
    seq.produce(100).unwrap().unwrap();

    seq.submit(signed_withdraw(&key, 0, 400_000)).unwrap();
    let (block, _) = seq.produce(100).unwrap().unwrap();
    let left = balance(&seq, &alice);
    assert!(left < 600_000, "400,000 burned plus the fee: {left}");

    let response = sena_node::handle(
        &mut seq,
        "sena-test-1",
        sena_node::Request::GetWithdrawalProof {
            sender: alice,
            nonce: 0,
            state_root: Some(block.post_state_root),
        },
    );
    let sena_node::Response::WithdrawalProof {
        state_root,
        record,
        to,
        amount,
        siblings,
        terminal_key,
        ..
    } = response
    else {
        panic!("no proof: {response:?}")
    };
    assert_eq!(state_root, block.post_state_root);
    assert_eq!(amount, 400_000);
    assert_eq!(to, format!("0x{}", "a7".repeat(32)));
    // The proof is what `bridge::claim` checks: the record under the root.
    let record = hex::decode(record).unwrap();
    let slot = sena_stf::keys::withdrawal(&alice, 0);
    assert_eq!(terminal_key, slot.to_hex());
    let proof = sena_state::MerkleProof {
        siblings: siblings
            .iter()
            .map(|s| sena_primitives::Hash256::from_hex(s).unwrap())
            .collect(),
        terminal: sena_state::Terminal::Leaf {
            key: slot,
            value_hash: sena_state::hash_value(&record),
        },
    };
    proof.verify_inclusion(&state_root, &slot, &record).unwrap();

    // A nonce that withdrew nothing has no record.
    assert!(matches!(
        sena_node::handle(
            &mut seq,
            "sena-test-1",
            sena_node::Request::GetWithdrawalProof {
                sender: alice,
                nonce: 1,
                state_root: None,
            },
        ),
        sena_node::Response::Error { .. }
    ));
}

#[test]
fn a_withdrawal_cannot_exceed_the_balance() {
    let key = ed25519_dalek::SigningKey::generate(&mut StdRng::seed_from_u64(8));
    let alice = L2Address::from_bytes(key.verifying_key().to_bytes());
    let mut seq = node(genesis());
    seq.record_deposit(1, deposit(alice, 1_000)).unwrap();
    seq.produce(100).unwrap().unwrap();
    assert!(seq.submit(signed_withdraw(&key, 0, 1_000_000)).is_err());
    assert!(
        seq.submit(signed_withdraw(&key, 0, 0)).is_err(),
        "nothing to withdraw"
    );
}
