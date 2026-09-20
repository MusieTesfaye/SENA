//! Adversarial dispute tests.
//!
//! These exercise the claim the whole protocol rests on: **an honest party wins**.
//! A sequencer that asserts a state no honest execution produces loses to any
//! verifier that re-executed the batch, and a challenger who disputes an honest
//! assertion loses their bond.
//!
//! The fraud modelled here is the realistic one. The instruction list is derived
//! from published batch data, so a fraudster cannot change which instructions
//! ran — they can only lie about the *state* those instructions produced. The
//! harness builds exactly that: an honest prefix, one step whose result is
//! misreported, and the remaining real instructions applied on top of the
//! falsified state.

use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, Hash256, L2Address};
use sena_state::MerkleTrie;
use sena_stf::gas::fee_for;
use sena_stf::{
    apply, compile, execute_batch, Authenticator, ExecutionTrace, Instruction, MachineState,
    Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};

use sena_fraudproof::{
    adjudicate, check_assertion, clock_budget, Assertion, AssertionChain, AssertionId, ChainError,
    Dispute, Finding, Opening, Party, PartyId, Resolution, Stage, Status, TracePlayer,
    VerdictReason, CHALLENGE_WINDOW_FLOOR, DEFAULT_CHALLENGE_WINDOW, MOVE_TIMEOUT,
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

/// A batch large enough that bisection takes several rounds.
fn sample_batch() -> (MerkleTrie, Vec<Transaction>) {
    let alice = signer(1);
    let bob = signer(2);
    let trie = genesis(&[
        (address_of(&alice), 5_000_000),
        (address_of(&bob), 5_000_000),
    ]);

    let mut batch = Vec::new();
    for i in 0..12 {
        batch.push(signed(
            &alice,
            i,
            Payload::Transfer {
                to: address_of(&bob),
                asset: USDC,
                amount: 1_000 + u128::from(i),
            },
        ));
    }
    for i in 0..8 {
        batch.push(signed(
            &bob,
            i,
            Payload::Transfer {
                to: address_of(&alice),
                asset: USDC,
                amount: 500,
            },
        ));
    }
    (trie, batch)
}

/// The instruction list Aptos L1 derives from the published batch data.
fn program(batch: &[Transaction]) -> Vec<Instruction> {
    batch
        .iter()
        .flat_map(|tx| compile(tx).expect("batch must compile"))
        .collect()
}

/// Builds a trace that misreports the result of exactly one step.
///
/// The published instruction list is untouched — only the states differ from
/// `at_step` onward, which is precisely what a lying sequencer can do.
fn fraudulent_trace(
    pre: &MerkleTrie,
    instructions: &[Instruction],
    at_step: usize,
    substitute: &Instruction,
) -> ExecutionTrace {
    let mut trie = pre.clone();
    let mut states = vec![MachineState::start(trie.root())];

    for (index, instruction) in instructions.iter().enumerate() {
        let executed = if index == at_step {
            substitute
        } else {
            instruction
        };
        let root = apply(&mut trie, executed).expect("fraudulent substitution must apply");
        states.push(MachineState {
            state_root: root,
            pc: (index + 1) as u64,
        });
    }

    ExecutionTrace {
        instructions: instructions.to_vec(),
        states,
    }
}

/// Runs a dispute to completion, returning the winner and the disputed step.
fn play_out(
    defender: &TracePlayer,
    challenger: &TracePlayer,
    instructions: &[Instruction],
    dispute: &mut Dispute,
) -> (Party, Option<u64>) {
    let mut now = 0u64;
    // Bounded: each round shrinks the interval, so this cannot spin.
    for _ in 0..256 {
        if let Some(winner) = dispute.winner() {
            return (winner, dispute.disputed_step());
        }
        match dispute.stage {
            Stage::Bisecting { .. } => {
                now += 60;
                let role = dispute.turn;
                let player = match role {
                    Party::Defender => defender,
                    Party::Challenger => challenger,
                };
                player
                    .play(dispute, role, now)
                    .expect("honest play should be accepted");
            }
            Stage::OneStep => {
                let step = dispute.disputed_step();
                let proof = challenger
                    .one_step_proof(dispute)
                    .expect("challenger must be able to prove the disputed step");
                let verdict = adjudicate(instructions, dispute, &proof);
                dispute.resolve_by_one_step(verdict.winner);
                return (verdict.winner, step);
            }
            Stage::Resolved { winner, .. } => return (winner, dispute.disputed_step()),
        }
    }
    panic!("dispute did not converge");
}

fn open_dispute(defender: &TracePlayer, challenger: &TracePlayer, length: u64) -> Dispute {
    Dispute::open(
        &Opening {
            assertion: AssertionId::GENESIS,
            defender: PartyId(1),
            challenger: PartyId(2),
            trace_length: length,
            lo_commitment: challenger.commitment_at(0),
            hi_commitment: defender.commitment_at(length),
            challenge_window: DEFAULT_CHALLENGE_WINDOW,
        },
        0,
    )
}

// --- The central claim -------------------------------------------------------

#[test]
fn an_honest_verifier_defeats_a_sequencer_who_inflates_a_balance() {
    let (pre, batch) = sample_batch();
    let instructions = program(&batch);

    // The sequencer executes a debit of 1 where the batch says 1,000 — keeping
    // the difference. Everything downstream is real, so only the balances differ.
    let victim = address_of(&signer(1));
    let fraud_step = instructions
        .iter()
        .position(|i| {
            matches!(i, Instruction::Debit { account, amount, .. }
            if *account == victim && *amount >= 1_000)
        })
        .expect("the batch should contain a debit to falsify");
    let substitute = Instruction::Debit {
        account: victim,
        asset: USDC,
        amount: 1,
    };

    let liar = fraudulent_trace(&pre, &instructions, fraud_step, &substitute);

    let mut honest_trie = pre.clone();
    let honest = execute_batch(&mut honest_trie, &batch).unwrap();

    assert_ne!(
        liar.final_state().state_root,
        honest.final_state().state_root,
        "the harness must actually produce divergent traces"
    );

    let defender = TracePlayer::new(liar.clone(), pre.clone());
    let challenger = TracePlayer::new(honest, pre);

    let mut dispute = open_dispute(&defender, &challenger, liar.len() as u64);
    let (winner, step) = play_out(&defender, &challenger, &instructions, &mut dispute);

    assert_eq!(winner, Party::Challenger, "fraud must lose");
    assert_eq!(
        step,
        Some(fraud_step as u64),
        "bisection must converge on the step that was actually falsified"
    );
}

#[test]
fn the_verdict_names_the_reason_the_claim_failed() {
    let (pre, batch) = sample_batch();
    let instructions = program(&batch);
    let victim = address_of(&signer(1));
    let fraud_step = instructions
        .iter()
        .position(|i| matches!(i, Instruction::Credit { account, .. } if *account != victim))
        .unwrap();

    let Instruction::Credit {
        account,
        asset,
        amount,
    } = instructions[fraud_step].clone()
    else {
        unreachable!()
    };
    let substitute = Instruction::Credit {
        account,
        asset,
        amount: amount + 999_999,
    };

    let liar = fraudulent_trace(&pre, &instructions, fraud_step, &substitute);
    let mut honest_trie = pre.clone();
    let honest = execute_batch(&mut honest_trie, &batch).unwrap();

    let defender = TracePlayer::new(liar.clone(), pre.clone());
    let challenger = TracePlayer::new(honest, pre);
    let mut dispute = open_dispute(&defender, &challenger, liar.len() as u64);

    // Drive to the one-step stage, then inspect the verdict directly.
    let mut now = 0;
    while matches!(dispute.stage, Stage::Bisecting { .. }) {
        now += 60;
        let role = dispute.turn;
        let player = if role == Party::Defender {
            &defender
        } else {
            &challenger
        };
        player.play(&mut dispute, role, now).unwrap();
    }

    let proof = challenger.one_step_proof(&dispute).unwrap();
    let verdict = adjudicate(&instructions, &dispute, &proof);
    assert_eq!(verdict.winner, Party::Challenger);
    assert_eq!(verdict.reason, VerdictReason::DefenderClaimRefuted);
}

#[test]
fn an_honest_sequencer_defeats_a_frivolous_challenger() {
    // The converse guarantee: challenging costs the challenger their bond if
    // the assertion was sound (REQ-FRAUD-021).
    let (pre, batch) = sample_batch();
    let instructions = program(&batch);

    let mut honest_trie = pre.clone();
    let honest = execute_batch(&mut honest_trie, &batch).unwrap();

    // The challenger invents a divergence that is not there.
    let victim = address_of(&signer(2));
    let bogus_step = instructions
        .iter()
        .position(|i| matches!(i, Instruction::Credit { account, .. } if *account == victim))
        .unwrap();
    let substitute = Instruction::Credit {
        account: victim,
        asset: USDC,
        amount: 1,
    };
    let bogus = fraudulent_trace(&pre, &instructions, bogus_step, &substitute);

    let defender = TracePlayer::new(honest.clone(), pre.clone());
    let challenger = TracePlayer::new(bogus, pre);

    let length = honest.len() as u64;
    let mut dispute = Dispute::open(
        &Opening {
            assertion: AssertionId::GENESIS,
            defender: PartyId(1),
            challenger: PartyId(2),
            trace_length: length,
            lo_commitment: defender.commitment_at(0),
            hi_commitment: defender.commitment_at(length),
            challenge_window: DEFAULT_CHALLENGE_WINDOW,
        },
        0,
    );
    let (winner, _) = play_out(&defender, &challenger, &instructions, &mut dispute);
    assert_eq!(winner, Party::Defender, "a groundless challenge must fail");
}

#[test]
fn bisection_converges_in_logarithmic_rounds() {
    let (pre, batch) = sample_batch();
    let instructions = program(&batch);
    let victim = address_of(&signer(1));
    let fraud_step = instructions.len() - 1;
    let substitute = Instruction::Credit {
        account: victim,
        asset: USDC,
        amount: 7,
    };

    let liar = fraudulent_trace(&pre, &instructions, fraud_step, &substitute);
    let mut honest_trie = pre.clone();
    let honest = execute_batch(&mut honest_trie, &batch).unwrap();

    let defender = TracePlayer::new(liar.clone(), pre.clone());
    let challenger = TracePlayer::new(honest, pre);
    let mut dispute = open_dispute(&defender, &challenger, liar.len() as u64);

    let mut rounds = 0;
    let mut now = 0;
    while matches!(dispute.stage, Stage::Bisecting { .. }) {
        now += 60;
        let role = dispute.turn;
        let player = if role == Party::Defender {
            &defender
        } else {
            &challenger
        };
        player.play(&mut dispute, role, now).unwrap();
        rounds += 1;
    }

    // Two moves per round, arity 8, ~120 steps: a handful of rounds, not 120.
    assert!(
        rounds <= 12,
        "expected logarithmic convergence, took {rounds} moves"
    );
}

// --- Timeouts and the clock --------------------------------------------------

#[test]
fn a_party_that_stops_responding_forfeits() {
    let (pre, batch) = sample_batch();
    let mut trie = pre.clone();
    let honest = execute_batch(&mut trie, &batch).unwrap();
    let player = TracePlayer::new(honest.clone(), pre);

    let mut dispute = open_dispute(&player, &player, honest.len() as u64);
    assert_eq!(dispute.turn, Party::Defender);

    assert!(dispute.check_timeout(MOVE_TIMEOUT).is_none(), "not yet due");
    assert_eq!(
        dispute.check_timeout(MOVE_TIMEOUT + 1),
        Some(Party::Challenger)
    );
    assert!(matches!(
        dispute.stage,
        Stage::Resolved {
            reason: Resolution::Timeout,
            ..
        }
    ));
}

#[test]
fn a_party_that_exhausts_its_total_budget_forfeits() {
    // The chess clock is a backstop behind the per-move deadline. A party that
    // answers just inside every deadline still runs out of total time, which is
    // what stops an adversary dragging a dispute toward the challenge window
    // (REQ-FRAUD-015).
    //
    // Tested directly rather than by stalling through a real game, because
    // bisection converges in a handful of rounds and would finish long before
    // the budget ran out -- which is the system working, not the clock failing.
    let (pre, batch) = sample_batch();
    let mut trie = pre.clone();
    let honest = execute_batch(&mut trie, &batch).unwrap();
    let player = TracePlayer::new(honest.clone(), pre);
    let mut dispute = open_dispute(&player, &player, honest.len() as u64);

    dispute.deadline = u64::MAX; // isolate the clock from the move deadline
    let overrun = clock_budget(DEFAULT_CHALLENGE_WINDOW) + 1;
    assert!(player.play(&mut dispute, Party::Defender, overrun).is_err());
    assert!(
        matches!(
            dispute.stage,
            Stage::Resolved {
                reason: Resolution::ClockExhausted,
                ..
            }
        ),
        "expected clock exhaustion, got {:?}",
        dispute.stage
    );
    assert_eq!(dispute.winner(), Some(Party::Challenger));
}

#[test]
fn moves_are_charged_against_the_mover_clock() {
    let (pre, batch) = sample_batch();
    let mut trie = pre.clone();
    let honest = execute_batch(&mut trie, &batch).unwrap();
    let player = TracePlayer::new(honest.clone(), pre);
    let mut dispute = open_dispute(&player, &player, honest.len() as u64);

    let before = dispute.defender_clock;
    let challenger_before = dispute.challenger_clock;
    player.play(&mut dispute, Party::Defender, 3_600).unwrap();

    assert_eq!(dispute.defender_clock, before - 3_600, "the mover pays");
    assert_eq!(
        dispute.challenger_clock, challenger_before,
        "the waiting party must not be charged for their opponent's delay"
    );
}

#[test]
fn a_dispute_always_concludes_inside_its_challenge_window() {
    // NFR-PERF-006. A dispute that could outlive its window would let fraud
    // finalize while it was still under challenge. The budget is derived from
    // the window precisely so this holds at every window the chain accepts --
    // including one set at the floor, where a fixed budget generous enough to
    // be fair under congestion would not have fitted.
    for window in [
        CHALLENGE_WINDOW_FLOOR,
        DEFAULT_CHALLENGE_WINDOW,
        CHALLENGE_WINDOW_FLOOR * 30,
    ] {
        let both_parties = 2 * clock_budget(window);
        assert!(
            both_parties < window,
            "at a {window}s window both clocks total {both_parties}s, which does not fit"
        );
    }
}

#[test]
fn a_single_move_can_never_consume_a_whole_budget() {
    // At a window near the floor, a fixed per-move timeout would otherwise
    // exceed the total budget, letting one stall end the dispute outright.
    let (pre, batch) = sample_batch();
    let mut trie = pre.clone();
    let honest = execute_batch(&mut trie, &batch).unwrap();
    let player = TracePlayer::new(honest.clone(), pre);
    let length = honest.len() as u64;

    let dispute = Dispute::open(
        &Opening {
            assertion: AssertionId::GENESIS,
            defender: PartyId(1),
            challenger: PartyId(2),
            trace_length: length,
            lo_commitment: player.commitment_at(0),
            hi_commitment: player.commitment_at(length),
            challenge_window: CHALLENGE_WINDOW_FLOOR,
        },
        0,
    );
    assert!(
        dispute.deadline <= dispute.clock_budget,
        "a single move ({}s) must not outlast the budget ({}s)",
        dispute.deadline,
        dispute.clock_budget
    );
    assert!(dispute.deadline <= MOVE_TIMEOUT);
}

// --- Detection ---------------------------------------------------------------

#[test]
fn a_verifier_detects_a_divergent_root() {
    let (pre, batch) = sample_batch();
    let mut trie = pre.clone();
    let honest = execute_batch(&mut trie, &batch).unwrap();

    let sound = Assertion {
        parent: AssertionId::GENESIS,
        proposer: PartyId(1),
        pre_state_root: pre.root(),
        post_state_root: honest.final_state().state_root,
        batch_commitment: Hash256::digest(b"batch"),
        trace_length: honest.len() as u64,
        bond: BOND,
    };
    assert_eq!(check_assertion(&sound, &honest), Finding::Agrees);

    let mut lying = sound.clone();
    lying.post_state_root = Hash256::digest(b"a root nobody computed");
    assert!(check_assertion(&lying, &honest).warrants_challenge());
}

#[test]
fn a_verifier_detects_an_overstated_trace_length() {
    let (pre, batch) = sample_batch();
    let mut trie = pre.clone();
    let honest = execute_batch(&mut trie, &batch).unwrap();

    let mut lying = Assertion {
        parent: AssertionId::GENESIS,
        proposer: PartyId(1),
        pre_state_root: pre.root(),
        post_state_root: honest.final_state().state_root,
        batch_commitment: Hash256::digest(b"batch"),
        trace_length: honest.len() as u64 + 50,
        bond: BOND,
    };
    assert!(matches!(
        check_assertion(&lying, &honest),
        Finding::TraceLengthDiverges { .. }
    ));

    lying.trace_length = honest.len() as u64;
    assert_eq!(check_assertion(&lying, &honest), Finding::Agrees);
}

// --- The assertion chain -----------------------------------------------------

fn chain() -> (AssertionChain, Hash256) {
    let root = Hash256::digest(b"genesis state");
    (
        AssertionChain::new(root, DEFAULT_CHALLENGE_WINDOW, BOND),
        root,
    )
}

fn child(parent: AssertionId, pre: Hash256, post: Hash256) -> Assertion {
    Assertion {
        parent,
        proposer: PartyId(1),
        pre_state_root: pre,
        post_state_root: post,
        batch_commitment: Hash256::digest(b"batch"),
        trace_length: 10,
        bond: BOND,
    }
}

#[test]
fn an_assertion_cannot_finalize_before_its_window_elapses() {
    let (mut chain, root) = chain();
    let parent = chain.latest_finalized().unwrap().assertion.id();
    let next = Hash256::digest(b"next");
    let id = chain.post(child(parent, root, next)).unwrap();

    chain.advance_to(DEFAULT_CHALLENGE_WINDOW - 1).unwrap();
    assert!(matches!(
        chain.finalize(&id),
        Err(ChainError::WindowOpen { .. })
    ));

    chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    chain.finalize(&id).unwrap();
    assert_eq!(chain.status(&id), Some(Status::Finalized));
}

#[test]
fn a_challenged_assertion_cannot_finalize() {
    // REQ-FRAUD-006, and the reason no governance path to finalize exists.
    let (mut chain, root) = chain();
    let parent = chain.latest_finalized().unwrap().assertion.id();
    let id = chain
        .post(child(parent, root, Hash256::digest(b"next")))
        .unwrap();

    chain.open_challenge(&id).unwrap();
    chain.advance_to(DEFAULT_CHALLENGE_WINDOW * 10).unwrap();
    assert!(matches!(
        chain.finalize(&id),
        Err(ChainError::WrongStatus { .. })
    ));

    chain.defender_won(&id).unwrap();
    chain.finalize(&id).unwrap();
}

#[test]
fn every_challenge_must_resolve_before_finalization() {
    let (mut chain, root) = chain();
    let parent = chain.latest_finalized().unwrap().assertion.id();
    let id = chain
        .post(child(parent, root, Hash256::digest(b"next")))
        .unwrap();

    chain.open_challenge(&id).unwrap();
    chain.open_challenge(&id).unwrap();
    chain.advance_to(DEFAULT_CHALLENGE_WINDOW * 2).unwrap();

    chain.defender_won(&id).unwrap();
    assert!(chain.finalize(&id).is_err(), "one challenge is still open");
    chain.defender_won(&id).unwrap();
    chain.finalize(&id).unwrap();
}

#[test]
fn a_successful_challenge_rejects_every_descendant() {
    // REQ-FRAUD-019: children claim to continue from a state that was never
    // reached, so they cannot survive their parent.
    let (mut chain, root) = chain();
    let genesis = chain.latest_finalized().unwrap().assertion.id();

    let a_root = Hash256::digest(b"a");
    let b_root = Hash256::digest(b"b");
    let a = chain.post(child(genesis, root, a_root)).unwrap();
    let b = chain.post(child(a, a_root, b_root)).unwrap();
    let c = chain.post(child(b, b_root, Hash256::digest(b"c"))).unwrap();

    chain.open_challenge(&a).unwrap();
    let rejected = chain.challenger_won(&a).unwrap();

    assert_eq!(rejected.len(), 3);
    for id in [a, b, c] {
        assert_eq!(chain.status(&id), Some(Status::Rejected));
    }
}

#[test]
fn nothing_may_be_built_on_a_rejected_assertion() {
    let (mut chain, root) = chain();
    let genesis = chain.latest_finalized().unwrap().assertion.id();
    let a_root = Hash256::digest(b"a");
    let a = chain.post(child(genesis, root, a_root)).unwrap();

    chain.open_challenge(&a).unwrap();
    chain.challenger_won(&a).unwrap();

    assert_eq!(
        chain
            .post(child(a, a_root, Hash256::digest(b"x")))
            .unwrap_err(),
        ChainError::ParentRejected
    );
}

#[test]
fn an_assertion_must_continue_its_parents_state() {
    let (mut chain, _) = chain();
    let genesis = chain.latest_finalized().unwrap().assertion.id();
    let err = chain
        .post(child(
            genesis,
            Hash256::digest(b"unrelated"),
            Hash256::digest(b"x"),
        ))
        .unwrap_err();
    assert!(matches!(err, ChainError::BrokenChain { .. }));
}

#[test]
fn an_underbonded_assertion_is_refused() {
    let (mut chain, root) = chain();
    let genesis = chain.latest_finalized().unwrap().assertion.id();
    let mut weak = child(genesis, root, Hash256::digest(b"x"));
    weak.bond = BOND - 1;
    assert!(matches!(
        chain.post(weak),
        Err(ChainError::BondTooSmall { .. })
    ));
}

#[test]
fn an_assertion_cannot_finalize_ahead_of_its_parent() {
    let (mut chain, root) = chain();
    let genesis = chain.latest_finalized().unwrap().assertion.id();
    let a_root = Hash256::digest(b"a");
    let a = chain.post(child(genesis, root, a_root)).unwrap();
    let b = chain.post(child(a, a_root, Hash256::digest(b"b"))).unwrap();

    chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    chain.open_challenge(&a).unwrap();
    assert!(
        chain.finalize(&b).is_err(),
        "b must not outrun its disputed parent"
    );
}

#[test]
fn withdrawals_are_honoured_only_against_finalized_roots() {
    // REQ-FRAUD-005: this is the rule that makes the challenge window mean
    // something to a user's funds.
    let (mut chain, root) = chain();
    let genesis = chain.latest_finalized().unwrap().assertion.id();
    let pending_root = Hash256::digest(b"pending");
    let id = chain.post(child(genesis, root, pending_root)).unwrap();

    assert!(chain.is_withdrawable(&root), "genesis is finalized");
    assert!(
        !chain.is_withdrawable(&pending_root),
        "pending roots are not withdrawable"
    );

    chain.advance_to(DEFAULT_CHALLENGE_WINDOW).unwrap();
    chain.finalize(&id).unwrap();
    assert!(chain.is_withdrawable(&pending_root));
}

#[test]
fn the_challenge_window_cannot_be_set_below_the_floor() {
    // REQ-FRAUD-004. Clamped rather than rejected, so no configuration path can
    // produce a chain with an unsafe window.
    let chain = AssertionChain::new(Hash256::ZERO, 1, BOND);
    assert_eq!(chain.challenge_window(), CHALLENGE_WINDOW_FLOOR);
}

#[test]
fn the_chain_clock_cannot_run_backwards() {
    let (mut chain, _) = chain();
    chain.advance_to(1_000).unwrap();
    assert_eq!(chain.advance_to(999), Err(ChainError::TimeWentBackwards));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Wherever the fraud is placed in the trace, the honest challenger wins and
    /// bisection lands on exactly the falsified step.
    #[test]
    fn honest_challenger_always_wins_wherever_fraud_is_placed(offset in 0usize..100) {
        let (pre, batch) = sample_batch();
        let instructions = program(&batch);

        // Pick a Credit step -- always applicable, so the substitution succeeds.
        let credit_steps: Vec<usize> = instructions
            .iter()
            .enumerate()
            .filter(|(_, i)| matches!(i, Instruction::Credit { .. }))
            .map(|(i, _)| i)
            .collect();
        let fraud_step = credit_steps[offset % credit_steps.len()];

        let Instruction::Credit { account, asset, amount } = instructions[fraud_step].clone()
        else {
            unreachable!()
        };
        let substitute = Instruction::Credit { account, asset, amount: amount + 4_242 };

        let liar = fraudulent_trace(&pre, &instructions, fraud_step, &substitute);
        let mut honest_trie = pre.clone();
        let honest = execute_batch(&mut honest_trie, &batch).unwrap();

        let defender = TracePlayer::new(liar.clone(), pre.clone());
        let challenger = TracePlayer::new(honest, pre);
        let mut dispute = open_dispute(&defender, &challenger, liar.len() as u64);

        let (winner, step) = play_out(&defender, &challenger, &instructions, &mut dispute);
        prop_assert_eq!(winner, Party::Challenger);
        prop_assert_eq!(step, Some(fraud_step as u64));
    }
}
