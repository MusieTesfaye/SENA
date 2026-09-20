//! An end-to-end demonstration of the SENA protocol.
//!
//! Runs three scenarios against real code — no mocks, no shortcuts:
//!
//! 1. An honest sequencer produces blocks and an independent verifier,
//!    rebuilding from published batch data alone, reaches the same state.
//! 2. A dishonest sequencer asserts a state it did not compute. The verifier
//!    detects it, challenges, bisection narrows the disagreement to one step,
//!    and Aptos L1 adjudicates that step.
//! 3. A withdrawal is refused against a pending root and honoured once the
//!    challenge window has elapsed.
//!
//! Run with `cargo run --bin sena-demo`.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, Hash256, L2Address};
use sena_state::MerkleTrie;
use sena_stf::gas::fee_for;
use sena_stf::{
    apply, compile, keys, Account, Authenticator, ExecutionTrace, Instruction, MachineState,
    Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};

use sena_fraudproof::{
    adjudicate, AssertionChain, Party, PartyId, Stage, TracePlayer, DEFAULT_CHALLENGE_WINDOW,
};
use sena_node::{Outcome, Sequencer, VerifierNode};

const USDC: AssetId = AssetId(1);
const RATE: u128 = RATE_SCALE;
const BOND: u128 = 1_000_000;

fn main() {
    banner("SENA protocol demonstration");
    honest_operation();
    fraud_is_caught();
    withdrawals_wait_for_finality();
    println!("\nAll scenarios completed.");
}

// --- Scenario 1 --------------------------------------------------------------

fn honest_operation() {
    banner("1. Honest operation: an independent verifier agrees");

    let alice = key(1);
    let bob = key(2);
    let start = genesis(&[(address(&alice), 5_000_000), (address(&bob), 5_000_000)]);

    let mut sequencer = new_sequencer(start.clone());
    let mut verifier = VerifierNode::new(start, PartyId(2));

    println!("  genesis state root   {}", short(&sequencer.state.root()));

    for nonce in 0..6 {
        let tx = signed(
            &alice,
            nonce,
            Payload::Transfer {
                to: address(&bob),
                asset: USDC,
                amount: 1_000,
            },
        );
        sequencer
            .mempool
            .submit(&sequencer.state, tx)
            .expect("admission should accept");
    }
    println!("  {} transactions queued", sequencer.mempool.len());

    let (block, id) = sequencer
        .produce(100)
        .expect("production")
        .expect("a block");
    let assertion = sequencer.chain.get(&id).expect("record").assertion.clone();

    println!(
        "  block {} produced, {} steps",
        block.height,
        block.trace.len()
    );
    println!(
        "  asserted post-root   {}",
        short(&assertion.post_state_root)
    );

    // The verifier has never seen the sequencer's trace. It re-executes the
    // published transactions itself.
    let outcome = verifier.follow(&block, &assertion);
    println!(
        "  verifier re-executed independently: {}",
        describe(&outcome)
    );
    println!("  verifier state root  {}", short(&verifier.state.root()));

    assert_eq!(outcome, Outcome::Accepted);
    assert_eq!(verifier.state.root(), sequencer.state.root());

    println!(
        "  alice {} -> {}",
        5_000_000,
        balance(&sequencer.state, &address(&alice))
    );
    println!(
        "  bob   {} -> {}",
        5_000_000,
        balance(&sequencer.state, &address(&bob))
    );
}

// --- Scenario 2 --------------------------------------------------------------

fn fraud_is_caught() {
    banner("2. Fraud: a sequencer inflates a balance and loses its bond");

    let alice = key(1);
    let bob = key(2);
    let start = genesis(&[(address(&alice), 5_000_000), (address(&bob), 5_000_000)]);

    // The published batch. Both parties derive the instruction list from it.
    let batch: Vec<Transaction> = (0..8)
        .map(|nonce| {
            signed(
                &alice,
                nonce,
                Payload::Transfer {
                    to: address(&bob),
                    asset: USDC,
                    amount: 1_000,
                },
            )
        })
        .collect();
    let program: Vec<Instruction> = batch
        .iter()
        .flat_map(|tx| compile(tx).expect("compiles"))
        .collect();

    // The honest trace, which the verifier computes for itself.
    let mut honest_state = start.clone();
    let honest = sena_stf::execute_batch(&mut honest_state, &batch).expect("executes");

    // The sequencer's lie: it executes a debit of 1 where the batch says 1,000
    // and pockets the difference. The instruction list is unchanged -- only the
    // states it claims differ.
    let victim = address(&alice);
    let fraud_step = program
        .iter()
        .position(|i| {
            matches!(i, Instruction::Debit { account, amount, .. }
            if *account == victim && *amount >= 1_000)
        })
        .expect("a debit to falsify");
    let substitute = Instruction::Debit {
        account: victim,
        asset: USDC,
        amount: 1,
    };
    let liar = falsify(&start, &program, fraud_step, &substitute);

    println!(
        "  batch of {} transactions, {} execution steps",
        batch.len(),
        program.len()
    );
    println!(
        "  honest post-root     {}",
        short(&honest.final_state().state_root)
    );
    println!(
        "  asserted post-root   {}",
        short(&liar.final_state().state_root)
    );
    println!("  (sequencer falsified step {fraud_step}, keeping 999 units)");

    let defender = TracePlayer::new(liar.clone(), start.clone());
    let challenger = TracePlayer::new(honest, start);

    let length = liar.len() as u64;
    let mut dispute = sena_fraudproof::Dispute::open(
        &sena_fraudproof::Opening {
            assertion: sena_fraudproof::AssertionId::GENESIS,
            defender: PartyId(1),
            challenger: PartyId(2),
            trace_length: length,
            lo_commitment: challenger.commitment_at(0),
            hi_commitment: defender.commitment_at(length),
            challenge_window: DEFAULT_CHALLENGE_WINDOW,
        },
        0,
    );

    println!(
        "\n  challenge opened; bisecting {}..{}",
        dispute.lo, dispute.hi
    );

    let mut now = 0;
    let mut round = 0;
    while matches!(dispute.stage, Stage::Bisecting { .. }) {
        now += 60;
        let role = dispute.turn;
        let player = if role == Party::Defender {
            &defender
        } else {
            &challenger
        };
        player
            .play(&mut dispute, role, now)
            .expect("honest play accepted");
        if role == Party::Challenger {
            round += 1;
            println!(
                "    round {round}: narrowed to {}..{}",
                dispute.lo, dispute.hi
            );
        }
    }

    let step = dispute.disputed_step().expect("narrowed to one step");
    println!("  bisection settled on step {step}");

    let proof = challenger
        .one_step_proof(&dispute)
        .expect("proof available");
    let verdict = adjudicate(&program, &dispute, &proof);

    println!("  Aptos L1 executed step {step} itself");
    println!(
        "  verdict: {:?} wins ({:?})",
        verdict.winner, verdict.reason
    );

    assert_eq!(verdict.winner, Party::Challenger);
    assert_eq!(step, fraud_step as u64);
    println!("  -> assertion rejected, proposer bond of {BOND} slashed");
}

// --- Scenario 3 --------------------------------------------------------------

fn withdrawals_wait_for_finality() {
    banner("3. Withdrawals: only against a finalized root");

    let alice = key(1);
    let start = genesis(&[(address(&alice), 1_000_000)]);
    let mut sequencer = new_sequencer(start);

    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address(&key(2)),
            asset: USDC,
            amount: 500,
        },
    );
    sequencer
        .mempool
        .submit(&sequencer.state, tx)
        .expect("admission");
    let (_, id) = sequencer
        .produce(100)
        .expect("production")
        .expect("a block");

    let root = sequencer.state.root();
    println!("  root {} posted", short(&root));
    println!(
        "  withdrawable now?                {}",
        yes_no(sequencer.chain.is_withdrawable(&root))
    );
    println!(
        "  challenge window                 {} days",
        DEFAULT_CHALLENGE_WINDOW / 86_400
    );

    sequencer
        .chain
        .advance_to(DEFAULT_CHALLENGE_WINDOW - 1)
        .expect("time advances");
    println!(
        "  withdrawable one second early?   {}",
        yes_no(sequencer.chain.finalize(&id).is_ok())
    );

    sequencer
        .chain
        .advance_to(DEFAULT_CHALLENGE_WINDOW)
        .expect("time advances");
    sequencer.chain.finalize(&id).expect("window elapsed");
    println!(
        "  withdrawable after the window?   {}",
        yes_no(sequencer.chain.is_withdrawable(&root))
    );
    println!(
        "  finalized height                 {}",
        sequencer.finalized_height()
    );
}

// --- Helpers -----------------------------------------------------------------

fn banner(title: &str) {
    println!("\n{}", "=".repeat(70));
    println!("{title}");
    println!("{}", "=".repeat(70));
}

fn short(hash: &Hash256) -> String {
    format!("{}…", &hash.to_hex()[..16])
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Accepted => "agrees".to_owned(),
        Outcome::Divergent { finding } => format!("DISAGREES ({finding:?})"),
        Outcome::Unexecutable { reason } => format!("batch will not execute ({reason})"),
    }
}

fn key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

fn address(key: &SigningKey) -> L2Address {
    L2Address::from_bytes(key.verifying_key().to_bytes())
}

fn signed(key: &SigningKey, nonce: u64, payload: Payload) -> Transaction {
    let mut tx = Transaction {
        sender: address(key),
        nonce,
        fee_asset: USDC,
        max_fee: fee_for(RATE).expect("rate is valid"),
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
    .expect("genesis whitelist");
    for (account, amount) in accounts {
        apply(
            &mut trie,
            &Instruction::Credit {
                account: *account,
                asset: USDC,
                amount: *amount,
            },
        )
        .expect("genesis credit");
    }
    trie
}

fn new_sequencer(state: MerkleTrie) -> Sequencer {
    let chain = AssertionChain::new(state.root(), DEFAULT_CHALLENGE_WINDOW, BOND);
    Sequencer::new(state, chain, PartyId(1), BOND)
}

fn balance(state: &MerkleTrie, address: &L2Address) -> u128 {
    state
        .get(&keys::account(address))
        .and_then(|bytes| Account::decode(bytes).ok())
        .map_or(0, |account| account.balance(USDC))
}

/// Builds a trace that misreports one step, leaving the instruction list intact.
fn falsify(
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
        let root = apply(&mut trie, executed).expect("substitution applies");
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
