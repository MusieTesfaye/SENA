//! Writes the plan for a real on-chain dispute, as JSON.
//!
//! Builds the same scenario `tests/move_vectors.rs` gives the Move unit tests
//! — two Ed25519 transfers and a keyless transfer carrying Aptos's real
//! circuit proof, with the keyless credit forged a thousandfold — but stamped
//! with a caller-chosen batch time, so the batch is fresh enough for a live
//! chain to accept. `scripts/localnet-dispute.py` replays it against a local
//! Aptos node, through real transactions, and reports the gas each move costs.
//!
//! ```sh
//! cargo run -p sena-fraudproof --example dispute_plan -- <unix-timestamp> > plan.json
//! ```

use ed25519_dalek::{Signer, SigningKey};
use sena_fraudproof::bisection::{Dispute, Opening, Stage};
use sena_fraudproof::{AssertionId, PartyId, TracePlayer};
use sena_primitives::{AssetId, Hash256, L2Address};
use sena_state::{MerkleTrie, Terminal};
use sena_stf::gas::fee_for;
use sena_stf::keyless::{aptos_sample, KeylessConfig};
use sena_stf::{
    apply, execute_batch, Authenticator, BatchContext, ExecutionTrace, Instruction, MachineState,
    Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};
use serde_json::json;

const USDC: AssetId = AssetId(1);

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn addr(k: &SigningKey) -> L2Address {
    L2Address::from_bytes(k.verifying_key().to_bytes())
}

fn base(sender: L2Address, nonce: u64, to: L2Address, amount: u128) -> Transaction {
    Transaction {
        sender,
        nonce,
        fee_asset: USDC,
        max_fee: fee_for(RATE_SCALE).unwrap(),
        fee_rate: RATE_SCALE,
        payload: Payload::Transfer {
            to,
            asset: USDC,
            amount,
        },
        authenticator: Authenticator::Ed25519 {
            public_key: [0; 32],
            signature: [0; 64],
        },
    }
}

fn transfer(from: &SigningKey, nonce: u64, to: L2Address, amount: u128) -> Transaction {
    let mut tx = base(addr(from), nonce, to, amount);
    let signature = from.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: from.verifying_key().to_bytes(),
        signature,
    };
    tx
}

fn keyless_transfer(to: L2Address, amount: u128) -> Transaction {
    let sig = aptos_sample::signature();
    let mut tx = base(sig.address(), 0, to, amount);
    tx.authenticator = Authenticator::Keyless(Box::new(sig));
    let esk = SigningKey::from_bytes(&aptos_sample::ephemeral_secret_key());
    let s = esk.sign(tx.signing_digest().as_bytes()).to_bytes();
    if let Authenticator::Keyless(k) = &mut tx.authenticator {
        k.ephemeral_signature = s;
    }
    tx
}

fn genesis() -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    let record = WhitelistedAsset {
        asset: USDC,
        symbol: "USDC".into(),
        rate: RATE_SCALE,
        enabled: true,
    };
    apply(&mut trie, &Instruction::SetGasAsset { record }).unwrap();
    let sample = aptos_sample::signature();
    apply(
        &mut trie,
        &Instruction::SetJwk {
            iss_hash: sample.iss_hash,
            jwk_hash: sample.jwk_hash,
            active: true,
        },
    )
    .unwrap();
    for who in [addr(&key(1)), sample.address()] {
        apply(
            &mut trie,
            &Instruction::Credit {
                account: who,
                asset: USDC,
                amount: 5_000_000,
            },
        )
        .unwrap();
    }
    trie
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn main() {
    let timestamp: u64 = std::env::args()
        .nth(1)
        .expect("usage: dispute_plan <unix-timestamp>")
        .parse()
        .expect("a unix timestamp");
    let devnet = KeylessConfig::aptos_devnet_insecure();
    let ctx = BatchContext {
        timestamp,
        keyless: Some(&devnet),
    };

    let bob = addr(&key(2));
    let txs = vec![
        transfer(&key(1), 0, bob, 1_000),
        keyless_transfer(bob, 1_234),
        transfer(&key(1), 1, addr(&key(3)), 7),
    ];
    let pre = genesis();
    let honest = execute_batch(&mut pre.clone(), &ctx, &txs).unwrap();
    let tree = honest.batch_tree(&txs);

    let at = usize::try_from(honest.tx_starts[1]).unwrap() + 6;
    let Instruction::Credit {
        account,
        asset,
        amount,
    } = honest.instructions[at]
    else {
        panic!()
    };
    let mut trie = pre.clone();
    let mut states = vec![MachineState::start(trie.root())];
    for (i, ins) in honest.instructions.iter().enumerate() {
        let forged = Instruction::Credit {
            account,
            asset,
            amount: amount * 1_000,
        };
        let root = apply(&mut trie, if i == at { &forged } else { ins }).unwrap();
        states.push(MachineState {
            state_root: root,
            pc: (i + 1) as u64,
        });
    }
    let fraud = ExecutionTrace {
        instructions: honest.instructions.clone(),
        states,
        tx_starts: honest.tx_starts.clone(),
    };
    let defender = TracePlayer::new(fraud.clone(), pre.clone());
    let challenger = TracePlayer::new(honest.clone(), pre.clone());

    let len = honest.len() as u64;
    let mut d = Dispute::open(
        &Opening {
            assertion: AssertionId(Hash256::ZERO),
            defender: PartyId(1),
            challenger: PartyId(2),
            trace_length: len,
            lo_commitment: defender.commitment_at(0),
            hi_commitment: defender.commitment_at(len),
            challenge_window: 86_400,
        },
        0,
    );
    let mut rounds = Vec::new();
    let mut now = 0;
    while matches!(d.stage, Stage::Bisecting { .. }) {
        let offered = defender.dissect(&d);
        now += 1;
        d.dissect(now, offered.clone()).unwrap();
        let index = challenger.first_disagreement(&d, &offered).unwrap();
        now += 1;
        d.select(now, index).unwrap();
        rounds.push(json!({
            "commitments": offered.iter().map(|h| hx(h.as_bytes())).collect::<Vec<_>>(),
            "select": index,
        }));
    }
    let step = d.disputed_step().unwrap();
    let leaf = honest.tx_starts.iter().rposition(|s| *s <= step).unwrap();
    let osp = challenger.one_step_proof(&d).unwrap();
    let (is_leaf, tk, tv) = match &osp.witness.proof.terminal {
        Terminal::Empty => (false, Hash256::ZERO, Hash256::ZERO),
        Terminal::Leaf { key, value_hash } => (true, *key, *value_hash),
    };

    let plan = json!({
        "genesis_root": hx(pre.root().as_bytes()),
        "timestamp": timestamp,
        "txs": txs.iter().map(|t| hx(&t.encode())).collect::<Vec<_>>(),
        "starts": honest.tx_starts,
        "trace_length": len,
        "fraud_post_root": hx(fraud.final_state().state_root.as_bytes()),
        "honest_post_root": hx(honest.final_state().state_root.as_bytes()),
        "rounds": rounds,
        "one_step": {
            "leaf_index": leaf,
            "leaf_start": honest.tx_starts[leaf],
            "leaf_tx": hx(&txs[leaf].encode()),
            "leaf_siblings": tree.prove(leaf as u64).unwrap().siblings.iter().map(|h| hx(h.as_bytes())).collect::<Vec<_>>(),
            "pre_root": hx(osp.pre_state.state_root.as_bytes()),
            "slot": hx(osp.witness.slot.as_bytes()),
            "present": osp.witness.value.is_some(),
            "value": hx(osp.witness.value.as_deref().unwrap_or(&[])),
            "trie_siblings": osp.witness.proof.siblings.iter().map(|h| hx(h.as_bytes())).collect::<Vec<_>>(),
            "terminal_is_leaf": is_leaf,
            "terminal_key": hx(tk.as_bytes()),
            "terminal_value_hash": hx(tv.as_bytes()),
        },
    });
    println!("{}", serde_json::to_string_pretty(&plan).unwrap());
}
