//! Generates the Move conformance vectors, and checks they are current.
//!
//! Aptos L1 must reach exactly the conclusions the Rust node does: decode the
//! same bytes, compile the same instructions, accept the same signatures and
//! proofs, and decide the same disputes. This test builds real batches with
//! the Rust implementation — including a keyless transaction carrying Aptos's
//! real circuit proof — plays real disputes over them with the Rust dispute
//! model, and writes every input and expected output to
//! `move/sena/tests/vectors.move`. The Move tests in `dispute_e2e_test.move`
//! replay them against the actual contracts.
//!
//! If the generated file is stale the test fails. Regenerate with:
//!
//! ```sh
//! SENA_WRITE_MOVE_VECTORS=1 cargo test -p sena-fraudproof --test move_vectors
//! ```

use std::fmt::Write as _;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use sena_fraudproof::bisection::{Dispute, Opening, Stage};
use sena_fraudproof::{AssertionId, PartyId, TracePlayer};
use sena_primitives::{AssetId, Channel, Hash256, HashedIdentifier, L2Address, NetworkSalt};
use sena_state::{MerkleTrie, Terminal};
use sena_stf::batch::BatchTree;
use sena_stf::gas::{
    DEFAULT_ASSET_INTRINSIC_GAS, DEFAULT_BASE_FEE_FLOOR, DEFAULT_GAS_TARGET, PRICE_SCALE,
};
use sena_stf::governance::{Council, CouncilSignature, GovernanceUpdate};
use sena_stf::keyless::{aptos_sample, KeylessConfig, KeylessSignature};
use sena_stf::{
    apply, compile, execute_batch, keys, Authenticator, BatchContext, ExecutionTrace, FeeMarket,
    FeeSplit, Instruction, MachineState, Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};

const USDC: AssetId = AssetId(1);
const TIMESTAMP: u64 = 1_700_000_000;
/// The batch's base fee: the floor, which a fresh market rolls to.
const BASE_FEE: u128 = DEFAULT_BASE_FEE_FLOOR;
/// The sequencer that collects the batch's tips.
fn sequencer() -> L2Address {
    L2Address::from_bytes([0x5e; 32])
}
const WINDOW: u64 = 604_800;
/// `sena::keyless` setup ids.
const SETUP_DISABLED: u8 = 0;
const SETUP_MAINNET: u8 = 1;
const SETUP_DEVNET: u8 = 2;

// --- Emitting Move -----------------------------------------------------------

struct Module(String);

impl Module {
    fn bytes(&mut self, name: &str, b: &[u8]) {
        writeln!(
            self.0,
            "    public fun {name}(): vector<u8> {{ x\"{}\" }}",
            hex::encode(b)
        )
        .unwrap();
    }
    fn hash(&mut self, name: &str, h: &Hash256) {
        self.bytes(name, h.as_bytes());
    }
    fn list(&mut self, name: &str, items: &[Vec<u8>]) {
        let body: Vec<String> = items
            .iter()
            .map(|b| format!("x\"{}\"", hex::encode(b)))
            .collect();
        writeln!(
            self.0,
            "    public fun {name}(): vector<vector<u8>> {{ vector[{}] }}",
            body.join(", ")
        )
        .unwrap();
    }
    fn hashes(&mut self, name: &str, items: &[Hash256]) {
        let v: Vec<Vec<u8>> = items.iter().map(|h| h.as_bytes().to_vec()).collect();
        self.list(name, &v);
    }
    fn u64(&mut self, name: &str, v: u64) {
        writeln!(self.0, "    public fun {name}(): u64 {{ {v} }}").unwrap();
    }
    fn u64s(&mut self, name: &str, v: &[u64]) {
        let body: Vec<String> = v.iter().map(u64::to_string).collect();
        writeln!(
            self.0,
            "    public fun {name}(): vector<u64> {{ vector[{}] }}",
            body.join(", ")
        )
        .unwrap();
    }
    fn u8(&mut self, name: &str, v: u8) {
        writeln!(self.0, "    public fun {name}(): u8 {{ {v} }}").unwrap();
    }
    fn boolean(&mut self, name: &str, v: bool) {
        writeln!(self.0, "    public fun {name}(): bool {{ {v} }}").unwrap();
    }
    fn u128(&mut self, name: &str, v: u128) {
        writeln!(self.0, "    public fun {name}(): u128 {{ {v} }}").unwrap();
    }
}

// --- The fixture -------------------------------------------------------------

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn addr(k: &SigningKey) -> L2Address {
    L2Address::from_bytes(k.verifying_key().to_bytes())
}

fn sign_ed25519(k: &SigningKey, mut tx: Transaction) -> Transaction {
    let signature = k.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: k.verifying_key().to_bytes(),
        signature,
    };
    tx
}

fn base(sender: L2Address, nonce: u64, payload: Payload) -> Transaction {
    let mut tx = Transaction {
        sender,
        nonce,
        fee_asset: USDC,
        fee_rate: 0,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload,
        authenticator: Authenticator::Ed25519 {
            public_key: [0; 32],
            signature: [0; 64],
        },
    };
    sena_stf::gas::fill_default_fees(&mut tx);
    tx
}

fn transfer(from: &SigningKey, nonce: u64, to: L2Address, amount: u128) -> Transaction {
    sign_ed25519(
        from,
        base(
            addr(from),
            nonce,
            Payload::Transfer {
                to,
                asset: USDC,
                amount,
            },
        ),
    )
}

fn keyless_transfer(to: L2Address, amount: u128) -> Transaction {
    let sig = aptos_sample::signature();
    let mut tx = base(
        sig.address(),
        0,
        Payload::Transfer {
            to,
            asset: USDC,
            amount,
        },
    );
    tx.authenticator = Authenticator::Keyless(Box::new(sig));
    // Keyless verification costs gas of its own.
    sena_stf::gas::fill_default_fees(&mut tx);
    let esk = SigningKey::from_bytes(&aptos_sample::ephemeral_secret_key());
    let s = esk.sign(tx.signing_digest().as_bytes()).to_bytes();
    if let Authenticator::Keyless(k) = &mut tx.authenticator {
        k.ephemeral_signature = s;
    }
    tx
}

fn council_members() -> [SigningKey; 2] {
    [key(0x51), key(0x52)]
}

fn governance(epoch: u64, update: GovernanceUpdate) -> Transaction {
    let digest = update.signing_digest(epoch);
    let signatures = council_members()
        .iter()
        .enumerate()
        .map(|(i, k)| CouncilSignature {
            index: u32::try_from(i).unwrap(),
            signature: k.sign(digest.as_bytes()).to_bytes(),
        })
        .collect();
    transfer_like_governance(epoch, update, signatures)
}

fn transfer_like_governance(
    epoch: u64,
    update: GovernanceUpdate,
    signatures: Vec<CouncilSignature>,
) -> Transaction {
    let alice = key(1);
    sign_ed25519(
        &alice,
        base(
            addr(&alice),
            9,
            Payload::Governance {
                epoch,
                update,
                signatures,
            },
        ),
    )
}

fn genesis() -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    apply(
        &mut trie,
        &Instruction::SetGasAsset {
            record: WhitelistedAsset {
                asset: USDC,
                symbol: "USDC".into(),
                rate: RATE_SCALE,
                intrinsic_gas: sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS,
                enabled: true,
            },
        },
    )
    .unwrap();
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
    for (who, amount) in [
        (addr(&key(1)), 5_000_000u128),
        (sample.address(), 5_000_000),
    ] {
        apply(
            &mut trie,
            &Instruction::Credit {
                account: who,
                asset: USDC,
                amount,
            },
        )
        .unwrap();
    }
    let council = Council {
        members: council_members()
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect(),
        threshold: 2,
        epoch: 0,
        guardian_threshold: 1,
    };
    trie.insert(keys::council(), council.encode());
    apply(
        &mut trie,
        &Instruction::SetFeeMarket {
            floor: DEFAULT_BASE_FEE_FLOOR,
            target: DEFAULT_GAS_TARGET,
        },
    )
    .unwrap();
    trie
}

fn devnet_ctx(config: &KeylessConfig) -> BatchContext<'_> {
    BatchContext {
        timestamp: TIMESTAMP,
        keyless: Some(config),
        base_fee: BASE_FEE,
        fee_recipient: sequencer(),
    }
}

/// Replays `program` from `pre`, substituting `substitute` at `at`.
fn forged_trace(
    pre: &MerkleTrie,
    honest: &ExecutionTrace,
    at: usize,
    substitute: &Instruction,
) -> ExecutionTrace {
    let mut trie = pre.clone();
    let mut states = vec![MachineState::start(trie.root())];
    for (i, instruction) in honest.instructions.iter().enumerate() {
        let executed = if i == at { substitute } else { instruction };
        let root = apply(&mut trie, executed).expect("forged step applies");
        states.push(MachineState {
            state_root: root,
            pc: (i + 1) as u64,
        });
    }
    ExecutionTrace {
        instructions: honest.instructions.clone(),
        states,
        tx_starts: honest.tx_starts.clone(),
    }
}

/// Plays a game to its one-step stage; returns the moves and the dispute.
fn play(
    defender: &TracePlayer,
    challenger: &TracePlayer,
    len: u64,
) -> (Vec<Vec<Hash256>>, Vec<u64>, Dispute) {
    let opening = Opening {
        assertion: AssertionId(Hash256::ZERO),
        defender: PartyId(1),
        challenger: PartyId(2),
        trace_length: len,
        lo_commitment: defender.commitment_at(0),
        hi_commitment: defender.commitment_at(len),
        challenge_window: WINDOW,
    };
    let mut d = Dispute::open(&opening, 0);
    let mut dissections = Vec::new();
    let mut selections = Vec::new();
    let mut now = 0;
    while matches!(d.stage, Stage::Bisecting { .. }) {
        let offered = defender.dissect(&d);
        now += 1;
        d.dissect(now, offered.clone()).unwrap();
        let index = challenger.first_disagreement(&d, &offered).unwrap_or(0);
        now += 1;
        d.select(now, index).unwrap();
        dissections.push(offered);
        selections.push(index as u64);
    }
    (dissections, selections, d)
}

/// Emits a full one-step game for the Move test to replay.
#[allow(clippy::too_many_arguments)]
fn emit_game(
    m: &mut Module,
    prefix: &str,
    defender: &TracePlayer,
    challenger: &TracePlayer,
    witness_from: &TracePlayer,
    txs: &[Transaction],
    tree: &BatchTree,
    starts: &[u64],
) {
    let len = defender.trace().len() as u64;
    let (dissections, selections, d) = play(defender, challenger, len);
    m.u64(&format!("{prefix}_rounds"), dissections.len() as u64);
    for (r, offered) in dissections.iter().enumerate() {
        m.hashes(&format!("{prefix}_dissection_{r}"), offered);
    }
    let arms: Vec<String> = (0..dissections.len())
        .map(|r| format!("if (r == {r}) {{ return {prefix}_dissection_{r}() }};"))
        .collect();
    writeln!(
        m.0,
        "    public fun {prefix}_dissection(r: u64): vector<vector<u8>> {{ {} abort 0 }}",
        arms.join(" ")
    )
    .unwrap();
    m.u64s(&format!("{prefix}_selections"), &selections);

    let step = d.disputed_step().unwrap();
    m.u64(&format!("{prefix}_step"), step);
    let leaf = starts.iter().rposition(|s| *s <= step).unwrap();
    m.u64(&format!("{prefix}_leaf_index"), leaf as u64);
    m.u64(&format!("{prefix}_leaf_start"), starts[leaf]);
    m.bytes(&format!("{prefix}_leaf_tx"), &txs[leaf].encode());
    m.hashes(
        &format!("{prefix}_leaf_siblings"),
        &tree.prove(leaf as u64).unwrap().siblings,
    );

    let osp = witness_from.one_step_proof(&d).unwrap();
    m.hash(&format!("{prefix}_pre_root"), &osp.pre_state.state_root);
    m.hash(&format!("{prefix}_slot"), &osp.witness.slot);
    m.boolean(&format!("{prefix}_present"), osp.witness.value.is_some());
    m.bytes(
        &format!("{prefix}_value"),
        osp.witness.value.as_deref().unwrap_or(&[]),
    );
    m.hashes(
        &format!("{prefix}_trie_siblings"),
        &osp.witness.proof.siblings,
    );
    let (is_leaf, k, vh) = match &osp.witness.proof.terminal {
        Terminal::Empty => (false, Hash256::ZERO, Hash256::ZERO),
        Terminal::Leaf { key, value_hash } => (true, *key, *value_hash),
    };
    m.boolean(&format!("{prefix}_terminal_is_leaf"), is_leaf);
    m.hash(&format!("{prefix}_terminal_key"), &k);
    m.hash(&format!("{prefix}_terminal_value_hash"), &vh);
}

struct CompileCase {
    name: &'static str,
    bytes: Vec<u8>,
    timestamp: u64,
    setup: u8,
    base_fee: u128,
}

impl CompileCase {
    fn at(name: &'static str, tx: &Transaction) -> Self {
        Self {
            name,
            bytes: tx.encode(),
            timestamp: TIMESTAMP,
            setup: SETUP_DEVNET,
            base_fee: BASE_FEE,
        }
    }
}

fn generate() -> String {
    let devnet = KeylessConfig::aptos_devnet_insecure();
    let mainnet = KeylessConfig::aptos_mainnet();
    let ctx_for = |setup: u8, timestamp: u64, base_fee: u128| -> BatchContext<'_> {
        BatchContext {
            timestamp,
            keyless: match setup {
                SETUP_MAINNET => Some(&*mainnet),
                SETUP_DEVNET => Some(&*devnet),
                _ => None,
            },
            base_fee,
            fee_recipient: sequencer(),
        }
    };

    let mut m = Module(String::new());
    let alice = key(1);
    let bob = addr(&key(2));
    let carol = addr(&key(3));

    // --- The batch disputed in the end-to-end tests ---------------------------

    let txs = vec![
        transfer(&alice, 0, bob, 1_000),
        keyless_transfer(bob, 1_234),
        transfer(&alice, 1, carol, 7),
    ];
    let pre = genesis();
    let mut post = pre.clone();
    let honest = execute_batch(&mut post, &devnet_ctx(&devnet), &txs).expect("honest batch");
    let tree = honest.batch_tree(&txs);
    let starts = honest.tx_starts.clone();

    m.hash("genesis_root", &pre.root());
    m.u64("batch_timestamp", TIMESTAMP);
    m.u128("batch_base_fee", BASE_FEE);
    m.bytes("batch_fee_recipient", sequencer().as_bytes());
    m.list(
        "batch_txs",
        &txs.iter().map(Transaction::encode).collect::<Vec<_>>(),
    );
    m.u64s("batch_starts", &starts);
    m.hash("batch_root", &tree.root());
    m.u64("trace_length", honest.len() as u64);
    m.hash("honest_post_root", &post.root());
    for i in 0..txs.len() {
        m.hashes(
            &format!("batch_siblings_{i}"),
            &tree.prove(i as u64).unwrap().siblings,
        );
    }

    // The fraud: the keyless transfer's credit to Bob is executed as a thousand
    // times the amount, so the step L1 adjudicates is inside the keyless
    // transaction and the dispute exercises the whole keyless path on L1.
    let credit_at = usize::try_from(starts[1]).unwrap() + 6;
    let Instruction::Credit {
        account,
        asset,
        amount,
    } = honest.instructions[credit_at]
    else {
        panic!("expected the payload credit at {credit_at}");
    };
    let forged = forged_trace(
        &pre,
        &honest,
        credit_at,
        &Instruction::Credit {
            account,
            asset,
            amount: amount * 1_000,
        },
    );
    m.hash("fraud_post_root", &forged.final_state().state_root);
    let honest_player = TracePlayer::new(honest.clone(), pre.clone());
    let fraud_player = TracePlayer::new(forged, pre.clone());

    // A fraudulent defender against an honest challenger.
    emit_game(
        &mut m,
        "fraud",
        &fraud_player,
        &honest_player,
        &honest_player,
        &txs,
        &tree,
        &starts,
    );
    // An honest defender against a challenger who believes the fraud.
    emit_game(
        &mut m,
        "honest",
        &honest_player,
        &fraud_player,
        &honest_player,
        &txs,
        &tree,
        &starts,
    );

    // --- Batches with structural fraud ---------------------------------------

    // Start positions that skip steps: transaction 1 claims to start at 3,
    // inside transaction 0.
    let gap_txs = vec![transfer(&alice, 0, bob, 1), transfer(&alice, 1, bob, 2)];
    let gap_starts = vec![0u64, 3];
    let gap_tree = BatchTree::build(
        &gap_starts
            .iter()
            .zip(&gap_txs)
            .map(|(s, t)| (*s, t.encode()))
            .collect::<Vec<_>>(),
    );
    m.list(
        "gap_txs",
        &gap_txs.iter().map(Transaction::encode).collect::<Vec<_>>(),
    );
    m.u64s("gap_starts", &gap_starts);
    m.hashes("gap_siblings_0", &gap_tree.prove(0).unwrap().siblings);
    m.hashes("gap_siblings_1", &gap_tree.prove(1).unwrap().siblings);

    // A transaction whose signature does not verify.
    let mut bad = transfer(&alice, 0, bob, 1);
    if let Authenticator::Ed25519 { signature, .. } = &mut bad.authenticator {
        signature[0] ^= 1;
    }
    m.bytes("bad_signature_tx", &bad.encode());

    // --- Compiler conformance ------------------------------------------------

    let mut cases = vec![
        CompileCase {
            name: "ed25519_transfer",
            bytes: txs[0].encode(),
            timestamp: TIMESTAMP,
            setup: SETUP_DEVNET,
            base_fee: BASE_FEE,
        },
        CompileCase {
            name: "keyless_transfer",
            bytes: txs[1].encode(),
            timestamp: TIMESTAMP,
            setup: SETUP_DEVNET,
            base_fee: BASE_FEE,
        },
        CompileCase {
            name: "keyless_expired",
            bytes: txs[1].encode(),
            timestamp: aptos_sample::EXP_DATE_SECS,
            setup: SETUP_DEVNET,
            base_fee: BASE_FEE,
        },
        CompileCase {
            name: "keyless_wrong_setup",
            bytes: txs[1].encode(),
            timestamp: TIMESTAMP,
            setup: SETUP_MAINNET,
            base_fee: BASE_FEE,
        },
        CompileCase {
            name: "keyless_disabled",
            bytes: txs[1].encode(),
            timestamp: TIMESTAMP,
            setup: SETUP_DISABLED,
            base_fee: BASE_FEE,
        },
        CompileCase {
            name: "bad_signature",
            bytes: bad.encode(),
            timestamp: TIMESTAMP,
            setup: SETUP_DEVNET,
            base_fee: BASE_FEE,
        },
    ];
    let mut wrong_signer = base(
        bob,
        0,
        Payload::Transfer {
            to: carol,
            asset: USDC,
            amount: 1,
        },
    );
    wrong_signer = sign_ed25519(&alice, wrong_signer);
    wrong_signer.sender = bob; // alice's key, bob's account
    let s = alice
        .sign(wrong_signer.signing_digest().as_bytes())
        .to_bytes();
    wrong_signer.authenticator = Authenticator::Ed25519 {
        public_key: alice.verifying_key().to_bytes(),
        signature: s,
    };
    cases.push(CompileCase {
        name: "wrong_signer",
        bytes: wrong_signer.encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    cases.push(CompileCase {
        name: "self_transfer",
        bytes: transfer(&alice, 0, addr(&alice), 1).encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    let plain = || {
        base(
            addr(&alice),
            0,
            Payload::Transfer {
                to: bob,
                asset: USDC,
                amount: 1,
            },
        )
    };
    let mut low_fee = plain();
    low_fee.max_fee_per_gas = BASE_FEE - 1;
    cases.push(CompileCase::at(
        "fee_below_base_fee",
        &sign_ed25519(&alice, low_fee),
    ));
    let mut low_limit = plain();
    low_limit.gas_limit -= 1;
    cases.push(CompileCase::at(
        "gas_limit_too_low",
        &sign_ed25519(&alice, low_limit),
    ));
    let mut zero = plain();
    zero.max_fee_per_gas = 0;
    let zero = sign_ed25519(&alice, zero);
    cases.push(CompileCase {
        base_fee: 0,
        ..CompileCase::at("fee_rounds_to_zero", &zero)
    });
    let mut tipped = plain();
    tipped.gas_limit += 12_345;
    tipped.max_fee_per_gas = 3 * BASE_FEE + 7;
    tipped.max_priority_fee_per_gas = PRICE_SCALE / 3;
    cases.push(CompileCase::at(
        "tip_and_refund",
        &sign_ed25519(&alice, tipped.clone()),
    ));
    // The same transaction in a busier window: the base fee eats into the tip.
    cases.push(CompileCase {
        base_fee: 3 * BASE_FEE,
        ..CompileCase::at("tip_capped_by_max_fee", &sign_ed25519(&alice, tipped))
    });
    // Every part of this one rounds, so the remainder the base fee absorbs is
    // non-zero: a tip of a seventh of a unit per gas, at an asset worth 2/3
    // of a native unit, three gas over what it uses.
    let mut rounding = plain();
    sena_stf::gas::fill_fees(&mut rounding, RATE_SCALE * 3 / 2, 7_001, 10 * BASE_FEE);
    rounding.gas_limit += 3;
    rounding.max_priority_fee_per_gas = PRICE_SCALE / 7;
    let rounding = sign_ed25519(&alice, rounding);
    let c = sena_stf::fee_charge(&rounding, &ctx_for(SETUP_DEVNET, TIMESTAMP, BASE_FEE)).unwrap();
    let exact_base = u128::from(c.gas_used) * (BASE_FEE * 3 / 2) / PRICE_SCALE;
    assert!(
        c.base > exact_base,
        "the case must leave a remainder for the base fee"
    );
    cases.push(CompileCase::at("rounding_remainder", &rounding));
    let mut eurc = plain();
    eurc.fee_asset = AssetId(2);
    sena_stf::gas::fill_fees(&mut eurc, RATE_SCALE * 3 / 2, 7_000, 2 * BASE_FEE);
    cases.push(CompileCase::at(
        "other_asset_rate",
        &sign_ed25519(&alice, eurc),
    ));
    let split = FeeSplit {
        beneficiaries: vec![(bob, 600_000), (carol, 300_001)],
        burn: 99_999,
    };
    cases.push(CompileCase::at(
        "distribute_fees",
        &sign_ed25519(
            &alice,
            base(
                addr(&alice),
                0,
                Payload::DistributeFees {
                    asset: USDC,
                    amount: 1_000_003,
                    split: split.clone(),
                },
            ),
        ),
    ));
    cases.push(CompileCase::at(
        "distribute_nothing",
        &sign_ed25519(
            &alice,
            base(
                addr(&alice),
                0,
                Payload::DistributeFees {
                    asset: USDC,
                    amount: 0,
                    split: split.clone(),
                },
            ),
        ),
    ));
    cases.push(CompileCase::at(
        "distribute_bad_split",
        &sign_ed25519(
            &alice,
            base(
                addr(&alice),
                0,
                Payload::DistributeFees {
                    asset: USDC,
                    amount: 5,
                    split: FeeSplit {
                        beneficiaries: vec![(bob, 1)],
                        burn: 0,
                    },
                },
            ),
        ),
    ));
    cases.push(CompileCase::at(
        "governance_set_fee_market",
        &governance(
            0,
            GovernanceUpdate::SetFeeMarket {
                floor: 2 * DEFAULT_BASE_FEE_FLOOR,
                target: 1_234_567,
            },
        ),
    ));
    cases.push(CompileCase::at(
        "governance_bad_fee_market",
        &governance(
            0,
            GovernanceUpdate::SetFeeMarket {
                floor: 0,
                target: 1,
            },
        ),
    ));
    cases.push(CompileCase::at(
        "governance_set_fee_split",
        &governance(
            0,
            GovernanceUpdate::SetFeeSplit {
                split: split.clone(),
            },
        ),
    ));
    let disable = GovernanceUpdate::DisableGasAsset { asset: USDC };
    let one = council_members()[1]
        .sign(disable.signing_digest(0).as_bytes())
        .to_bytes();
    cases.push(CompileCase::at(
        "guardian_disable",
        &transfer_like_governance(
            0,
            disable,
            vec![CouncilSignature {
                index: 1,
                signature: one,
            }],
        ),
    ));
    let identifier =
        HashedIdentifier::new(Channel::Handle, "@alice", &NetworkSalt::new(*b"vectors"));
    cases.push(CompileCase {
        name: "bind_identifier",
        bytes: sign_ed25519(
            &alice,
            base(
                addr(&alice),
                0,
                Payload::BindIdentifier {
                    channel: Channel::Handle,
                    identifier,
                },
            ),
        )
        .encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    cases.push(CompileCase {
        name: "unbind_identifier",
        bytes: sign_ed25519(
            &alice,
            base(addr(&alice), 1, Payload::UnbindIdentifier { identifier }),
        )
        .encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    let sample = aptos_sample::signature();
    cases.push(CompileCase {
        name: "governance_set_jwk",
        bytes: governance(
            0,
            GovernanceUpdate::SetJwk {
                iss_hash: sample.iss_hash,
                jwk_hash: sample.jwk_hash,
                active: false,
            },
        )
        .encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    cases.push(CompileCase {
        name: "governance_disable_asset",
        bytes: governance(
            0,
            GovernanceUpdate::SetGasAsset {
                record: WhitelistedAsset {
                    asset: USDC,
                    symbol: "USDC".into(),
                    rate: RATE_SCALE,
                    intrinsic_gas: sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS,
                    enabled: false,
                },
            },
        )
        .encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    cases.push(CompileCase {
        name: "governance_set_parameter",
        bytes: governance(
            0,
            GovernanceUpdate::SetParameter {
                name: "batch.max_transactions".into(),
                value: 64,
            },
        )
        .encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    cases.push(CompileCase {
        name: "governance_ungovernable",
        bytes: governance(
            0,
            GovernanceUpdate::SetParameter {
                name: "challenge_window".into(),
                value: 0,
            },
        )
        .encode(),
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    let mut truncated = txs[0].encode();
    truncated.pop();
    cases.push(CompileCase {
        name: "truncated",
        bytes: truncated,
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    let mut trailing = txs[0].encode();
    trailing.push(0);
    cases.push(CompileCase {
        name: "trailing_byte",
        bytes: trailing,
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });
    let mut bad_flag = txs[1].encode();
    let flag = bad_flag.len() - 128 - 32 - 1;
    bad_flag[flag] = 2;
    cases.push(CompileCase {
        name: "keyless_bad_flag",
        bytes: bad_flag,
        timestamp: TIMESTAMP,
        setup: SETUP_DEVNET,
        base_fee: BASE_FEE,
    });

    m.u64("compile_case_count", cases.len() as u64);
    m.u64(
        "council_case",
        cases
            .iter()
            .position(|c| c.name == "governance_set_jwk")
            .unwrap() as u64,
    );
    for (i, case) in cases.iter().enumerate() {
        let rust = Transaction::decode(&case.bytes)
            .ok()
            .and_then(|tx| compile(&tx, &ctx_for(case.setup, case.timestamp, case.base_fee)).ok());
        writeln!(m.0, "    // case {i}: {}", case.name).unwrap();
        m.bytes(&format!("compile_bytes_{i}"), &case.bytes);
        m.u64(&format!("compile_timestamp_{i}"), case.timestamp);
        m.u128(&format!("compile_base_fee_{i}"), case.base_fee);
        m.u8(&format!("compile_setup_{i}"), case.setup);
        m.boolean(&format!("compile_ok_{i}"), rust.is_some());
        let encoded: Vec<Vec<u8>> = rust
            .unwrap_or_default()
            .iter()
            .map(Instruction::encode)
            .collect();
        m.list(&format!("compile_program_{i}"), &encoded);
        if let Ok(tx) = Transaction::decode(&case.bytes) {
            m.hash(&format!("compile_digest_{i}"), &tx.signing_digest());
        } else {
            m.bytes(&format!("compile_digest_{i}"), &[]);
        }
    }

    let arms: Vec<String> = (0..cases.len())
        .map(|i| {
            format!(
                "if (i == {i}) {{ return (compile_bytes_{i}(), compile_timestamp_{i}(), compile_setup_{i}(), \
                 compile_ok_{i}(), compile_program_{i}(), compile_digest_{i}(), compile_base_fee_{i}()) }};"
            )
        })
        .collect();
    writeln!(
        m.0,
        "    public fun compile_case(i: u64): (vector<u8>, u64, u8, bool, vector<vector<u8>>, vector<u8>, u128) {{\n        {}\n        abort 0\n    }}",
        arms.join("\n        ")
    )
    .unwrap();

    // --- Council verification as a transition ---------------------------------

    let council_before = genesis().get(&keys::council()).unwrap().to_vec();
    let gov = Transaction::decode(
        &cases
            .iter()
            .find(|c| c.name == "governance_set_jwk")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let program = compile(&gov, &devnet_ctx(&devnet)).unwrap();
    emit_transitions(&mut m, &split);
    let verify = program
        .iter()
        .find(|i| matches!(i, Instruction::VerifyCouncil { .. }))
        .unwrap();
    let council_after = sena_stf::transition(verify, Some(&council_before)).unwrap();
    m.bytes("council_before", &council_before);
    m.bytes("council_after", &council_after);
    m.bytes("council_instruction", &verify.encode());
    m.hash("council_slot", &verify.slot());

    let mut out = String::from(
        "// GENERATED by crates/sena-fraudproof/tests/move_vectors.rs. Do not edit by hand.\n\
         // Regenerate: SENA_WRITE_MOVE_VECTORS=1 cargo test -p sena-fraudproof --test move_vectors\n\
         #[test_only]\nmodule sena::vectors {\n",
    );
    out.push_str(&m.0);
    out.push_str("}\n");
    out
}

/// One step's semantics against concrete slot contents.
struct TransitionCase {
    name: &'static str,
    instruction: Instruction,
    current: Option<Vec<u8>>,
}

/// Emits every fee-related transition the Move one-step verifier must agree
/// on, as `(instruction, present, current, ok, updated)`.
fn emit_transitions(m: &mut Module, split: &FeeSplit) {
    let market = |base_fee, window_ts, window_gas| {
        FeeMarket {
            base_fee,
            floor: DEFAULT_BASE_FEE_FLOOR,
            target: 1_000_000,
            window_ts,
            window_gas,
        }
        .encode()
    };
    let charge = |timestamp, base_fee, gas| Instruction::ChargeBaseFee {
        timestamp,
        base_fee,
        gas,
    };
    let floor = DEFAULT_BASE_FEE_FLOOR;
    let asset = |intrinsic_gas, enabled| {
        WhitelistedAsset {
            asset: USDC,
            symbol: "USDC".into(),
            rate: RATE_SCALE,
            intrinsic_gas,
            enabled,
        }
        .encode()
    };
    let council = |guardian_threshold| {
        Council {
            members: council_members()
                .iter()
                .map(|k| k.verifying_key().to_bytes())
                .collect(),
            threshold: 2,
            epoch: 4,
            guardian_threshold,
        }
        .encode()
    };
    let disable = GovernanceUpdate::DisableGasAsset { asset: USDC };
    let digest = disable.signing_digest(4);
    let one = vec![CouncilSignature {
        index: 0,
        signature: council_members()[0].sign(digest.as_bytes()).to_bytes(),
    }];
    let guardian = |guardian| Instruction::VerifyCouncil {
        epoch: 4,
        digest,
        signatures: one.clone(),
        guardian,
    };
    let cases = vec![
        TransitionCase {
            name: "charge_same_window",
            instruction: charge(10, 3 * floor, 7),
            current: Some(market(3 * floor, 10, 5)),
        },
        TransitionCase {
            name: "charge_rolls_up",
            instruction: charge(11, 3 * floor + 3 * floor / 8, 1),
            current: Some(market(3 * floor, 10, 2_000_000)),
        },
        TransitionCase {
            name: "charge_rolls_partway_up",
            instruction: charge(11, 3 * floor + 3 * floor / 16, 1),
            current: Some(market(3 * floor, 10, 1_500_000)),
        },
        TransitionCase {
            name: "charge_rolls_down",
            instruction: charge(12, 3 * floor - 3 * floor / 8, 1),
            current: Some(market(3 * floor, 10, 0)),
        },
        TransitionCase {
            name: "charge_floors",
            instruction: charge(12, floor, 1),
            current: Some(market(floor + 1, 10, 0)),
        },
        TransitionCase {
            name: "charge_mismatch",
            instruction: charge(11, 3 * floor, 1),
            current: Some(market(3 * floor, 10, 2_000_000)),
        },
        TransitionCase {
            name: "charge_window_full",
            instruction: charge(10, floor, 2),
            current: Some(market(floor, 10, 1_999_999)),
        },
        TransitionCase {
            name: "charge_fills_window",
            instruction: charge(10, floor, 1),
            current: Some(market(floor, 10, 1_999_999)),
        },
        TransitionCase {
            name: "charge_regressed",
            instruction: charge(9, floor, 1),
            current: Some(market(floor, 10, 0)),
        },
        TransitionCase {
            name: "charge_genesis_market",
            instruction: charge(TIMESTAMP, floor, 21_000),
            current: None,
        },
        TransitionCase {
            name: "set_fee_market_absent",
            instruction: Instruction::SetFeeMarket {
                floor: 2 * floor,
                target: 9,
            },
            current: None,
        },
        TransitionCase {
            name: "set_fee_market_keeps_window",
            instruction: Instruction::SetFeeMarket {
                floor: floor / 2,
                target: 9,
            },
            current: Some(market(3 * floor, 10, 77)),
        },
        TransitionCase {
            name: "set_fee_market_zero",
            instruction: Instruction::SetFeeMarket {
                floor: 0,
                target: 9,
            },
            current: None,
        },
        TransitionCase {
            name: "verify_asset_ok",
            instruction: Instruction::VerifyGasAsset {
                asset: USDC,
                rate: RATE_SCALE,
                intrinsic_gas: 10_000,
            },
            current: Some(asset(10_000, true)),
        },
        TransitionCase {
            name: "verify_asset_intrinsic_mismatch",
            instruction: Instruction::VerifyGasAsset {
                asset: USDC,
                rate: RATE_SCALE,
                intrinsic_gas: 9_999,
            },
            current: Some(asset(10_000, true)),
        },
        TransitionCase {
            name: "verify_asset_disabled",
            instruction: Instruction::VerifyGasAsset {
                asset: USDC,
                rate: RATE_SCALE,
                intrinsic_gas: 10_000,
            },
            current: Some(asset(10_000, false)),
        },
        TransitionCase {
            name: "disable_asset",
            instruction: Instruction::DisableGasAsset { asset: USDC },
            current: Some(asset(10_000, true)),
        },
        TransitionCase {
            name: "disable_absent_asset",
            instruction: Instruction::DisableGasAsset { asset: USDC },
            current: None,
        },
        TransitionCase {
            name: "verify_split_ok",
            instruction: Instruction::VerifyFeeSplit {
                split: split.clone(),
            },
            current: Some(split.encode()),
        },
        TransitionCase {
            name: "verify_split_absent",
            instruction: Instruction::VerifyFeeSplit {
                split: split.clone(),
            },
            current: None,
        },
        TransitionCase {
            name: "verify_split_other",
            instruction: Instruction::VerifyFeeSplit {
                split: FeeSplit {
                    beneficiaries: vec![],
                    burn: 1_000_000,
                },
            },
            current: Some(split.encode()),
        },
        TransitionCase {
            name: "set_split",
            instruction: Instruction::SetFeeSplit {
                split: split.clone(),
            },
            current: None,
        },
        TransitionCase {
            name: "set_split_invalid",
            instruction: Instruction::SetFeeSplit {
                split: FeeSplit::default(),
            },
            current: None,
        },
        TransitionCase {
            name: "guardian_signs_alone",
            instruction: guardian(true),
            current: Some(council(1)),
        },
        TransitionCase {
            name: "guardian_without_fast_path",
            instruction: guardian(true),
            current: Some(council(0)),
        },
        TransitionCase {
            name: "one_signature_for_council",
            instruction: guardian(false),
            current: Some(council(1)),
        },
    ];
    m.u64("transition_case_count", cases.len() as u64);
    for (i, case) in cases.iter().enumerate() {
        let result = sena_stf::transition(&case.instruction, case.current.as_deref());
        writeln!(m.0, "    // transition {i}: {}", case.name).unwrap();
        m.bytes(
            &format!("transition_instruction_{i}"),
            &case.instruction.encode(),
        );
        m.boolean(&format!("transition_present_{i}"), case.current.is_some());
        m.bytes(
            &format!("transition_current_{i}"),
            case.current.as_deref().unwrap_or(&[]),
        );
        m.boolean(&format!("transition_ok_{i}"), result.is_ok());
        m.bytes(
            &format!("transition_updated_{i}"),
            result.as_deref().unwrap_or(&[]),
        );
        m.hash(&format!("transition_slot_{i}"), &case.instruction.slot());
    }
    let arms: Vec<String> = (0..cases.len())
        .map(|i| {
            format!(
                "if (i == {i}) {{ return (transition_instruction_{i}(), transition_present_{i}(), \
                 transition_current_{i}(), transition_ok_{i}(), transition_updated_{i}(), transition_slot_{i}()) }};"
            )
        })
        .collect();
    writeln!(
        m.0,
        "    public fun transition_case(i: u64): (vector<u8>, bool, vector<u8>, bool, vector<u8>, vector<u8>) {{\n        {}\n        abort 0\n    }}",
        arms.join("\n        ")
    )
    .unwrap();
    let _ = DEFAULT_ASSET_INTRINSIC_GAS;
}

#[test]
fn move_vectors_are_current() {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "move",
        "sena",
        "tests",
        "vectors.move",
    ]
    .iter()
    .collect();
    let generated = generate();
    if std::env::var_os("SENA_WRITE_MOVE_VECTORS").is_some() {
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        current == generated,
        "move/sena/tests/vectors.move is stale; regenerate with \
         SENA_WRITE_MOVE_VECTORS=1 cargo test -p sena-fraudproof --test move_vectors"
    );
}

#[test]
fn the_rust_dispute_model_agrees_with_itself() {
    // Sanity for the generator: the fraud game ends on the forged step, and the
    // honest game ends where the honest witness reproduces the defender.
    let devnet = KeylessConfig::aptos_devnet_insecure();
    let alice = key(1);
    let txs = vec![
        transfer(&alice, 0, addr(&key(2)), 1_000),
        keyless_transfer(addr(&key(2)), 1_234),
    ];
    let pre = genesis();
    let honest = execute_batch(&mut pre.clone(), &devnet_ctx(&devnet), &txs).unwrap();
    let at = usize::try_from(honest.tx_starts[1]).unwrap() + 6;
    let Instruction::Credit {
        account,
        asset,
        amount,
    } = honest.instructions[at]
    else {
        panic!()
    };
    let forged = forged_trace(
        &pre,
        &honest,
        at,
        &Instruction::Credit {
            account,
            asset,
            amount: amount + 1,
        },
    );
    let (_, _, d) = play(
        &TracePlayer::new(forged, pre.clone()),
        &TracePlayer::new(honest.clone(), pre.clone()),
        honest.len() as u64,
    );
    assert_eq!(d.disputed_step(), Some(at as u64));
    let _ = KeylessSignature::address(&aptos_sample::signature());
}
