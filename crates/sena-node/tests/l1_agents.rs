//! The relayer and the watcher against an in-memory model of the SENA
//! contracts on Aptos.
//!
//! The model keeps the parts of `sena::assertions` and `sena::disputes` the
//! agents depend on — ids, statuses, batch data, the challenge window, the
//! bisection interval and whose turn it is — and records every transaction.
//! It does not adjudicate one-step proofs (the Move tests and the localnet
//! dispute do that); here the question is whether the agents, driven by a real
//! sequencer, make the right moves with the right arguments.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_fraudproof::bisection::{self, DEFAULT_ARITY};
use sena_fraudproof::{AssertionChain, PartyId};
use sena_node::genesis::{Allocation, GenesisConfig};
use sena_node::l1::{self, Arg, DisputeState, L1Error, PublishedBatch, L1};
use sena_node::relayer::{L2Block, RelayError};
use sena_node::{
    handle, L2Source, Relayer, RelayerConfig, Request, Response, Sequencer, WatchError, Watcher,
    WatcherConfig,
};
use sena_primitives::{AssetId, Hash256, L2Address};
use sena_state::MerkleTrie;
use sena_stf::batch::{header_commitment, BatchTree};
use sena_stf::{Authenticator, Payload, Transaction};
use serde_json::{json, Value};

const USDC: AssetId = AssetId(1);
const WINDOW: u64 = 86_400;
const BOND: u128 = 1_000_000;
const PROPOSER: &str = "0xa11ce";
const CHALLENGER: &str = "0xb0b";

// --- The model of L1 ------------------------------------------------------------

#[derive(Clone, Debug)]
struct Record {
    parent: Vec<u8>,
    proposer: String,
    pre: Hash256,
    post: Hash256,
    timestamp: u64,
    tx_count: u64,
    tx_root: Hash256,
    trace_length: u64,
    posted_at: u64,
    status: u8,
}

#[derive(Default, Debug)]
struct Chain {
    now: u64,
    records: BTreeMap<Vec<u8>, Record>,
    order: Vec<Vec<u8>>,
    batches: BTreeMap<Vec<u8>, PublishedBatch>,
    challengers: BTreeMap<Vec<u8>, Vec<String>>,
    disputes: BTreeMap<Vec<u8>, DisputeState>,
    /// Every successful transaction: (sender, function, arguments).
    log: Vec<(String, String, Vec<Arg>)>,
    /// Make the next submission of this function fail in transport.
    fail_next: Option<String>,
}

impl Chain {
    fn new(genesis_root: Hash256) -> Self {
        let id = l1::genesis_id(genesis_root).to_vec();
        let mut chain = Self {
            now: 1_000,
            ..Self::default()
        };
        chain.records.insert(
            id.clone(),
            Record {
                parent: vec![0; 32],
                proposer: "0x0".into(),
                pre: Hash256::ZERO,
                post: genesis_root,
                timestamp: 0,
                tx_count: 0,
                tx_root: Hash256::ZERO,
                trace_length: 0,
                posted_at: 0,
                status: l1::status::FINALIZED,
            },
        );
        chain.order.push(id);
        chain
    }

    fn calls(&self, function: &str) -> Vec<&(String, String, Vec<Arg>)> {
        self.log.iter().filter(|(_, f, _)| f == function).collect()
    }
}

#[derive(Clone)]
struct MockL1 {
    chain: Rc<RefCell<Chain>>,
    me: String,
}

fn bytes(a: &Arg) -> Vec<u8> {
    match a {
        Arg::Bytes(b) => b.clone(),
        other => panic!("expected bytes, got {other:?}"),
    }
}

fn hash(a: &Arg) -> Hash256 {
    Hash256(bytes(a).try_into().expect("32 bytes"))
}

fn num(a: &Arg) -> u64 {
    match a {
        Arg::U64(v) => *v,
        other => panic!("expected u64, got {other:?}"),
    }
}

fn abort(function: &str, code: u64) -> L1Error {
    L1Error::Rejected {
        function: function.to_owned(),
        status: format!("Move abort in 0xc0::module: E_SOMETHING(0x{code:x}): test"),
    }
}

impl L1 for MockL1 {
    #[allow(clippy::too_many_lines)]
    fn submit(&self, function: &str, args: &[Arg]) -> Result<u64, L1Error> {
        let mut c = self.chain.borrow_mut();
        if c.fail_next.as_deref() == Some(function) {
            c.fail_next = None;
            return Err(L1Error::Transport("connection reset".into()));
        }
        let now = c.now;
        match function {
            "assertions::post" => {
                let parent = bytes(&args[1]);
                let (pre, post) = (hash(&args[2]), hash(&args[3]));
                let timestamp = num(&args[4]);
                let Arg::U128(base_fee) = args[5] else {
                    panic!()
                };
                let fee_recipient = L2Address::from_bytes(bytes(&args[6]).try_into().unwrap());
                let Arg::BytesList(txs) = &args[7] else {
                    panic!()
                };
                let Arg::U64List(starts) = &args[8] else {
                    panic!()
                };
                let trace_length = num(&args[9]);
                let Some(p) = c.records.get(&parent) else {
                    return Err(abort(function, 32));
                };
                if p.post != pre {
                    return Err(abort(function, 34));
                }
                let leaves: Vec<(u64, Vec<u8>)> =
                    starts.iter().copied().zip(txs.iter().cloned()).collect();
                let tree = BatchTree::build(&leaves);
                let commitment = header_commitment(
                    timestamp,
                    base_fee,
                    &fee_recipient,
                    tree.tx_count(),
                    &tree.root(),
                );
                let id = l1::assertion_id(
                    &parent.clone().try_into().unwrap(),
                    pre,
                    post,
                    commitment,
                    trace_length,
                    BOND,
                )
                .to_vec();
                // `table::add` aborts on a duplicate key.
                if c.records.contains_key(&id) {
                    return Err(abort(function, 0x6_4000));
                }
                c.records.insert(
                    id.clone(),
                    Record {
                        parent,
                        proposer: self.me.clone(),
                        pre,
                        post,
                        timestamp,
                        tx_count: txs.len() as u64,
                        tx_root: tree.root(),
                        trace_length,
                        posted_at: now,
                        status: l1::status::PENDING,
                    },
                );
                c.order.push(id.clone());
                c.batches.insert(
                    id.clone(),
                    PublishedBatch {
                        assertion: id,
                        timestamp,
                        base_fee,
                        fee_recipient,
                        tx_bytes: txs.clone(),
                        tx_starts: starts.clone(),
                    },
                );
            }
            "assertions::open_challenge" => {
                let id = bytes(&args[1]);
                let list = c.challengers.entry(id.clone()).or_default();
                if list.contains(&self.me) {
                    return Err(abort(function, 62));
                }
                list.push(self.me.clone());
                c.records.get_mut(&id).unwrap().status = l1::status::CHALLENGED;
            }
            "assertions::finalize" => {
                let id = bytes(&args[1]);
                let r = c.records[&id].clone();
                if r.posted_at + WINDOW > now {
                    return Err(abort(function, 37));
                }
                if c.records[&r.parent].status != l1::status::FINALIZED {
                    return Err(abort(function, 38));
                }
                c.records.get_mut(&id).unwrap().status = l1::status::FINALIZED;
            }
            "disputes::open" => {
                let id = bytes(&args[1]);
                let did = l1::dispute_id(&id, &self.me);
                assert!(!c.disputes.contains_key(&did), "dispute opened twice");
                let trace_length = c.records[&id].trace_length;
                c.disputes.insert(
                    did,
                    DisputeState {
                        exists: true,
                        stage: u8::from(trace_length == 1),
                        turn: u8::from(trace_length == 1),
                        lo: 0,
                        hi: trace_length,
                        has_offer: false,
                        offered: Vec::new(),
                        deadline: now + 3_600,
                    },
                );
            }
            "disputes::dissect" => {
                let d = c.disputes.get_mut(&bytes(&args[1])).unwrap();
                assert_eq!(
                    (d.stage, d.turn, d.has_offer),
                    (0, 0, false),
                    "dissect out of turn"
                );
                let Arg::BytesList(list) = &args[2] else {
                    panic!()
                };
                let expected = bisection::boundaries(d.lo, d.hi, DEFAULT_ARITY).len() - 2;
                assert_eq!(list.len(), expected, "wrong dissection width");
                d.offered = list
                    .iter()
                    .map(|b| Hash256(b.clone().try_into().unwrap()))
                    .collect();
                d.has_offer = true;
                d.turn = 1;
                d.deadline = now + 3_600;
            }
            "disputes::select" => {
                let d = c.disputes.get_mut(&bytes(&args[1])).unwrap();
                assert_eq!(
                    (d.stage, d.turn, d.has_offer),
                    (0, 1, true),
                    "select out of turn"
                );
                let i = usize::try_from(num(&args[2])).unwrap();
                let bounds = bisection::boundaries(d.lo, d.hi, DEFAULT_ARITY);
                d.lo = bounds[i];
                d.hi = bounds[i + 1];
                d.has_offer = false;
                d.offered.clear();
                if d.hi - d.lo == 1 {
                    d.stage = 1;
                    d.turn = 1;
                } else {
                    d.turn = 0;
                }
                d.deadline = now + 3_600;
            }
            "disputes::one_step" => {
                let did = bytes(&args[1]);
                let d = c.disputes.get_mut(&did).unwrap();
                assert_eq!(
                    d.stage, 1,
                    "one-step proof before the game narrowed to one step"
                );
                d.stage = 2;
                let id = did[..32].to_vec();
                c.records.get_mut(&id).unwrap().status = l1::status::REJECTED;
            }
            "disputes::prove_uncompilable"
            | "disputes::prove_start_gap"
            | "disputes::prove_trace_length" => {
                let id = bytes(&args[1]);
                assert!(
                    c.challengers[&id].contains(&self.me),
                    "structural proof without a challenge"
                );
                c.records.get_mut(&id).unwrap().status = l1::status::REJECTED;
            }
            "disputes::claim_timeout" => {}
            other => panic!("unexpected entry function {other}"),
        }
        c.log
            .push((self.me.clone(), function.to_owned(), args.to_vec()));
        Ok(1)
    }

    fn view(&self, function: &str, args: &[Arg]) -> Result<Vec<Value>, L1Error> {
        let c = self.chain.borrow();
        let hx = |b: &[u8]| json!(format!("0x{}", hex::encode(b)));
        Ok(match function {
            "assertions::record" => {
                let Some(r) = c.records.get(&bytes(&args[1])) else {
                    return Err(abort(function, 31));
                };
                vec![
                    hx(&r.parent),
                    json!(r.proposer),
                    hx(r.pre.as_bytes()),
                    hx(r.post.as_bytes()),
                    json!(r.timestamp.to_string()),
                    json!(r.tx_count.to_string()),
                    hx(r.tx_root.as_bytes()),
                    json!(r.trace_length.to_string()),
                    json!(BOND.to_string()),
                    json!(r.posted_at.to_string()),
                    json!(r.status),
                ]
            }
            "assertions::assertion_count" => vec![json!(c.order.len().to_string())],
            "assertions::assertion_at" => {
                vec![hx(&c.order[usize::try_from(num(&args[1])).unwrap()])]
            }
            "assertions::challengers" => {
                vec![json!(c
                    .challengers
                    .get(&bytes(&args[1]))
                    .cloned()
                    .unwrap_or_default())]
            }
            "assertions::challenge_window" => vec![json!(WINDOW.to_string())],
            "disputes::keyless_setup" => vec![json!(0)],
            "disputes::dispute_state" => {
                let d = c
                    .disputes
                    .get(&bytes(&args[1]))
                    .cloned()
                    .unwrap_or(DisputeState {
                        exists: false,
                        stage: 0,
                        turn: 0,
                        lo: 0,
                        hi: 0,
                        has_offer: false,
                        offered: Vec::new(),
                        deadline: 0,
                    });
                vec![
                    json!(d.exists),
                    json!(d.stage),
                    json!(d.turn),
                    json!(d.lo.to_string()),
                    json!(d.hi.to_string()),
                    json!(d.has_offer),
                    json!(d
                        .offered
                        .iter()
                        .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                        .collect::<Vec<_>>()),
                    json!(d.deadline.to_string()),
                ]
            }
            other => panic!("unexpected view {other}"),
        })
    }

    fn now(&self) -> Result<u64, L1Error> {
        Ok(self.chain.borrow().now)
    }

    fn published_batch(
        &self,
        proposer: &str,
        assertion: &[u8],
    ) -> Result<Option<PublishedBatch>, L1Error> {
        let c = self.chain.borrow();
        Ok(c.batches
            .get(assertion)
            .filter(|_| c.records[assertion].proposer == proposer)
            .cloned())
    }

    fn address(&self) -> String {
        self.me.clone()
    }

    fn contract(&self) -> String {
        "0xc0".into()
    }
}

// --- L2 -------------------------------------------------------------------------

/// Rewrites the block at a height before the relayer sees it.
type Forgery = (u64, Box<dyn Fn(&mut L2Block)>);

/// A sequencer, served the way `RpcSource` would see it, optionally lying
/// about one block.
struct Node {
    sequencer: Rc<RefCell<Sequencer>>,
    forge: Option<Forgery>,
}

impl L2Source for Node {
    fn block(&self, height: u64) -> Result<Option<L2Block>, String> {
        let response = handle(
            &mut self.sequencer.borrow_mut(),
            "test",
            Request::GetBlock { height },
        );
        let mut block = match response {
            Response::Block {
                height,
                timestamp,
                base_fee,
                fee_recipient,
                pre_state_root,
                post_state_root,
                transactions,
                trace_length,
                tx_starts,
                ..
            } => L2Block {
                height,
                timestamp,
                base_fee,
                fee_recipient,
                pre_state_root,
                post_state_root,
                tx_bytes: transactions.iter().map(Transaction::encode).collect(),
                tx_starts,
                trace_length,
            },
            Response::Error { .. } => return Ok(None),
            other => return Err(format!("{other:?}")),
        };
        if let Some((h, f)) = &self.forge {
            if *h == height {
                f(&mut block);
            }
        }
        Ok(Some(block))
    }

    fn commitments(&self, height: u64, steps: &[u64]) -> Result<Vec<Hash256>, String> {
        match handle(
            &mut self.sequencer.borrow_mut(),
            "test",
            Request::GetTraceCommitments {
                height,
                steps: steps.to_vec(),
            },
        ) {
            Response::TraceCommitments { commitments } => Ok(commitments),
            other => Err(format!("{other:?}")),
        }
    }
}

fn key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}

fn address_of(key: &SigningKey) -> L2Address {
    L2Address::from_bytes(key.verifying_key().to_bytes())
}

fn transfer(from: &SigningKey, nonce: u64, to: L2Address, amount: u128) -> Transaction {
    let mut tx = Transaction {
        sender: address_of(from),
        nonce,
        fee_asset: USDC,
        fee_rate: 0,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload: Payload::Transfer {
            to,
            asset: USDC,
            amount,
        },
        authenticator: Authenticator::Ed25519 {
            public_key: from.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    sena_stf::gas::fill_default_fees(&mut tx);
    let signature = from.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: from.verifying_key().to_bytes(),
        signature,
    };
    tx
}

fn clock() -> u64 {
    1_000
}

struct World {
    chain: Rc<RefCell<Chain>>,
    sequencer: Rc<RefCell<Sequencer>>,
    genesis: MerkleTrie,
    dir: PathBuf,
}

impl World {
    /// A chain with two blocks of transfers.
    fn new(name: &str) -> Self {
        let alice = key(1);
        let bob = address_of(&key(2));
        let config = GenesisConfig::dev(vec![Allocation {
            address: address_of(&alice),
            asset: 1,
            amount: 1_000_000_000,
        }]);
        let genesis = config.build_state().unwrap();
        let chain = AssertionChain::new(genesis.root(), WINDOW, BOND);
        let mut sequencer =
            Sequencer::new(genesis.clone(), chain, PartyId(1), BOND).with_clock(clock);
        for (nonce, amount) in [(0, 10), (1, 20)] {
            sequencer
                .submit(transfer(&alice, nonce, bob, amount))
                .unwrap();
        }
        sequencer.produce(16).unwrap().unwrap();
        for (nonce, amount) in [(2, 30), (3, 40), (4, 50)] {
            sequencer
                .submit(transfer(&alice, nonce, bob, amount))
                .unwrap();
        }
        sequencer.produce(16).unwrap().unwrap();

        let dir =
            std::env::temp_dir().join(format!("sena-l1-agents-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            chain: Rc::new(RefCell::new(Chain::new(genesis.root()))),
            sequencer: Rc::new(RefCell::new(sequencer)),
            genesis,
            dir,
        }
    }

    fn l1(&self, who: &str) -> MockL1 {
        MockL1 {
            chain: Rc::clone(&self.chain),
            me: who.into(),
        }
    }

    fn relayer(&self, forge: Option<Forgery>) -> Relayer<MockL1, Node> {
        let node = Node {
            sequencer: Rc::clone(&self.sequencer),
            forge,
        };
        let config = RelayerConfig {
            bond: BOND,
            state_path: self.dir.join("relayer.json"),
        };
        Relayer::new(self.l1(PROPOSER), node, config).unwrap()
    }

    fn watcher(&self) -> Watcher<MockL1> {
        let config = WatcherConfig {
            bond: BOND,
            state_path: self.dir.join("watcher.json"),
            keyless: None,
            keyless_setup: 0,
            keyless_steps_per_tx: 12,
        };
        Watcher::new(self.l1(CHALLENGER), config, self.genesis.clone()).unwrap()
    }

    fn status(&self, index: usize) -> u8 {
        let c = self.chain.borrow();
        c.records[&c.order[index]].status
    }
}

// --- Tests ----------------------------------------------------------------------

#[test]
fn an_honest_chain_is_posted_verified_and_finalized() {
    let world = World::new("honest");
    let mut relayer = world.relayer(None);
    let mut watcher = world.watcher();

    assert_eq!(relayer.step().unwrap().posted, vec![1, 2]);
    let report = watcher.step().unwrap();
    assert_eq!(report.verified, 2);
    assert!(report.challenged.is_empty());
    assert!(world
        .chain
        .borrow()
        .calls("assertions::open_challenge")
        .is_empty());

    // Nothing finalizes inside the window, and asking early is not an error.
    assert!(relayer.step().unwrap().finalized.is_empty());
    world.chain.borrow_mut().now += WINDOW;
    assert_eq!(relayer.step().unwrap().finalized, vec![1, 2]);
    assert_eq!(world.status(2), l1::status::FINALIZED);

    // Both resume from their state files without redoing anything.
    let before = world.chain.borrow().log.len();
    world.relayer(None).step().unwrap();
    assert_eq!(world.watcher().step().unwrap().verified, 0);
    assert_eq!(world.chain.borrow().log.len(), before);
}

#[test]
fn a_relayer_that_lost_its_state_does_not_post_twice() {
    let world = World::new("lost-state");
    world.relayer(None).step().unwrap();
    std::fs::remove_file(world.dir.join("relayer.json")).unwrap();

    let report = world.relayer(None).step().unwrap();
    assert_eq!(report.posted, vec![1, 2], "it relearns what it posted");
    assert_eq!(
        world.chain.borrow().calls("assertions::post").len(),
        2,
        "without posting again"
    );
}

#[test]
fn a_forged_post_state_is_bisected_to_one_step_and_rejected() {
    let world = World::new("forged");
    let forged = Hash256([0x66; 32]);
    let mut relayer = world.relayer(Some((2, Box::new(move |b| b.post_state_root = forged))));
    let mut watcher = world.watcher();

    relayer.step().unwrap();
    let report = watcher.step().unwrap();
    assert_eq!(report.verified, 1, "block 1 is honest");
    assert_eq!(report.challenged.len(), 1);
    assert_eq!(report.challenged[0].1, "bisection");

    // Play the game out: the relayer dissects, the watcher selects, until one
    // step remains and the watcher proves it.
    let mut rejected = false;
    for _ in 0..64 {
        match relayer.step() {
            Err(RelayError::Rejected(2)) => {
                rejected = true;
                break;
            }
            other => {
                other.unwrap();
            }
        }
        watcher.step().unwrap();
    }
    assert!(
        rejected,
        "the relayer learns its assertion was rejected and halts"
    );
    assert_eq!(world.status(2), l1::status::REJECTED);

    // The one-step proof is for the last step (the only one the forger lied
    // about), from the leaf that covers it, with the honest pre-state.
    let c = world.chain.borrow();
    let steps = c.calls("disputes::one_step");
    assert_eq!(steps.len(), 1);
    let args = &steps[0].2;
    let block = world.sequencer.borrow().blocks[1].clone();
    let last = block.trace.len() as u64 - 1;
    let leaf = block
        .trace
        .tx_starts
        .iter()
        .rposition(|s| *s <= last)
        .unwrap() as u64;
    assert_eq!(num(&args[2]), leaf, "leaf index");
    assert_eq!(
        num(&args[3]),
        block.trace.tx_starts[usize::try_from(leaf).unwrap()],
        "leaf start"
    );
    assert_eq!(
        bytes(&args[4]),
        block.transactions[usize::try_from(leaf).unwrap()].encode(),
        "leaf bytes"
    );
    let honest_pre = handle(
        &mut world.sequencer.borrow_mut(),
        "test",
        Request::GetTraceCommitments {
            height: 2,
            steps: vec![last],
        },
    );
    let Response::TraceCommitments { commitments } = honest_pre else {
        panic!()
    };
    let pre_root = hash(&args[6]);
    assert_eq!(
        sena_stf::MachineState {
            state_root: pre_root,
            pc: last
        }
        .commitment(),
        commitments[0],
        "the witness starts from the honest state before the disputed step"
    );
}

#[test]
fn an_uncompilable_transaction_is_proven_without_a_game() {
    let world = World::new("uncompilable");
    let mut relayer = world.relayer(Some((
        1,
        Box::new(|b| {
            b.tx_bytes.push(vec![0xff; 40]);
            b.tx_starts.push(b.trace_length);
        }),
    )));
    let mut watcher = world.watcher();
    relayer.step().unwrap();

    let report = watcher.step().unwrap();
    assert_eq!(report.challenged.len(), 1);
    assert_eq!(report.challenged[0].1, "uncompilable transaction");
    let c = world.chain.borrow();
    let proofs = c.calls("disputes::prove_uncompilable");
    assert_eq!(proofs.len(), 1);
    assert_eq!(
        num(&proofs[0].2[2]),
        2,
        "the third transaction is the bad one"
    );
    assert!(c.calls("disputes::open").is_empty());
    drop(c);
    assert_eq!(world.status(1), l1::status::REJECTED);
    // Block 2 built on a rejected parent is never adopted.
    assert_eq!(
        watcher.state().head,
        hex::encode(&world.chain.borrow().order[0])
    );
}

#[test]
fn a_challenge_interrupted_part_way_resumes() {
    let world = World::new("interrupted");
    let forged = Hash256([0x66; 32]);
    world
        .relayer(Some((2, Box::new(move |b| b.post_state_root = forged))))
        .step()
        .unwrap();
    let mut watcher = world.watcher();

    world.chain.borrow_mut().fail_next = Some("disputes::open".into());
    assert!(matches!(
        watcher.step(),
        Err(WatchError::L1(L1Error::Transport(_)))
    ));
    let report = watcher.step().unwrap();
    assert_eq!(
        report.challenged.len(),
        1,
        "the retry finishes the challenge"
    );
    let c = world.chain.borrow();
    assert_eq!(
        c.calls("assertions::open_challenge").len(),
        1,
        "without challenging twice"
    );
    assert_eq!(c.calls("disputes::open").len(), 1);
}

#[test]
fn a_watcher_refuses_a_chain_with_another_genesis() {
    let world = World::new("genesis");
    let config = WatcherConfig {
        bond: BOND,
        state_path: world.dir.join("other.json"),
        keyless: None,
        keyless_setup: 0,
        keyless_steps_per_tx: 12,
    };
    let other = MerkleTrie::new();
    assert!(matches!(
        Watcher::new(world.l1(CHALLENGER), config, other),
        Err(WatchError::Misconfigured(_))
    ));
}
