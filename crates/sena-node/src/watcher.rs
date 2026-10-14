//! The independent verifier: watch L1, re-execute, challenge fraud.
//!
//! "An invalid state root cannot finalize while one honest verifier is
//! watching" is only true if someone actually watches. The [`Watcher`] does,
//! trusting nothing but Aptos and its own genesis file:
//!
//! - it reads every assertion from the L1 chain and the batch data the
//!   assertion published there, never from the sequencer;
//! - it re-executes each batch on its own replica of L2 state;
//! - when an assertion is wrong it picks the cheapest valid evidence — a
//!   batch-structure proof for an uncompilable transaction or bad start
//!   positions or trace length, otherwise a bisection game — and plays it to
//!   the end, computing keyless verdicts on L1 when the disputed step needs
//!   one.
//!
//! Its replica only ever advances along assertions it has verified, so a
//! rejected assertion and everything built on it are simply never adopted.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sena_fraudproof::bisection::{self, DEFAULT_ARITY};
use sena_primitives::{CanonicalEncoder, Hash256};
use sena_state::{MerkleTrie, Terminal};
use sena_stf::batch::BatchTree;
use sena_stf::{
    apply, compile, Authenticator, BatchContext, Instruction, KeylessConfig, MachineState,
    Transaction,
};
use serde::{Deserialize, Serialize};

use crate::l1::{self, status, Arg, L1Error, L1};

/// Steps in L1's resumable Poseidon schedule (`sena::poseidon::steps`).
const POSEIDON_STEPS: u64 = 69;

/// Watcher settings.
#[derive(Clone, Debug)]
pub struct WatcherConfig {
    /// The bond posted with each challenge.
    pub bond: u128,
    /// Where progress is persisted.
    pub state_path: PathBuf,
    /// The network's keyless parameters, as the genesis file names them.
    pub keyless: Option<Arc<KeylessConfig>>,
    /// The same parameters as an L1 setup id (`sena::keyless`).
    pub keyless_setup: u8,
    /// Poseidon steps per keyless-job transaction.
    pub keyless_steps_per_tx: u64,
}

/// What the watcher persists.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct WatcherState {
    /// Next index into the L1 assertion order to examine.
    pub cursor: u64,
    /// The last assertion verified, hex; the replica holds its post-state.
    pub head: String,
    /// The replica, `MerkleTrie::to_bytes`, hex.
    pub replica: String,
    /// Bisection games in progress.
    pub games: Vec<Game>,
}

/// A bisection game the watcher is playing.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Game {
    /// The disputed assertion, hex.
    pub assertion: String,
    /// The state the disputed batch starts from, `MerkleTrie::to_bytes`,
    /// hex. Kept per game: the replica moves on as honest siblings of the
    /// disputed assertion are verified.
    pub pre_state: String,
}

impl WatcherState {
    fn load(path: &Path) -> Result<Option<Self>, String> {
        match fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
}

/// Why a step failed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum WatchError {
    /// L1 refused or could not be reached.
    #[error("{0}")]
    L1(#[from] L1Error),
    /// Progress could not be saved or loaded.
    #[error("state: {0}")]
    State(String),
    /// This watcher's configuration is not the chain's.
    #[error("misconfigured: {0}")]
    Misconfigured(String),
    /// An assertion this watcher knows is wrong finalized before it could be
    /// challenged. L1's canonical chain now contains fraud; the watcher stops
    /// rather than adopt it. Operator action.
    #[error("assertion {0} is wrong and already final on L1; halting")]
    FinalizedFraud(String),
    /// An assertion's batch data could not be found on L1.
    #[error("batch data for assertion {0} not found on L1")]
    MissingData(String),
}

/// What one step found and did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct WatchReport {
    /// Assertions verified and adopted.
    pub verified: usize,
    /// Assertions found wrong, with the evidence used.
    pub challenged: Vec<(String, &'static str)>,
    /// Moves made in games.
    pub moves: usize,
    /// Games concluded.
    pub concluded: usize,
}

/// Our own view of a batch: every state up to the end, or up to the step
/// that cannot execute.
#[derive(Clone, Debug)]
struct Replay {
    program: Vec<Instruction>,
    states: Vec<MachineState>,
    tx_starts: Vec<u64>,
    /// The first step that cannot execute, if any.
    fails_at: Option<u64>,
    pre: MerkleTrie,
    post: MerkleTrie,
}

/// What is wrong with an assertion.
#[derive(Clone, Copy)]
enum Fault {
    /// Transaction `index` does not compile.
    Uncompilable(usize),
    /// Transaction `index` does not start where it should.
    StartGap(usize),
    /// The trace length is not where the last transaction ends.
    TraceLength,
    /// Execution diverges somewhere inside: bisect.
    Bisect,
}

impl Replay {
    fn commitment_at(&self, step: u64) -> Hash256 {
        if self.fails_at.is_some_and(|k| step > k) {
            // Past a step that cannot execute there is no honest state; any
            // claim there is one we disagree with.
            return Hash256::commit(CanonicalEncoder::new(b"SENA:v1:no-honest-state").u64(step));
        }
        usize::try_from(step)
            .ok()
            .and_then(|i| self.states.get(i))
            .map_or_else(
                || Hash256::commit(CanonicalEncoder::new(b"SENA:v1:no-honest-state").u64(step)),
                MachineState::commitment,
            )
    }
}

fn replay(pre: &MerkleTrie, txs: &[Transaction], ctx: &BatchContext<'_>) -> Result<Replay, usize> {
    let mut program = Vec::new();
    let mut tx_starts = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        tx_starts.push(program.len() as u64);
        program.extend(compile(tx, ctx).map_err(|_| i)?);
    }
    let mut trie = pre.clone();
    let mut states = vec![MachineState::start(trie.root())];
    let mut fails_at = None;
    for (k, instruction) in program.iter().enumerate() {
        let Ok(root) = apply(&mut trie, instruction) else {
            fails_at = Some(k as u64);
            break;
        };
        states.push(MachineState {
            state_root: root,
            pc: k as u64 + 1,
        });
    }
    Ok(Replay {
        program,
        states,
        tx_starts,
        fails_at,
        pre: pre.clone(),
        post: trie,
    })
}

/// The independent verifier.
#[derive(Debug)]
pub struct Watcher<C: L1> {
    l1: C,
    config: WatcherConfig,
    state: WatcherState,
    replica: MerkleTrie,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap_or_default()
}

impl<C: L1> Watcher<C> {
    /// Creates a watcher over `genesis`, resuming persisted progress.
    ///
    /// # Errors
    ///
    /// Returns [`WatchError::Misconfigured`] if L1's genesis or keyless setup
    /// is not this watcher's, or [`WatchError::State`] on a bad state file.
    pub fn new(l1: C, config: WatcherConfig, genesis: MerkleTrie) -> Result<Self, WatchError> {
        let setup = l1::u128_of(
            l1.view("disputes::keyless_setup", &[Arg::Address(l1.contract())])?
                .first()
                .ok_or_else(|| L1Error::Malformed("no keyless setup".into()))?,
        )?;
        if setup != u128::from(config.keyless_setup) {
            return Err(WatchError::Misconfigured(format!(
                "L1 runs keyless setup {setup}, this watcher {}",
                config.keyless_setup
            )));
        }
        let genesis_id = l1::assertion_at(&l1, 0)?;
        if genesis_id != l1::genesis_id(genesis.root()).to_vec() {
            return Err(WatchError::Misconfigured(
                "L1's genesis is not this genesis file's".into(),
            ));
        }
        let (state, replica) =
            match WatcherState::load(&config.state_path).map_err(WatchError::State)? {
                Some(s) => {
                    let replica = MerkleTrie::from_bytes(&unhex(&s.replica))
                        .map_err(|e| WatchError::State(e.to_string()))?;
                    (s, replica)
                }
                None => (
                    WatcherState {
                        cursor: 1,
                        head: hex::encode(genesis_id),
                        replica: hex::encode(genesis.to_bytes()),
                        games: Vec::new(),
                    },
                    genesis,
                ),
            };
        Ok(Self {
            l1,
            config,
            state,
            replica,
        })
    }

    /// The persisted state.
    #[must_use]
    pub const fn state(&self) -> &WatcherState {
        &self.state
    }

    fn save(&mut self) -> Result<(), WatchError> {
        self.state.replica = hex::encode(self.replica.to_bytes());
        self.state
            .save(&self.config.state_path)
            .map_err(WatchError::State)
    }

    fn ctx(&self, timestamp: u64) -> BatchContext<'_> {
        BatchContext {
            timestamp,
            keyless: self.config.keyless.as_deref(),
        }
    }

    fn record(&self, id: &[u8]) -> Result<l1::Record, WatchError> {
        Ok(l1::parse_record(&self.l1.view(
            "assertions::record",
            &[Arg::Address(self.l1.contract()), Arg::Bytes(id.to_vec())],
        )?)?)
    }

    /// Examines new assertions and plays open games.
    ///
    /// # Errors
    ///
    /// Returns the first [`WatchError`]; progress before it is persisted.
    pub fn step(&mut self) -> Result<WatchReport, WatchError> {
        let mut report = WatchReport::default();
        self.play(&mut report)?;
        self.examine(&mut report)?;
        Ok(report)
    }

    fn examine(&mut self, report: &mut WatchReport) -> Result<(), WatchError> {
        let count = l1::u128_of(
            self.l1
                .view(
                    "assertions::assertion_count",
                    &[Arg::Address(self.l1.contract())],
                )?
                .first()
                .ok_or_else(|| L1Error::Malformed("count".into()))?,
        )?;
        while u128::from(self.state.cursor) < count {
            let id = l1::assertion_at(&self.l1, self.state.cursor)?;
            let rec = self.record(&id)?;
            // Only assertions continuing our verified head concern us; the
            // rest build on something already rejected or not yet verified.
            if rec.parent == unhex(&self.state.head) && rec.status != status::REJECTED {
                match self.judge(&id, &rec)? {
                    None => {
                        let batch = self.batch(&id, &rec)?;
                        let txs = decode_all(&batch.tx_bytes).unwrap_or_default();
                        let r = replay(&self.replica, &txs, &self.ctx(rec.timestamp)).map_err(
                            |_| WatchError::State("a verified batch stopped replaying".into()),
                        )?;
                        self.replica = r.post;
                        self.state.head = hex::encode(&id);
                        report.verified += 1;
                    }
                    Some(_) if rec.status == status::FINALIZED => {
                        return Err(WatchError::FinalizedFraud(hex::encode(&id)));
                    }
                    Some(fault) => {
                        let evidence = self.challenge(&id, &rec, fault)?;
                        report.challenged.push((hex::encode(&id), evidence));
                    }
                }
            }
            self.state.cursor += 1;
            self.save()?;
        }
        Ok(())
    }

    fn batch(&self, id: &[u8], rec: &l1::Record) -> Result<l1::PublishedBatch, WatchError> {
        self.l1
            .published_batch(&rec.proposer, id)?
            .ok_or_else(|| WatchError::MissingData(hex::encode(id)))
    }

    /// `None` if the assertion is right, otherwise what is wrong with it.
    fn judge(&self, id: &[u8], rec: &l1::Record) -> Result<Option<Fault>, WatchError> {
        let batch = self.batch(id, rec)?;
        let txs = match decode_all(&batch.tx_bytes) {
            Ok(t) => t,
            Err(i) => return Ok(Some(Fault::Uncompilable(i))),
        };
        if rec.pre_state_root != self.replica.root() {
            return Err(WatchError::State(
                "an assertion on our head starts elsewhere".into(),
            ));
        }
        let r = match replay(&self.replica, &txs, &self.ctx(rec.timestamp)) {
            Ok(r) => r,
            Err(i) => return Ok(Some(Fault::Uncompilable(i))),
        };
        if let Some(i) = (1..r.tx_starts.len()).find(|i| r.tx_starts[*i] != batch.tx_starts[*i]) {
            return Ok(Some(Fault::StartGap(i)));
        }
        if r.fails_at.is_none() && r.program.len() as u64 != rec.trace_length {
            return Ok(Some(Fault::TraceLength));
        }
        if r.fails_at.is_some() || r.post.root() != rec.post_state_root {
            return Ok(Some(Fault::Bisect));
        }
        Ok(None)
    }

    /// `(start_pc, tx_bytes, siblings)` for leaf `i`. L1 compiles a leaf it
    /// is given unless `proof_only`, and compiling a keyless leaf needs its
    /// verdict computed first.
    fn leaf_args(
        &self,
        rec: &l1::Record,
        batch: &l1::PublishedBatch,
        i: usize,
        proof_only: bool,
    ) -> Result<Vec<Arg>, WatchError> {
        let leaves: Vec<(u64, Vec<u8>)> = batch
            .tx_starts
            .iter()
            .copied()
            .zip(batch.tx_bytes.iter().cloned())
            .collect();
        let tree = BatchTree::build(&leaves);
        if !proof_only {
            self.ensure_keyless_verdict(&batch.tx_bytes[i], rec.timestamp)?;
        }
        Ok(vec![
            Arg::U64(batch.tx_starts[i]),
            Arg::Bytes(batch.tx_bytes[i].clone()),
            Arg::BytesList(
                tree.prove(i as u64)
                    .map(|p| p.siblings.iter().map(|h| h.as_bytes().to_vec()).collect())
                    .unwrap_or_default(),
            ),
        ])
    }

    fn challenge(
        &mut self,
        id: &[u8],
        rec: &l1::Record,
        fault: Fault,
    ) -> Result<&'static str, WatchError> {
        let contract = self.l1.contract();
        // A challenge is several transactions; after a failure part-way the
        // next round starts again, so each one is skipped if it already landed.
        let me = self.l1.address();
        let challengers = self.l1.view(
            "assertions::challengers",
            &[Arg::Address(contract.clone()), Arg::Bytes(id.to_vec())],
        )?;
        let already = challengers
            .first()
            .and_then(serde_json::Value::as_array)
            .is_some_and(|l| {
                l.iter()
                    .any(|c| c.as_str().is_some_and(|c| same_address(c, &me)))
            });
        if !already {
            self.l1.submit(
                "assertions::open_challenge",
                &[
                    Arg::Address(contract.clone()),
                    Arg::Bytes(id.to_vec()),
                    Arg::U128(self.config.bond),
                ],
            )?;
        }
        let batch = self.batch(id, rec)?;
        let head = [Arg::Address(contract), Arg::Bytes(id.to_vec())];
        match fault {
            Fault::Uncompilable(i) => {
                let mut args = head.to_vec();
                args.push(Arg::U64(i as u64));
                args.extend(self.leaf_args(rec, &batch, i, false)?);
                self.l1.submit("disputes::prove_uncompilable", &args)?;
                Ok("uncompilable transaction")
            }
            Fault::StartGap(i) => {
                let mut args = head.to_vec();
                args.push(Arg::U64(i as u64 - 1));
                args.extend(self.leaf_args(rec, &batch, i - 1, false)?);
                args.extend(self.leaf_args(rec, &batch, i, true)?);
                self.l1.submit("disputes::prove_start_gap", &args)?;
                Ok("start positions")
            }
            Fault::TraceLength => {
                let mut args = head.to_vec();
                args.extend(self.leaf_args(rec, &batch, batch.tx_bytes.len() - 1, false)?);
                self.l1.submit("disputes::prove_trace_length", &args)?;
                Ok("trace length")
            }
            Fault::Bisect => {
                let did = l1::dispute_id(id, &me);
                let existing = l1::parse_dispute(&self.l1.view(
                    "disputes::dispute_state",
                    &[Arg::Address(self.l1.contract()), Arg::Bytes(did)],
                )?)?;
                if !existing.exists {
                    self.l1.submit("disputes::open", &head)?;
                }
                self.state.games.push(Game {
                    assertion: hex::encode(id),
                    pre_state: hex::encode(self.replica.to_bytes()),
                });
                self.save()?;
                Ok("bisection")
            }
        }
    }

    /// Computes a keyless leaf's verdict on L1, if it is keyless and has none.
    fn ensure_keyless_verdict(&self, tx_bytes: &[u8], timestamp: u64) -> Result<(), WatchError> {
        let Ok(tx) = Transaction::decode(tx_bytes) else {
            return Ok(());
        };
        if !matches!(tx.authenticator, Authenticator::Keyless(_)) {
            return Ok(());
        }
        let contract = self.l1.contract();
        let job = keyless_job_id(tx_bytes, timestamp, self.config.keyless_setup);
        let progress = self.l1.view(
            "keyless_jobs::progress",
            &[Arg::Address(contract.clone()), Arg::Bytes(job.to_vec())],
        );
        let (mut next, finished) = match progress {
            Ok(v) if v.len() == 2 => (
                u64::try_from(l1::u128_of(&v[0])?).unwrap_or(0),
                v[1].as_bool().unwrap_or(false),
            ),
            _ => {
                self.l1.submit(
                    "keyless_jobs::start",
                    &[
                        Arg::Address(contract.clone()),
                        Arg::Bytes(tx_bytes.to_vec()),
                        Arg::U64(timestamp),
                        Arg::U8(self.config.keyless_setup),
                    ],
                )?;
                let v = self.l1.view(
                    "keyless_jobs::progress",
                    &[Arg::Address(contract.clone()), Arg::Bytes(job.to_vec())],
                )?;
                (
                    0,
                    v.get(1)
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                )
            }
        };
        if finished {
            return Ok(());
        }
        while next < POSEIDON_STEPS {
            self.l1.submit(
                "keyless_jobs::advance",
                &[
                    Arg::Address(contract.clone()),
                    Arg::Bytes(job.to_vec()),
                    Arg::U64(self.config.keyless_steps_per_tx),
                ],
            )?;
            next = (next + self.config.keyless_steps_per_tx).min(POSEIDON_STEPS);
        }
        self.l1.submit(
            "keyless_jobs::finish",
            &[Arg::Address(contract), Arg::Bytes(job.to_vec())],
        )?;
        Ok(())
    }

    fn play(&mut self, report: &mut WatchReport) -> Result<(), WatchError> {
        let games = self.state.games.clone();
        let now = self.l1.now()?;
        for game in games {
            let id = unhex(&game.assertion);
            let rec = self.record(&id)?;
            let did = l1::dispute_id(&id, &self.l1.address());
            let d = l1::parse_dispute(&self.l1.view(
                "disputes::dispute_state",
                &[Arg::Address(self.l1.contract()), Arg::Bytes(did.clone())],
            )?)?;
            if !d.exists || d.stage == 2 || rec.status == status::REJECTED {
                self.state.games.retain(|g| *g != game);
                self.save()?;
                report.concluded += 1;
                continue;
            }
            let batch = self.batch(&id, &rec)?;
            let txs = decode_all(&batch.tx_bytes)
                .map_err(|_| WatchError::State("game over undecodable data".into()))?;
            let pre = MerkleTrie::from_bytes(&unhex(&game.pre_state))
                .map_err(|e| WatchError::State(e.to_string()))?;
            let r = replay(&pre, &txs, &self.ctx(rec.timestamp))
                .map_err(|_| WatchError::State("game over uncompilable data".into()))?;
            let contract = self.l1.contract();
            if d.turn == 1 && d.stage == 0 && d.has_offer {
                let bounds = bisection::boundaries(d.lo, d.hi, DEFAULT_ARITY);
                let index = d
                    .offered
                    .iter()
                    .enumerate()
                    .find(|(j, offered)| r.commitment_at(bounds[j + 1]) != **offered)
                    .map_or(bounds.len() - 2, |(j, _)| j);
                self.l1.submit(
                    "disputes::select",
                    &[
                        Arg::Address(contract),
                        Arg::Bytes(did),
                        Arg::U64(index as u64),
                    ],
                )?;
                report.moves += 1;
            } else if d.turn == 1 && d.stage == 1 {
                let pc = d.lo;
                let leaf = batch.tx_starts.iter().rposition(|s| *s <= pc).unwrap_or(0);
                let mut args = vec![
                    Arg::Address(contract),
                    Arg::Bytes(did),
                    Arg::U64(leaf as u64),
                ];
                args.extend(self.leaf_args(&rec, &batch, leaf, false)?);
                args.extend(one_step_witness(&r, pc));
                self.l1.submit("disputes::one_step", &args)?;
                report.moves += 1;
            } else if d.turn == 0 && now > d.deadline {
                self.l1.submit(
                    "disputes::claim_timeout",
                    &[Arg::Address(contract), Arg::Bytes(did)],
                )?;
                report.moves += 1;
            }
        }
        Ok(())
    }
}

/// Compares account addresses, tolerating leading zeros.
fn same_address(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.trim_start_matches("0x")
            .trim_start_matches('0')
            .to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

fn decode_all(bytes: &[Vec<u8>]) -> Result<Vec<Transaction>, usize> {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| Transaction::decode(b).map_err(|_| i))
        .collect()
}

/// `keyless_jobs::job_id`.
#[must_use]
pub fn keyless_job_id(tx_bytes: &[u8], timestamp: u64, setup: u8) -> [u8; 32] {
    Hash256::commit(
        CanonicalEncoder::new(b"SENA:v1:keyless-job")
            .field(tx_bytes)
            .u64(timestamp)
            .u64(u64::from(setup)),
    )
    .0
}

/// The witness arguments for `disputes::one_step` at `pc`: the pre-state root
/// and a proof of the slot the instruction there touches.
fn one_step_witness(r: &Replay, pc: u64) -> Vec<Arg> {
    let index = usize::try_from(pc).unwrap_or(usize::MAX);
    let mut trie = r.pre.clone();
    for instruction in r.program.iter().take(index) {
        let _ = apply(&mut trie, instruction);
    }
    let slot = r
        .program
        .get(index)
        .map_or(Hash256::ZERO, Instruction::slot);
    let value = trie.get(&slot).map(<[u8]>::to_vec);
    let proof = trie.prove(&slot);
    let (is_leaf, key, value_hash) = match proof.terminal {
        Terminal::Empty => (false, Hash256::ZERO, Hash256::ZERO),
        Terminal::Leaf { key, value_hash } => (true, key, value_hash),
    };
    vec![
        Arg::Bytes(trie.root().as_bytes().to_vec()),
        Arg::Bytes(slot.as_bytes().to_vec()),
        Arg::Bool(value.is_some()),
        Arg::Bytes(value.unwrap_or_default()),
        Arg::BytesList(
            proof
                .siblings
                .iter()
                .map(|h| h.as_bytes().to_vec())
                .collect(),
        ),
        Arg::Bool(is_leaf),
        Arg::Bytes(key.as_bytes().to_vec()),
        Arg::Bytes(value_hash.as_bytes().to_vec()),
    ]
}
