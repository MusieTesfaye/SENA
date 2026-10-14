//! The proposer's L1 duties: post, defend, finalize.
//!
//! An honest sequencer is safe only if it acts on L1. It must post each sealed
//! block as a bonded assertion with its batch data, answer every bisection
//! move against its assertions before the deadline (or lose its bond for a
//! correct claim), and finalize assertions whose window has passed. The
//! [`Relayer`] does all three, one [`Relayer::step`] at a time.
//!
//! It fails closed. A post that does not land is not recorded, so the next
//! block is never posted on a parent L1 does not have; progress is persisted
//! atomically after every change, so a restart resumes rather than re-posts.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sena_fraudproof::bisection::{self, DEFAULT_ARITY};
use sena_primitives::Hash256;
use sena_stf::batch::{header_commitment, BatchTree};
use serde::{Deserialize, Serialize};

use crate::l1::{self, status, Arg, L1Error, L1};
use crate::rpc::{Request, Response};

/// Move abort codes the relayer reacts to.
mod abort {
    /// `assertions::E_WINDOW_OPEN`.
    pub const WINDOW_OPEN: u64 = 37;
    /// `assertions::E_PARENT_NOT_FINAL`.
    pub const PARENT_NOT_FINAL: u64 = 38;
}

/// A sealed L2 block, as the relayer needs it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct L2Block {
    /// Height.
    pub height: u64,
    /// Batch timestamp.
    pub timestamp: u64,
    /// State root before.
    pub pre_state_root: Hash256,
    /// State root after.
    pub post_state_root: Hash256,
    /// Transactions, canonically encoded.
    pub tx_bytes: Vec<Vec<u8>>,
    /// Each transaction's start position.
    pub tx_starts: Vec<u64>,
    /// Trace length.
    pub trace_length: u64,
}

/// Where the relayer reads sealed blocks and their traces.
pub trait L2Source {
    /// The block at `height`, or `None` if not sealed yet.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure.
    fn block(&self, height: u64) -> Result<Option<L2Block>, String>;

    /// The block's machine-state commitments at `steps`.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure.
    fn commitments(&self, height: u64, steps: &[u64]) -> Result<Vec<Hash256>, String>;
}

/// [`L2Source`] over a node's JSON-RPC.
#[derive(Clone, Debug)]
pub struct RpcSource {
    /// The node's RPC URL.
    pub url: String,
    /// Bearer token, if the node requires one.
    pub auth_token: Option<String>,
}

impl RpcSource {
    fn call(&self, request: &Request) -> Result<Response, String> {
        let mut req = ureq::post(&self.url).timeout(Duration::from_secs(10));
        if let Some(token) = &self.auth_token {
            req = req.set("Authorization", &format!("Bearer {token}"));
        }
        req.send_json(request)
            .map_err(|e| format!("L2 RPC {}: {e}", self.url))?
            .into_json()
            .map_err(|e| format!("L2 RPC response: {e}"))
    }
}

impl L2Source for RpcSource {
    fn block(&self, height: u64) -> Result<Option<L2Block>, String> {
        match self.call(&Request::GetBlock { height })? {
            Response::Block {
                height,
                timestamp,
                pre_state_root,
                post_state_root,
                transactions,
                trace_length,
                tx_starts,
                ..
            } => Ok(Some(L2Block {
                height,
                timestamp,
                pre_state_root,
                post_state_root,
                tx_bytes: transactions
                    .iter()
                    .map(sena_stf::Transaction::encode)
                    .collect(),
                tx_starts,
                trace_length,
            })),
            Response::Error { message } if message.starts_with("no block") => Ok(None),
            other => Err(format!("unexpected response: {other:?}")),
        }
    }

    fn commitments(&self, height: u64, steps: &[u64]) -> Result<Vec<Hash256>, String> {
        match self.call(&Request::GetTraceCommitments {
            height,
            steps: steps.to_vec(),
        })? {
            Response::TraceCommitments { commitments } => Ok(commitments),
            other => Err(format!("unexpected response: {other:?}")),
        }
    }
}

/// Relayer settings.
#[derive(Clone, Debug)]
pub struct RelayerConfig {
    /// The bond posted with each assertion.
    pub bond: u128,
    /// Where progress is persisted.
    pub state_path: PathBuf,
}

/// One posted assertion.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Posted {
    /// The L2 block it covers.
    pub height: u64,
    /// Its id, hex.
    pub id: String,
    /// Whether it has finalized.
    pub finalized: bool,
    /// Whether it was rejected. Nothing builds on it afterwards.
    pub rejected: bool,
}

/// What the relayer has done, persisted across restarts.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct RelayerState {
    /// Assertions posted, in order.
    pub posted: Vec<Posted>,
}

impl RelayerState {
    /// Loads state, or starts empty if there is none yet.
    ///
    /// # Errors
    ///
    /// Returns a description if the file exists but cannot be read.
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Persists state atomically: write a sibling, then rename over.
    ///
    /// # Errors
    ///
    /// Returns a description if the write fails.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// What one step did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct StepReport {
    /// Heights posted.
    pub posted: Vec<u64>,
    /// Dissections submitted, as (assertion, challenger).
    pub dissected: Vec<(String, String)>,
    /// Timeouts claimed.
    pub timeouts_claimed: usize,
    /// Heights finalized.
    pub finalized: Vec<u64>,
    /// Heights learned to be rejected.
    pub rejected: Vec<u64>,
}

/// Why a step failed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RelayError {
    /// L1 refused or could not be reached.
    #[error("{0}")]
    L1(#[from] L1Error),
    /// The L2 node could not be read.
    #[error("L2: {0}")]
    L2(String),
    /// Progress could not be saved.
    #[error("state: {0}")]
    State(String),
    /// An assertion of ours was rejected: the sequencer asserted something
    /// L1 found wrong, and nothing more can be built on it. Operator action.
    #[error("assertion for block {0} was rejected on L1; halting")]
    Rejected(u64),
}

/// The proposer's L1 agent.
#[derive(Debug)]
pub struct Relayer<C: L1, S: L2Source> {
    l1: C,
    l2: S,
    config: RelayerConfig,
    state: RelayerState,
}

fn parse_id(hex_id: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_id).unwrap_or_default();
    bytes.try_into().unwrap_or([0; 32])
}

impl<C: L1, S: L2Source> Relayer<C, S> {
    /// Creates a relayer, resuming from its persisted state.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::State`] if the state file cannot be read.
    pub fn new(l1: C, l2: S, config: RelayerConfig) -> Result<Self, RelayError> {
        let state = RelayerState::load(&config.state_path).map_err(RelayError::State)?;
        Ok(Self {
            l1,
            l2,
            config,
            state,
        })
    }

    /// The persisted state.
    #[must_use]
    pub const fn state(&self) -> &RelayerState {
        &self.state
    }

    fn save(&self) -> Result<(), RelayError> {
        self.state
            .save(&self.config.state_path)
            .map_err(RelayError::State)
    }

    /// Posts, defends and finalizes as far as it can. Defending comes first:
    /// a missed deadline costs a bond, a late post or finalization does not.
    ///
    /// # Errors
    ///
    /// Returns the first [`RelayError`]; whatever succeeded before it is
    /// already persisted.
    pub fn step(&mut self) -> Result<StepReport, RelayError> {
        let mut report = StepReport::default();
        self.defend(&mut report)?;
        self.post_new(&mut report)?;
        self.finalize(&mut report)?;
        Ok(report)
    }

    fn post_new(&mut self, report: &mut StepReport) -> Result<(), RelayError> {
        loop {
            let height = self.state.posted.last().map_or(1, |p| p.height + 1);
            let Some(block) = self.l2.block(height).map_err(RelayError::L2)? else {
                return Ok(());
            };
            let parent = match self.state.posted.last() {
                Some(p) => parse_id(&p.id),
                None => l1::genesis_id(block.pre_state_root),
            };
            let leaves: Vec<(u64, Vec<u8>)> = block
                .tx_starts
                .iter()
                .copied()
                .zip(block.tx_bytes.iter().cloned())
                .collect();
            let tree = BatchTree::build(&leaves);
            let commitment = header_commitment(block.timestamp, tree.tx_count(), &tree.root());
            let id = l1::assertion_id(
                &parent,
                block.pre_state_root,
                block.post_state_root,
                commitment,
                block.trace_length,
                self.config.bond,
            );
            // A crash between a successful post and saving it leaves the
            // assertion on L1 but not in our state; posting it again would
            // abort on the duplicate id forever.
            let already_posted = self
                .l1
                .view(
                    "assertions::record",
                    &[Arg::Address(self.l1.contract()), Arg::Bytes(id.to_vec())],
                )
                .is_ok();
            if !already_posted {
                self.l1.submit(
                    "assertions::post",
                    &[
                        Arg::Address(self.l1.contract()),
                        Arg::Bytes(parent.to_vec()),
                        Arg::Bytes(block.pre_state_root.as_bytes().to_vec()),
                        Arg::Bytes(block.post_state_root.as_bytes().to_vec()),
                        Arg::U64(block.timestamp),
                        Arg::BytesList(block.tx_bytes.clone()),
                        Arg::U64List(block.tx_starts.clone()),
                        Arg::U64(block.trace_length),
                        Arg::U128(self.config.bond),
                    ],
                )?;
            }
            self.state.posted.push(Posted {
                height,
                id: hex::encode(id),
                finalized: false,
                rejected: false,
            });
            self.save()?;
            report.posted.push(height);
        }
    }

    fn record(&self, id: &str) -> Result<l1::Record, RelayError> {
        let v = self.l1.view(
            "assertions::record",
            &[
                Arg::Address(self.l1.contract()),
                Arg::Bytes(hex::decode(id).unwrap_or_default()),
            ],
        )?;
        Ok(l1::parse_record(&v)?)
    }

    fn defend(&mut self, report: &mut StepReport) -> Result<(), RelayError> {
        let now = self.l1.now()?;
        for i in 0..self.state.posted.len() {
            let posted = self.state.posted[i].clone();
            if posted.finalized || posted.rejected {
                continue;
            }
            let record = self.record(&posted.id)?;
            if record.status == status::REJECTED {
                self.state.posted[i].rejected = true;
                self.save()?;
                report.rejected.push(posted.height);
                return Err(RelayError::Rejected(posted.height));
            }
            if record.status != status::CHALLENGED {
                continue;
            }
            let id_bytes = hex::decode(&posted.id).unwrap_or_default();
            let challengers = self.l1.view(
                "assertions::challengers",
                &[
                    Arg::Address(self.l1.contract()),
                    Arg::Bytes(id_bytes.clone()),
                ],
            )?;
            for challenger in challengers
                .first()
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                let Some(challenger) = challenger.as_str() else {
                    continue;
                };
                let did = l1::dispute_id(&id_bytes, challenger);
                let d = l1::parse_dispute(&self.l1.view(
                    "disputes::dispute_state",
                    &[Arg::Address(self.l1.contract()), Arg::Bytes(did.clone())],
                )?)?;
                if !d.exists || d.stage == 2 {
                    continue;
                }
                if d.turn == 0 && d.stage == 0 && !d.has_offer {
                    let bounds = bisection::boundaries(d.lo, d.hi, DEFAULT_ARITY);
                    let interior = &bounds[1..bounds.len() - 1];
                    let commitments = self
                        .l2
                        .commitments(posted.height, interior)
                        .map_err(RelayError::L2)?;
                    self.l1.submit(
                        "disputes::dissect",
                        &[
                            Arg::Address(self.l1.contract()),
                            Arg::Bytes(did),
                            Arg::BytesList(
                                commitments.iter().map(|h| h.as_bytes().to_vec()).collect(),
                            ),
                        ],
                    )?;
                    report
                        .dissected
                        .push((posted.id.clone(), challenger.to_owned()));
                } else if d.turn == 1 && now > d.deadline {
                    // The challenger stopped moving: the defender wins.
                    self.l1.submit(
                        "disputes::claim_timeout",
                        &[Arg::Address(self.l1.contract()), Arg::Bytes(did)],
                    )?;
                    report.timeouts_claimed += 1;
                }
            }
        }
        Ok(())
    }

    fn finalize(&mut self, report: &mut StepReport) -> Result<(), RelayError> {
        let window = l1::u128_of(
            self.l1
                .view(
                    "assertions::challenge_window",
                    &[Arg::Address(self.l1.contract())],
                )?
                .first()
                .ok_or_else(|| L1Error::Malformed("no challenge window".into()))?,
        )?;
        let now = u128::from(self.l1.now()?);
        for i in 0..self.state.posted.len() {
            let posted = self.state.posted[i].clone();
            if posted.finalized || posted.rejected {
                continue;
            }
            let record = self.record(&posted.id)?;
            if record.status == status::FINALIZED {
                self.state.posted[i].finalized = true;
                self.save()?;
                continue;
            }
            // Finalization is in order: nothing after a pending one can go.
            if record.status != status::PENDING || u128::from(record.posted_at) + window > now {
                return Ok(());
            }
            match self.l1.submit(
                "assertions::finalize",
                &[
                    Arg::Address(self.l1.contract()),
                    Arg::Bytes(hex::decode(&posted.id).unwrap_or_default()),
                ],
            ) {
                Ok(_) => {
                    self.state.posted[i].finalized = true;
                    self.save()?;
                    report.finalized.push(posted.height);
                }
                Err(e) if e.is_abort(abort::WINDOW_OPEN) || e.is_abort(abort::PARENT_NOT_FINAL) => {
                    return Ok(())
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
