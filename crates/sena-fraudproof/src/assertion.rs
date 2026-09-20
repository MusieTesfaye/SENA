//! Bonded assertions and the chain they form on Aptos L1.
//!
//! An assertion is a claim, not a fact: "executing this batch against this
//! pre-state yields this post-state". It is posted with a bond, it is open to
//! challenge for a window, and only then does it finalize (REQ-FRAUD-001 through
//! REQ-FRAUD-006).
//!
//! [`AssertionChain`] models the `sena::assertions` Move contract. It is
//! deliberately written as a pure state machine over an explicit clock rather
//! than against a real clock, both because the L1 contract sees only block
//! timestamps and because a dispute system whose behaviour depends on wall time
//! cannot be tested adversarially.

use std::collections::BTreeMap;

use sena_primitives::{domain, CanonicalEncoder, Hash256};
use serde::{Deserialize, Serialize};

/// Identifies an assertion by the hash of its contents.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct AssertionId(pub Hash256);

impl AssertionId {
    /// The virtual parent of the first assertion.
    pub const GENESIS: Self = Self(Hash256::ZERO);
}

/// Identifies a party that can post or challenge assertions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct PartyId(pub u32);

/// A claim about the result of executing one batch.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Assertion {
    /// The assertion this one builds on.
    pub parent: AssertionId,
    /// Who posted it, and whose bond is at risk.
    pub proposer: PartyId,
    /// State root before the batch.
    pub pre_state_root: Hash256,
    /// State root the proposer claims results from the batch.
    pub post_state_root: Hash256,
    /// Commitment to the published batch data (REQ-FRAUD-007).
    pub batch_commitment: Hash256,
    /// Number of steps in the batch's execution trace.
    ///
    /// Bisection searches `0..=trace_length`, so both parties must agree on the
    /// bound before the game can start. It is part of the assertion for that
    /// reason: a proposer who misstates it is making a checkable claim.
    pub trace_length: u64,
    /// The bond locked behind this claim.
    pub bond: u128,
}

impl Assertion {
    /// Returns the assertion's identifier.
    #[must_use]
    pub fn id(&self) -> AssertionId {
        AssertionId(Hash256::commit(
            CanonicalEncoder::new(domain::ASSERTION)
                .field(self.parent.0.as_bytes())
                .u64(u64::from(self.proposer.0))
                .field(self.pre_state_root.as_bytes())
                .field(self.post_state_root.as_bytes())
                .field(self.batch_commitment.as_bytes())
                .u64(self.trace_length)
                .u128(self.bond),
        ))
    }
}

/// Where an assertion stands (SDD §3.5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Status {
    /// Posted, within its challenge window, no open challenge.
    Pending,
    /// Under challenge; finalization is blocked until every challenge resolves.
    Challenged,
    /// Survived its window. Withdrawals may be honoured against it.
    Finalized,
    /// Lost a challenge, or descends from one that did.
    Rejected,
}

/// An assertion together with the chain's bookkeeping for it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Record {
    /// The claim itself.
    pub assertion: Assertion,
    /// Current status.
    pub status: Status,
    /// L1 time at which it was posted; the challenge window runs from here.
    pub posted_at: u64,
    /// How many challenges against it are unresolved.
    pub open_challenges: u32,
}

/// Why an operation on the chain was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ChainError {
    /// The named assertion is not on the chain.
    #[error("no such assertion")]
    UnknownAssertion,
    /// The parent is not an assertion the chain knows.
    #[error("parent assertion is unknown")]
    UnknownParent,
    /// The parent has been rejected, so nothing may build on it.
    #[error("cannot build on a rejected assertion")]
    ParentRejected,
    /// The pre-state root does not continue the parent's post-state root.
    #[error("pre-state root {got} does not match the parent's post-state root {expected}")]
    BrokenChain {
        /// The pre-state root offered.
        got: Hash256,
        /// The parent's post-state root.
        expected: Hash256,
    },
    /// The bond is below the minimum.
    #[error("bond {offered} is below the minimum {required}")]
    BondTooSmall {
        /// What was offered.
        offered: u128,
        /// What the chain requires.
        required: u128,
    },
    /// The assertion is not in a state that permits this operation.
    #[error("assertion is {status:?}, which does not permit this operation")]
    WrongStatus {
        /// The status it is actually in.
        status: Status,
    },
    /// The challenge window has not elapsed.
    #[error("challenge window has not elapsed: {remaining} seconds remain")]
    WindowOpen {
        /// Seconds still to run.
        remaining: u64,
    },
    /// Time moved backwards.
    #[error("time moved backwards")]
    TimeWentBackwards,
}

/// The L1 assertion chain.
///
/// # What this refuses to do
///
/// There is no method here to finalize a challenged assertion, dismiss a
/// challenge, or set the challenge window below its floor — not because such a
/// method is guarded, but because it does not exist. REQ-FRAUD-015 and
/// REQ-GOV-007 are enforced by the absence of the capability, which is the only
/// form of enforcement that survives a compromised council.
#[derive(Clone, Debug)]
pub struct AssertionChain {
    records: BTreeMap<AssertionId, Record>,
    /// Most recent finalized assertion; withdrawals are honoured against it.
    latest_finalized: Option<AssertionId>,
    challenge_window: u64,
    minimum_bond: u128,
    now: u64,
}

/// The floor on the challenge window, in seconds (REQ-FRAUD-004).
///
/// Twenty-four hours. A shorter window would make honest challenge contingent on
/// a verifier being online and able to land an L1 transaction within hours,
/// which is not a safe assumption under congestion. Governance may raise the
/// window but cannot go below this.
pub const CHALLENGE_WINDOW_FLOOR: u64 = 24 * 60 * 60;

/// The default challenge window, in seconds (REQ-FRAUD-004): seven days.
pub const DEFAULT_CHALLENGE_WINDOW: u64 = 7 * 24 * 60 * 60;

impl AssertionChain {
    /// Creates a chain anchored at `genesis_root`.
    ///
    /// The window is clamped to [`CHALLENGE_WINDOW_FLOOR`] rather than rejected,
    /// so that no configuration path can produce a chain with an unsafe window.
    #[must_use]
    pub fn new(genesis_root: Hash256, challenge_window: u64, minimum_bond: u128) -> Self {
        let genesis = Assertion {
            parent: AssertionId::GENESIS,
            proposer: PartyId(0),
            pre_state_root: Hash256::ZERO,
            post_state_root: genesis_root,
            batch_commitment: Hash256::ZERO,
            trace_length: 0,
            bond: 0,
        };
        let id = genesis.id();
        let mut records = BTreeMap::new();
        records.insert(
            id,
            Record {
                assertion: genesis,
                status: Status::Finalized,
                posted_at: 0,
                open_challenges: 0,
            },
        );
        Self {
            records,
            latest_finalized: Some(id),
            challenge_window: challenge_window.max(CHALLENGE_WINDOW_FLOOR),
            minimum_bond,
            now: 0,
        }
    }

    /// Returns the configured challenge window.
    #[must_use]
    pub const fn challenge_window(&self) -> u64 {
        self.challenge_window
    }

    /// Returns the chain's current time.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }

    /// Advances the chain's clock.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::TimeWentBackwards`] if `to` precedes the current time.
    pub fn advance_to(&mut self, to: u64) -> Result<(), ChainError> {
        if to < self.now {
            return Err(ChainError::TimeWentBackwards);
        }
        self.now = to;
        Ok(())
    }

    /// Returns the record for an assertion.
    #[must_use]
    pub fn get(&self, id: &AssertionId) -> Option<&Record> {
        self.records.get(id)
    }

    /// Returns the status of an assertion.
    #[must_use]
    pub fn status(&self, id: &AssertionId) -> Option<Status> {
        self.records.get(id).map(|r| r.status)
    }

    /// Returns the most recent finalized assertion.
    #[must_use]
    pub fn latest_finalized(&self) -> Option<&Record> {
        self.latest_finalized
            .as_ref()
            .and_then(|id| self.records.get(id))
    }

    /// Posts a bonded assertion (REQ-FRAUD-001 to REQ-FRAUD-003).
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the parent is unknown or rejected, the
    /// pre-state root does not continue the parent, or the bond is too small.
    pub fn post(&mut self, assertion: Assertion) -> Result<AssertionId, ChainError> {
        let parent = self
            .records
            .get(&assertion.parent)
            .ok_or(ChainError::UnknownParent)?;
        if parent.status == Status::Rejected {
            return Err(ChainError::ParentRejected);
        }
        if parent.assertion.post_state_root != assertion.pre_state_root {
            return Err(ChainError::BrokenChain {
                got: assertion.pre_state_root,
                expected: parent.assertion.post_state_root,
            });
        }
        if assertion.bond < self.minimum_bond {
            return Err(ChainError::BondTooSmall {
                offered: assertion.bond,
                required: self.minimum_bond,
            });
        }

        let id = assertion.id();
        self.records.insert(
            id,
            Record {
                assertion,
                status: Status::Pending,
                posted_at: self.now,
                open_challenges: 0,
            },
        );
        Ok(id)
    }

    /// Records that a challenge has opened against an assertion.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the assertion is unknown or no longer pending.
    pub fn open_challenge(&mut self, id: &AssertionId) -> Result<(), ChainError> {
        let record = self
            .records
            .get_mut(id)
            .ok_or(ChainError::UnknownAssertion)?;
        match record.status {
            Status::Pending | Status::Challenged => {
                record.status = Status::Challenged;
                record.open_challenges = record.open_challenges.saturating_add(1);
                Ok(())
            }
            status => Err(ChainError::WrongStatus { status }),
        }
    }

    /// Records that a challenge resolved in the proposer's favour.
    ///
    /// The assertion returns to `Pending` only once every challenge against it
    /// has resolved (REQ-FRAUD-006).
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the assertion is unknown or not challenged.
    pub fn defender_won(&mut self, id: &AssertionId) -> Result<(), ChainError> {
        let record = self
            .records
            .get_mut(id)
            .ok_or(ChainError::UnknownAssertion)?;
        if record.status != Status::Challenged {
            return Err(ChainError::WrongStatus {
                status: record.status,
            });
        }
        record.open_challenges = record.open_challenges.saturating_sub(1);
        if record.open_challenges == 0 {
            record.status = Status::Pending;
        }
        Ok(())
    }

    /// Records that a challenge succeeded, rejecting the assertion and every
    /// assertion built on it (REQ-FRAUD-019).
    ///
    /// Returns the ids rejected, most recent first.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the assertion is unknown or not challenged.
    pub fn challenger_won(&mut self, id: &AssertionId) -> Result<Vec<AssertionId>, ChainError> {
        let record = self.records.get(id).ok_or(ChainError::UnknownAssertion)?;
        if record.status != Status::Challenged {
            return Err(ChainError::WrongStatus {
                status: record.status,
            });
        }

        // Rejecting only the disputed assertion would leave its children
        // claiming to continue from a state that was never reached.
        let mut rejected = Vec::new();
        let mut frontier = vec![*id];
        while let Some(current) = frontier.pop() {
            if let Some(record) = self.records.get_mut(&current) {
                record.status = Status::Rejected;
                record.open_challenges = 0;
                rejected.push(current);
            }
            frontier.extend(
                self.records
                    .iter()
                    .filter(|(_, r)| r.assertion.parent == current && r.status != Status::Rejected)
                    .map(|(child_id, _)| *child_id),
            );
        }
        Ok(rejected)
    }

    /// Finalizes an assertion whose window has elapsed (REQ-FRAUD-004).
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the assertion is unknown, is not pending, has
    /// an unfinalized parent, or is still inside its window.
    ///
    /// # Panics
    ///
    /// Does not panic: the record is re-read under a key just confirmed present.
    pub fn finalize(&mut self, id: &AssertionId) -> Result<(), ChainError> {
        let record = self.records.get(id).ok_or(ChainError::UnknownAssertion)?;
        if record.status != Status::Pending {
            return Err(ChainError::WrongStatus {
                status: record.status,
            });
        }

        // An assertion cannot outrun its parent: finalizing out of order would
        // let a descendant of a still-disputable claim become withdrawable.
        let parent_status = self.records.get(&record.assertion.parent).map(|r| r.status);
        if parent_status != Some(Status::Finalized) {
            return Err(ChainError::WrongStatus {
                status: parent_status.unwrap_or(Status::Rejected),
            });
        }

        let elapsed = self.now.saturating_sub(record.posted_at);
        if elapsed < self.challenge_window {
            return Err(ChainError::WindowOpen {
                remaining: self.challenge_window - elapsed,
            });
        }

        self.records
            .get_mut(id)
            .expect("record was just read")
            .status = Status::Finalized;
        self.latest_finalized = Some(*id);
        Ok(())
    }

    /// Returns whether a withdrawal may be honoured against `root`
    /// (REQ-FRAUD-005).
    #[must_use]
    pub fn is_withdrawable(&self, root: &Hash256) -> bool {
        self.records
            .values()
            .any(|r| r.status == Status::Finalized && r.assertion.post_state_root == *root)
    }
}

/// A serialisable view of the whole chain, for persistence across restarts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainSnapshot {
    /// Every assertion the chain knows, with its bookkeeping.
    pub records: Vec<Record>,
    /// The most recent finalized assertion, if any.
    pub latest_finalized: Option<AssertionId>,
    /// The configured challenge window.
    pub challenge_window: u64,
    /// The minimum bond.
    pub minimum_bond: u128,
    /// The chain's clock at the time of the snapshot.
    pub now: u64,
}

impl AssertionChain {
    /// Captures the chain's state.
    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        ChainSnapshot {
            records: self.records.values().cloned().collect(),
            latest_finalized: self.latest_finalized,
            challenge_window: self.challenge_window,
            minimum_bond: self.minimum_bond,
            now: self.now,
        }
    }

    /// Rebuilds a chain from a snapshot.
    ///
    /// The window is re-clamped to [`CHALLENGE_WINDOW_FLOOR`] on the way in. A
    /// snapshot is a file on disk, so it is exactly the sort of thing that could
    /// be edited to shorten the window; re-applying the floor means a tampered
    /// file cannot produce a chain that finalizes early.
    #[must_use]
    pub fn restore(snapshot: ChainSnapshot) -> Self {
        let mut records = BTreeMap::new();
        for record in snapshot.records {
            records.insert(record.assertion.id(), record);
        }
        Self {
            records,
            latest_finalized: snapshot.latest_finalized,
            challenge_window: snapshot.challenge_window.max(CHALLENGE_WINDOW_FLOOR),
            minimum_bond: snapshot.minimum_bond,
            now: snapshot.now,
        }
    }
}
