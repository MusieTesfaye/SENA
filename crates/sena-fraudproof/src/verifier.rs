//! Verifier-node logic: detecting divergence and playing a dispute honestly
//! (REQ-FRAUD-024, REQ-FRAUD-025).
//!
//! A verifier re-executes every batch from published data and compares the
//! result against what was asserted. On divergence it challenges, and then plays
//! the bisection game to completion without an operator present — a dispute can
//! run for days and an honest party that misses a move loses.
//!
//! [`TracePlayer`] is the part that plays. It answers only from a trace it
//! computed itself, which is exactly why an honest party cannot lose: every
//! commitment it publishes is one it can defend, and every disagreement it names
//! is real.

use sena_primitives::Hash256;
use sena_state::MerkleTrie;
use sena_stf::{ExecutionTrace, MachineState, StepWitness};

use crate::assertion::Assertion;
use crate::bisection::{Dispute, MoveError, Party};
use crate::osp::OneStepProof;

/// What a verifier found when it re-executed a batch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Finding {
    /// The assertion matches what honest execution produces.
    Agrees,
    /// The asserted post-state root differs from the one computed locally.
    RootDiverges {
        /// What the assertion claimed.
        asserted: Hash256,
        /// What honest execution produced.
        computed: Hash256,
    },
    /// The assertion's trace length does not match the batch.
    TraceLengthDiverges {
        /// What the assertion claimed.
        asserted: u64,
        /// The real length.
        computed: u64,
    },
}

impl Finding {
    /// Returns whether this finding warrants opening a challenge.
    #[must_use]
    pub const fn warrants_challenge(&self) -> bool {
        !matches!(self, Self::Agrees)
    }
}

/// Compares an assertion against a locally computed trace (REQ-FRAUD-024).
///
/// The trace length is checked as well as the root. A proposer who understates
/// it could otherwise hide steps beyond the bisection range, and one who
/// overstates it could point a dispute at a step that does not exist.
#[must_use]
pub fn check_assertion(assertion: &Assertion, local: &ExecutionTrace) -> Finding {
    let computed_root = local.final_state().state_root;
    if assertion.post_state_root != computed_root {
        return Finding::RootDiverges {
            asserted: assertion.post_state_root,
            computed: computed_root,
        };
    }
    let computed_length = local.len() as u64;
    if assertion.trace_length != computed_length {
        return Finding::TraceLengthDiverges {
            asserted: assertion.trace_length,
            computed: computed_length,
        };
    }
    Finding::Agrees
}

/// Plays a dispute from a locally computed trace.
///
/// Holds the pre-state trie alongside the trace because a One-Step Proof needs a
/// Merkle proof taken at the disputed step's pre-state, which means replaying
/// the batch up to that step.
#[derive(Clone, Debug)]
pub struct TracePlayer {
    trace: ExecutionTrace,
    pre_state: MerkleTrie,
}

impl TracePlayer {
    /// Creates a player from a trace and the trie the batch started from.
    #[must_use]
    pub const fn new(trace: ExecutionTrace, pre_state: MerkleTrie) -> Self {
        Self { trace, pre_state }
    }

    /// Returns the trace being played.
    #[must_use]
    pub const fn trace(&self) -> &ExecutionTrace {
        &self.trace
    }

    /// Returns this player's machine state at `step`.
    ///
    /// Steps beyond the trace return the final state. A party is only ever asked
    /// about a step inside an interval it has agreed to, so this arises only
    /// when an opponent has overstated the trace length — in which case they
    /// lose at one-step adjudication anyway.
    #[must_use]
    pub fn state_at(&self, step: u64) -> MachineState {
        usize::try_from(step)
            .ok()
            .and_then(|i| self.trace.states.get(i))
            .copied()
            .unwrap_or_else(|| self.trace.final_state())
    }

    /// Returns this player's commitment at `step`.
    #[must_use]
    pub fn commitment_at(&self, step: u64) -> Hash256 {
        self.state_at(step).commitment()
    }

    /// Produces the interior commitments for the dispute's current interval.
    #[must_use]
    pub fn dissect(&self, dispute: &Dispute) -> Vec<Hash256> {
        let boundaries = dispute.boundaries();
        boundaries[1..boundaries.len() - 1]
            .iter()
            .map(|step| self.commitment_at(*step))
            .collect()
    }

    /// Returns the index of the first segment whose end commitment this player
    /// disputes.
    ///
    /// Returns `None` only if the player agrees with every division offered,
    /// which cannot happen for an honest player that genuinely disagrees about
    /// the interval's end: if it agreed with all interior points *and* the end,
    /// there would be no dispute.
    #[must_use]
    pub fn first_disagreement(&self, dispute: &Dispute, offered: &[Hash256]) -> Option<usize> {
        let boundaries = dispute.boundaries();
        let mut ends = offered.to_vec();
        ends.push(dispute.hi_commitment);

        ends.iter().enumerate().find_map(|(index, claimed)| {
            (self.commitment_at(boundaries[index + 1]) != *claimed).then_some(index)
        })
    }

    /// Builds the One-Step Proof for the disputed step.
    ///
    /// Replays the batch from its pre-state to the step in question so the
    /// Merkle proof is taken against the right root. A production node would
    /// replay from the nearest stored checkpoint instead (NFR-REL-004); the
    /// distinction is performance, not correctness.
    ///
    /// # Errors
    ///
    /// Returns `None` if the dispute has not narrowed to a single step, or if
    /// the step lies outside this player's trace.
    #[must_use]
    pub fn one_step_proof(&self, dispute: &Dispute) -> Option<OneStepProof> {
        let step = dispute.disputed_step()?;
        let index = usize::try_from(step).ok()?;
        let instruction = self.trace.instructions.get(index)?;

        let mut replay = self.pre_state.clone();
        for earlier in &self.trace.instructions[..index] {
            sena_stf::apply(&mut replay, earlier).ok()?;
        }

        let slot = instruction.slot();
        Some(OneStepProof {
            pre_state: self.state_at(step),
            witness: StepWitness {
                slot,
                value: replay.get(&slot).map(<[u8]>::to_vec),
                proof: replay.prove(&slot),
            },
        })
    }

    /// Makes this player's move in `dispute`, whichever role it holds.
    ///
    /// # Errors
    ///
    /// Returns [`MoveError`] if the move is refused, or
    /// [`PlayError::NoDisagreement`] if this player is challenging but agrees
    /// with everything offered.
    pub fn play(&self, dispute: &mut Dispute, role: Party, now: u64) -> Result<(), PlayError> {
        match role {
            Party::Defender => {
                let commitments = self.dissect(dispute);
                dispute.dissect(now, commitments)?;
                Ok(())
            }
            Party::Challenger => {
                let offered = match &dispute.stage {
                    crate::bisection::Stage::Bisecting { offered: Some(o) } => o.clone(),
                    _ => return Err(PlayError::Move(MoveError::WrongStage)),
                };
                let index = self
                    .first_disagreement(dispute, &offered)
                    .ok_or(PlayError::NoDisagreement)?;
                dispute.select(now, index)?;
                Ok(())
            }
        }
    }
}

/// Why a player could not move.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum PlayError {
    /// The dispute refused the move.
    #[error("{0}")]
    Move(#[from] MoveError),
    /// This player agrees with every division offered, so has nothing to select.
    #[error("no disagreement with the offered division; this party has conceded in substance")]
    NoDisagreement,
}
