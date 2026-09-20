//! Verifier mode (REQ-FRAUD-024 to REQ-FRAUD-026).
//!
//! A verifier follows the assertion chain, re-executes every batch **from the
//! published transactions**, and challenges anything that disagrees with its own
//! result. It never reads the sequencer's trace: taking the sequencer's word for
//! how the batch executed would defeat the entire purpose.
//!
//! The node runs the same binary as the sequencer, in a different mode. That is
//! deliberate (NFR-MAINT-004): two separate implementations could drift, and a
//! verifier whose semantics differ from an honest sequencer's would open
//! disputes it deserves to lose.

use sena_state::MerkleTrie;
use sena_stf::{execute_batch, BatchError};

use sena_fraudproof::{
    check_assertion, Assertion, AssertionId, Dispute, Finding, Opening, PartyId, TracePlayer,
};

use crate::sequencer::Block;

/// What following a block produced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// The assertion matches independent re-execution.
    Accepted,
    /// The assertion disagrees; a challenge is warranted.
    Divergent {
        /// What the disagreement was.
        finding: Finding,
    },
    /// The published batch does not execute at all against the verifier's state.
    ///
    /// Also grounds for a challenge: a batch that cannot execute cannot have
    /// produced the asserted root.
    Unexecutable {
        /// Why it failed.
        reason: String,
    },
}

impl Outcome {
    /// Returns whether this outcome warrants opening a challenge.
    #[must_use]
    pub const fn warrants_challenge(&self) -> bool {
        !matches!(self, Self::Accepted)
    }
}

/// An independent verifier node.
#[derive(Debug)]
pub struct VerifierNode {
    /// The verifier's own replica of L2 state, built by re-execution.
    pub state: MerkleTrie,
    /// This verifier's identity on L1.
    pub identity: PartyId,
    /// The trace it last computed, kept so it can play a dispute.
    last_trace: Option<TracePlayer>,
}

impl VerifierNode {
    /// Creates a verifier starting from `genesis_state`.
    #[must_use]
    pub const fn new(genesis_state: MerkleTrie, identity: PartyId) -> Self {
        Self {
            state: genesis_state,
            identity,
            last_trace: None,
        }
    }

    /// Re-executes a published block and compares it against the assertion.
    ///
    /// On agreement the verifier's replica advances. On disagreement it does
    /// not: the assertion is the one being challenged, so following it would
    /// mean adopting the state the verifier is disputing.
    pub fn follow(&mut self, block: &Block, assertion: &Assertion) -> Outcome {
        let pre_state = self.state.clone();
        let mut next = self.state.clone();

        let trace = match execute_batch(&mut next, &block.transactions) {
            Ok(trace) => trace,
            Err(BatchError::Compile { index, source }) => {
                return Outcome::Unexecutable {
                    reason: format!("transaction {index} does not compile: {source}"),
                }
            }
            Err(error) => {
                return Outcome::Unexecutable {
                    reason: error.to_string(),
                }
            }
        };

        let finding = check_assertion(assertion, &trace);
        self.last_trace = Some(TracePlayer::new(trace, pre_state));

        if finding.warrants_challenge() {
            Outcome::Divergent { finding }
        } else {
            self.state = next;
            Outcome::Accepted
        }
    }

    /// Returns a player for the last batch re-executed, for playing a dispute.
    #[must_use]
    pub const fn player(&self) -> Option<&TracePlayer> {
        self.last_trace.as_ref()
    }

    /// Opens a dispute against an assertion the verifier disagrees with.
    ///
    /// Returns `None` if no batch has been re-executed yet.
    #[must_use]
    pub fn open_dispute(
        &self,
        assertion_id: AssertionId,
        assertion: &Assertion,
        challenge_window: u64,
        now: u64,
    ) -> Option<Dispute> {
        let player = self.last_trace.as_ref()?;
        Some(Dispute::open(
            &Opening {
                assertion: assertion_id,
                defender: assertion.proposer,
                challenger: self.identity,
                trace_length: assertion.trace_length,
                // The verifier's own commitment at step zero. Both parties
                // agree here by construction: they share the pre-state.
                lo_commitment: player.commitment_at(0),
                // What the proposer claims at the end, which is the claim in
                // dispute.
                hi_commitment: sena_stf::MachineState {
                    state_root: assertion.post_state_root,
                    pc: assertion.trace_length,
                }
                .commitment(),
                challenge_window,
            },
            now,
        ))
    }
}
