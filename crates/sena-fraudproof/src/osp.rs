//! One-Step Proof adjudication (REQ-FRAUD-016 to REQ-FRAUD-018).
//!
//! This is where a dispute actually ends. Bisection has narrowed the
//! disagreement to a single step; both parties agree on the state going in and
//! disagree on the state coming out. Aptos L1 executes that one step and sees
//! who was right.
//!
//! [`adjudicate`] is the function `sena::osp` reimplements in Move. It holds no
//! state: everything it needs arrives in the proof, and everything it trusts it
//! checks first.

use sena_stf::{verify_step, Instruction, MachineState, StepError, StepWitness};
use serde::{Deserialize, Serialize};

use crate::bisection::{Dispute, Party};

/// Everything L1 needs to settle the disputed step.
///
/// Note what is *absent*: the instruction. A challenger does not get to say
/// which instruction was at the disputed index, because that would let them pick
/// one that fails. L1 derives it from the published batch data instead — which
/// is only possible because compilation is a pure function of the transaction
/// (see [`sena_stf::compile`]).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OneStepProof {
    /// The machine state going into the step, which must match the commitment
    /// both parties agreed on during bisection.
    pub pre_state: MachineState,
    /// Proof of the one slot the step touches.
    pub witness: StepWitness,
}

/// The outcome of adjudicating a step, and why.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Verdict {
    /// Who won.
    pub winner: Party,
    /// The reasoning, for logging and for the record.
    pub reason: VerdictReason,
}

/// Why a step was decided as it was.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerdictReason {
    /// Honest execution reproduced the defender's claimed post-state.
    DefenderClaimConfirmed,
    /// Honest execution produced a different post-state than the defender claimed.
    DefenderClaimRefuted,
    /// The step cannot execute at all against the proven pre-state.
    StepIsNotExecutable {
        /// What went wrong.
        error: StepError,
    },
    /// The proof did not describe the state both parties had agreed on.
    ProofContradictsAgreedState,
    /// The proof's witness was malformed or for the wrong slot.
    WitnessRejected {
        /// What was wrong with it.
        error: StepError,
    },
    /// The defender claimed a trace longer than the batch actually produces.
    TraceLengthOverstated {
        /// The step index that does not exist.
        step: u64,
        /// How many steps the batch really has.
        program_length: usize,
    },
}

/// Settles a dispute that has narrowed to a single step.
///
/// `program` is the instruction sequence L1 derives from the published batch
/// data. `dispute` supplies the agreed pre-state commitment and the defender's
/// disputed post-state commitment.
///
/// # How a bad proof is distinguished from real fraud
///
/// The witness comes from the challenger, so a failure to execute could mean
/// either that the defender committed fraud or that the challenger supplied
/// garbage. Conflating the two would let anyone win a dispute by submitting a
/// deliberately broken witness.
///
/// The two are separated by *when* the failure occurs. A witness that does not
/// prove against the agreed pre-state root, or that describes the wrong slot, is
/// the challenger's fault and loses them the dispute. A witness that proves
/// correctly, followed by a step that cannot execute, is fraud: the defender
/// claimed an outcome for a step that honest execution refuses.
///
/// # Panics
///
/// Panics if `dispute` has not narrowed to a single step; callers reach this
/// only through [`Dispute::disputed_step`].
#[must_use]
pub fn adjudicate(program: &[Instruction], dispute: &Dispute, proof: &OneStepProof) -> Verdict {
    let step = dispute
        .disputed_step()
        .expect("adjudication requires a dispute narrowed to one step");

    // The pre-state must be the one bisection established. Without this check a
    // challenger could prove a step against some unrelated state.
    if proof.pre_state.commitment() != dispute.lo_commitment {
        return Verdict {
            winner: Party::Defender,
            reason: VerdictReason::ProofContradictsAgreedState,
        };
    }

    let Some(instruction) = usize::try_from(step).ok().and_then(|i| program.get(i)) else {
        // The batch has no such step, so the defender's trace_length was a
        // false claim and the assertion falls with it.
        return Verdict {
            winner: Party::Challenger,
            reason: VerdictReason::TraceLengthOverstated {
                step,
                program_length: program.len(),
            },
        };
    };

    match verify_step(&proof.pre_state, instruction, &proof.witness) {
        Ok(post) => {
            if post.commitment() == dispute.hi_commitment {
                Verdict {
                    winner: Party::Defender,
                    reason: VerdictReason::DefenderClaimConfirmed,
                }
            } else {
                Verdict {
                    winner: Party::Challenger,
                    reason: VerdictReason::DefenderClaimRefuted,
                }
            }
        }
        // The challenger's own submission was defective.
        Err(error @ (StepError::WitnessSlotMismatch { .. } | StepError::BadWitnessProof(_))) => {
            Verdict {
                winner: Party::Defender,
                reason: VerdictReason::WitnessRejected { error },
            }
        }
        // The witness was sound and the step still cannot execute: the
        // defender asserted an outcome honest execution does not produce.
        Err(error) => Verdict {
            winner: Party::Challenger,
            reason: VerdictReason::StepIsNotExecutable { error },
        },
    }
}
