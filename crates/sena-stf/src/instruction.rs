//! The step machine: the granularity at which execution can be disputed.
//!
//! A fraud proof works by narrowing a disagreement about a whole batch down to a
//! disagreement about one step, small enough for Aptos L1 to settle by executing
//! it. That only works if execution is expressible as a sequence of steps, each
//! of which touches a bounded, explicitly named set of state.
//!
//! An [`Instruction`] is that unit. Every instruction reads and writes at most
//! two trie slots, and names them in its operands, so a One-Step Proof carrying
//! a Merkle proof per slot is enough for L1 to check it in isolation.
//!
//! # Relationship to the SDD
//!
//! SDD §3.5.4 specifies compiling the state transition function to RV32IM and
//! stepping individual machine instructions. This module implements bisection
//! and one-step verification over a higher-level instruction set instead. The
//! protocol structure is identical — bonded assertions, bisection to a single
//! step, on-L1 adjudication of that step — but the step is a state-machine
//! operation rather than a RISC-V instruction.
//!
//! The trade-off is real and worth stating: an RV32IM target makes the disputed
//! step independent of the state machine's design, so new features cannot
//! introduce steps the verifier does not understand. Here, every new instruction
//! must be implemented in the L1 verifier too, and an instruction that is
//! expensive to verify is a protocol-level problem. Closing that gap is tracked
//! as follow-up work; the present design is sound for the instruction set that
//! exists.

use sena_primitives::{domain, AssetId, CanonicalEncoder, Hash256, HashedIdentifier, L2Address};
use serde::{Deserialize, Serialize};

/// One indivisible operation on the state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum Instruction {
    /// Check that an account's nonce equals `expected`, then increment it.
    ///
    /// Bundling the check with the increment is what makes replay impossible
    /// (NFR-SEC-005): the two cannot be separated by a reordering, because they
    /// are one step.
    ConsumeNonce {
        /// Account whose nonce is being consumed.
        account: L2Address,
        /// The nonce the transaction claimed.
        expected: u64,
    },
    /// Reduce an account's balance.
    Debit {
        /// Account to debit.
        account: L2Address,
        /// Asset to debit.
        asset: AssetId,
        /// Amount to remove.
        amount: u128,
    },
    /// Increase an account's balance.
    Credit {
        /// Account to credit.
        account: L2Address,
        /// Asset to credit.
        asset: AssetId,
        /// Amount to add.
        amount: u128,
    },
    /// Bind a hashed identifier to an address (REQ-SOCIAL-001).
    BindIdentifier {
        /// The identifier being bound.
        identifier: HashedIdentifier,
        /// The address it will resolve to.
        address: L2Address,
    },
    /// Release a binding, leaving a vacant marker.
    ///
    /// The entry is overwritten rather than removed. Removal can require
    /// collapsing a trie branch, whose shape a Merkle proof does not describe,
    /// which would put it out of reach of the L1 one-step verifier. Keeping the
    /// trie structurally append-only means every step is a replace or an insert.
    UnbindIdentifier {
        /// The identifier being released.
        identifier: HashedIdentifier,
        /// The address that must currently hold it.
        expected_owner: L2Address,
    },
}

/// The machine's observable state between two steps.
///
/// Small by design: it is committed to on Aptos L1 at every bisection round, so
/// each round costs one hash and a handful of bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MachineState {
    /// Root of the state trie at this point in the trace.
    pub state_root: Hash256,
    /// Index of the next instruction to execute.
    pub pc: u64,
}

impl MachineState {
    /// Creates the state at the start of a trace.
    #[must_use]
    pub const fn start(state_root: Hash256) -> Self {
        Self { state_root, pc: 0 }
    }

    /// Returns the commitment published during bisection.
    ///
    /// Both the trie root and the program counter are committed. Committing only
    /// the root would let a party claim the same state at a different point in
    /// the trace, which is exactly the ambiguity bisection needs to exclude.
    #[must_use]
    pub fn commitment(&self) -> Hash256 {
        Hash256::commit(
            CanonicalEncoder::new(domain::MACHINE_STATE)
                .field(self.state_root.as_bytes())
                .u64(self.pc),
        )
    }
}

impl Instruction {
    /// Returns the single trie slot this instruction reads and writes.
    ///
    /// Every instruction touches exactly one slot. That restriction is what
    /// keeps one-step verification simple enough to live in a Move contract: the
    /// proof is checked against the pre-state root, the new value is computed,
    /// and the post-state root follows from the same proof path. An instruction
    /// writing two slots would need the second proof to be against the
    /// intermediate root produced by the first write, and assembling and
    /// checking such chained proofs on L1 is exactly the complexity worth
    /// avoiding.
    ///
    /// Operations that span accounts are therefore expressed as several
    /// instructions: a transfer is a `Debit` of the sender followed by a
    /// `Credit` of the recipient, and each is disputable on its own.
    #[must_use]
    pub fn slot(&self) -> Hash256 {
        use crate::keys;
        match self {
            Self::ConsumeNonce { account, .. }
            | Self::Debit { account, .. }
            | Self::Credit { account, .. } => keys::account(account),
            Self::BindIdentifier { identifier, .. } | Self::UnbindIdentifier { identifier, .. } => {
                keys::social_by_identifier(identifier)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_distinguishes_position_in_the_trace() {
        let root = Hash256::digest(b"state");
        let a = MachineState {
            state_root: root,
            pc: 4,
        };
        let b = MachineState {
            state_root: root,
            pc: 5,
        };
        assert_ne!(
            a.commitment(),
            b.commitment(),
            "the same state at two trace positions must not be conflated"
        );
    }

    #[test]
    fn commitment_distinguishes_state() {
        let a = MachineState {
            state_root: Hash256::digest(b"a"),
            pc: 1,
        };
        let b = MachineState {
            state_root: Hash256::digest(b"b"),
            pc: 1,
        };
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn each_instruction_names_its_single_slot() {
        let account = L2Address::from_bytes([3; 32]);
        let instr = Instruction::Credit {
            account,
            asset: AssetId::NATIVE,
            amount: 1,
        };
        assert_eq!(instr.slot(), crate::keys::account(&account));
    }
}
