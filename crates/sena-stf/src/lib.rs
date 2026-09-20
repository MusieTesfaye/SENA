//! The SENA state transition function.
//!
//! This crate defines what a transaction means. It is the reference the whole
//! protocol is measured against: the sequencer runs it to produce blocks,
//! verifier nodes run it to decide whether an assertion is honest, and Aptos L1
//! runs one step of it to settle a dispute.
//!
//! # Execution is a trace, not a black box
//!
//! Executing a batch does not merely produce a new state root — it produces an
//! [`ExecutionTrace`], the full sequence of intermediate machine states. That is
//! what makes fraud proofs possible. Two parties who disagree about a batch's
//! outcome agree about its starting state, so there is a first step where their
//! traces diverge; bisection finds it, and Aptos L1 settles it.
//!
//! Each [`Instruction`] touches exactly one state slot, which keeps one-step
//! verification small enough to implement in Move.
//!
//! ```
//! use sena_primitives::{AssetId, L2Address};
//! use sena_state::MerkleTrie;
//! use sena_stf::{execute::genesis_credit, Instruction, apply};
//!
//! let mut trie = MerkleTrie::new();
//! let alice = L2Address::from_bytes([1; 32]);
//! genesis_credit(&mut trie, alice, AssetId::NATIVE, 10_000);
//!
//! // Every step is individually disputable, and names the one slot it touches.
//! let step = Instruction::Debit { account: alice, asset: AssetId::NATIVE, amount: 250 };
//! assert_eq!(step.slot(), sena_stf::keys::account(&alice));
//! apply(&mut trie, &step).unwrap();
//! ```

#![doc(html_root_url = "https://docs.rs/sena-stf")]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod account;
pub mod execute;
pub mod instruction;
pub mod keys;
pub mod social;
pub mod transaction;

pub use account::{Account, BalanceError};
pub use execute::{
    apply, compile, execute_batch, transition, verify_step, BatchError, CompileError,
    ExecutionTrace, StepError, StepWitness, FEE_VAULT, FLAT_FEE,
};
pub use instruction::{Instruction, MachineState};
pub use social::{MalformedBinding, SocialBinding};
pub use transaction::{AuthError, Authenticator, Payload, Transaction};
