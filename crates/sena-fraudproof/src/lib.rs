//! Fraud proofs: bonded assertions, interactive bisection, and one-step
//! adjudication on Aptos L1.
//!
//! This crate is what makes SENA's optimism safe. Without it, a committed state
//! root is only as trustworthy as the sequencer that produced it — a compromised
//! sequencer could commit a root describing balances no honest execution would
//! produce, and users would withdraw against that false record.
//!
//! # The argument, in four steps
//!
//! 1. Every state root is posted as a bonded [`Assertion`] that finalizes only
//!    after a challenge window ([`assertion`]).
//! 2. The batch data is published, so anyone can re-execute and compare
//!    ([`verifier::check_assertion`]).
//! 3. A party who disagrees opens a [`Dispute`], and bisection narrows the
//!    disagreement to one step ([`bisection`]).
//! 4. Aptos L1 executes that step and rules ([`osp::adjudicate`]).
//!
//! An honest party never has to make a false claim at any round, so it cannot
//! lose a dispute it entered correctly. The guarantee that follows is that an
//! invalid root cannot finalize while *one* honest verifier is watching — and
//! the cost is that trust-minimised withdrawal takes a challenge window.
//!
//! # What this does not do
//!
//! It does not defend against every verifier being absent or compromised, nor
//! against Aptos L1 censoring challenge transactions for a whole window. Those
//! are stated in SDD §5.4 and are properties of the model, not gaps in the code.

#![doc(html_root_url = "https://docs.rs/sena-fraudproof")]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod assertion;
pub mod bisection;
pub mod osp;
pub mod verifier;

pub use assertion::{
    Assertion, AssertionChain, AssertionId, ChainError, PartyId, Record, Status,
    CHALLENGE_WINDOW_FLOOR, DEFAULT_CHALLENGE_WINDOW,
};
pub use bisection::{
    clock_budget, Dispute, MoveError, Opening, Party, Resolution, Stage, CLOCK_BUDGET_DIVISOR,
    DEFAULT_ARITY, MOVE_TIMEOUT,
};
pub use osp::{adjudicate, OneStepProof, Verdict, VerdictReason};
pub use verifier::{check_assertion, Finding, PlayError, TracePlayer};
