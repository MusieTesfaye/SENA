//! Transaction admission.
//!
//! The mempool is where invalid transactions are filtered, and that is a
//! consensus-relevant responsibility rather than an optimisation. The state
//! transition function rejects a whole batch if any transaction in it cannot
//! execute (see [`sena_stf::execute_batch`]), which keeps a verifier's rule
//! unambiguous but means the sequencer must not include anything it has not
//! checked.
//!
//! Admission therefore runs the same compilation and execution the batch will,
//! against a speculative copy of the state, and drops anything that fails.

use std::collections::BTreeMap;

use sena_primitives::{Hash256, L2Address};
use sena_state::MerkleTrie;
use sena_stf::{execute_batch, Transaction};

/// Why a transaction was not admitted.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RejectReason {
    /// The transaction is already queued.
    #[error("transaction is already in the pool")]
    Duplicate,
    /// The pool is full.
    #[error("mempool is full")]
    Full,
    /// The transaction would not execute against the speculative state.
    #[error("transaction would not execute: {reason}")]
    WouldNotExecute {
        /// The failure, rendered for the submitter.
        reason: String,
    },
    /// The sender already has a queued transaction with this nonce.
    #[error("nonce {nonce} is already queued for this sender")]
    NonceQueued {
        /// The conflicting nonce.
        nonce: u64,
    },
}

/// A queue of transactions awaiting inclusion.
#[derive(Clone, Debug)]
pub struct Mempool {
    /// Queued transactions in arrival order. Ordering is explicit rather than
    /// incidental: a verifier replays the batch exactly as published, so
    /// whatever order the sequencer chooses must be reproducible.
    queued: Vec<Transaction>,
    /// Nonces already claimed by queued transactions, by sender.
    claimed: BTreeMap<L2Address, Vec<u64>>,
    capacity: usize,
}

impl Mempool {
    /// Creates an empty pool.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            queued: Vec::new(),
            claimed: BTreeMap::new(),
            capacity,
        }
    }

    /// Returns how many transactions are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queued.len()
    }

    /// Returns whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    /// Returns the queued transactions.
    #[must_use]
    pub fn queued(&self) -> &[Transaction] {
        &self.queued
    }

    /// Offers a transaction to the pool, checking it against `state`.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason`] if the transaction is a duplicate, the pool is
    /// full, or it would not execute after everything already queued.
    pub fn submit(
        &mut self,
        state: &MerkleTrie,
        transaction: Transaction,
    ) -> Result<Hash256, RejectReason> {
        if self.queued.len() >= self.capacity {
            return Err(RejectReason::Full);
        }
        let hash = transaction.hash();
        if self.queued.iter().any(|t| t.hash() == hash) {
            return Err(RejectReason::Duplicate);
        }
        if let Some(nonces) = self.claimed.get(&transaction.sender) {
            if nonces.contains(&transaction.nonce) {
                return Err(RejectReason::NonceQueued {
                    nonce: transaction.nonce,
                });
            }
        }

        // Execute the whole pending batch plus this candidate against a
        // throwaway copy. Checking the candidate alone would miss a transaction
        // that only becomes invalid because of what is already queued -- a
        // sender spending the same balance twice, for instance.
        let mut speculative = state.clone();
        let mut candidate_batch = self.queued.clone();
        candidate_batch.push(transaction.clone());
        if let Err(error) = execute_batch(&mut speculative, &candidate_batch) {
            return Err(RejectReason::WouldNotExecute {
                reason: error.to_string(),
            });
        }

        self.claimed
            .entry(transaction.sender)
            .or_default()
            .push(transaction.nonce);
        self.queued.push(transaction);
        Ok(hash)
    }

    /// Removes and returns up to `limit` transactions for inclusion in a batch.
    pub fn take_batch(&mut self, limit: usize) -> Vec<Transaction> {
        let taken: Vec<_> = self.queued.drain(..limit.min(self.queued.len())).collect();
        for transaction in &taken {
            if let Some(nonces) = self.claimed.get_mut(&transaction.sender) {
                nonces.retain(|n| *n != transaction.nonce);
            }
        }
        self.claimed.retain(|_, nonces| !nonces.is_empty());
        taken
    }

    /// Drops every queued transaction.
    ///
    /// Used after a rollback, when the state the pool validated against no
    /// longer exists.
    pub fn clear(&mut self) {
        self.queued.clear();
        self.claimed.clear();
    }
}
