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
//!
//! The pool keeps the state after its whole queue (the *tip*) and checks a
//! candidate against that alone, so admission costs one transaction's
//! execution rather than the queue's. Executing a batch is executing its
//! transactions in order, so this is the same check.

use std::collections::{BTreeMap, BTreeSet};

use sena_primitives::{Hash256, L2Address};
use sena_state::MerkleTrie;
use sena_stf::{execute_batch, BatchContext, Transaction};

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

/// The state after the queue, and the root before each queued transaction.
#[derive(Clone, Debug)]
struct Tip {
    /// `roots[i]` is the state root before `queued[i]`; the last entry is
    /// the root of `state`. `roots[0]` is the base state the queue builds on.
    roots: Vec<Hash256>,
    state: MerkleTrie,
}

/// A queue of transactions awaiting inclusion.
#[derive(Clone, Debug)]
pub struct Mempool {
    /// Queued transactions in arrival order. Ordering is explicit rather than
    /// incidental: a verifier replays the batch exactly as published, so
    /// whatever order the sequencer chooses must be reproducible.
    queued: Vec<Transaction>,
    /// Hashes of the queued transactions.
    hashes: BTreeSet<Hash256>,
    /// The speculative state after the queue, if known.
    tip: Option<Tip>,
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
            hashes: BTreeSet::new(),
            tip: None,
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
        ctx: &BatchContext<'_>,
        transaction: Transaction,
    ) -> Result<Hash256, RejectReason> {
        if self.queued.len() >= self.capacity {
            return Err(RejectReason::Full);
        }
        let hash = transaction.hash();
        if self.hashes.contains(&hash) {
            return Err(RejectReason::Duplicate);
        }
        if let Some(nonces) = self.claimed.get(&transaction.sender) {
            if nonces.contains(&transaction.nonce) {
                return Err(RejectReason::NonceQueued {
                    nonce: transaction.nonce,
                });
            }
        }

        // Execute the candidate after everything already queued. Checking it
        // against `state` alone would miss a transaction that only becomes
        // invalid because of what is queued -- a sender spending the same
        // balance twice, for instance.
        let tip = self.tip_over(state, ctx);
        let mut speculative = tip.state.clone();
        if let Err(error) = execute_batch(&mut speculative, ctx, std::slice::from_ref(&transaction))
        {
            return Err(RejectReason::WouldNotExecute {
                reason: error.to_string(),
            });
        }
        tip.roots.push(speculative.root());
        tip.state = speculative;
        self.hashes.insert(hash);

        self.claimed
            .entry(transaction.sender)
            .or_default()
            .push(transaction.nonce);
        self.queued.push(transaction);
        Ok(hash)
    }

    /// The tip over `state`, rebuilt if the queue does not build on `state`
    /// (after a block that dropped or reordered queued transactions, say).
    /// Rebuilding drops queued transactions that no longer execute.
    fn tip_over(&mut self, state: &MerkleTrie, ctx: &BatchContext<'_>) -> &mut Tip {
        let valid = self.tip.as_ref().is_some_and(|t| {
            t.roots.first() == Some(&state.root()) && t.roots.len() == self.queued.len() + 1
        });
        if !valid {
            let mut tip = Tip {
                roots: vec![state.root()],
                state: state.clone(),
            };
            let mut kept = Vec::with_capacity(self.queued.len());
            for transaction in std::mem::take(&mut self.queued) {
                let mut next = tip.state.clone();
                if execute_batch(&mut next, ctx, std::slice::from_ref(&transaction)).is_ok() {
                    tip.roots.push(next.root());
                    tip.state = next;
                    kept.push(transaction);
                }
            }
            self.queued = kept;
            self.reindex();
            self.tip = Some(tip);
        }
        self.tip.as_mut().expect("just set")
    }

    /// Rebuilds the hash and nonce indexes from the queue.
    fn reindex(&mut self) {
        self.hashes = self.queued.iter().map(Transaction::hash).collect();
        self.claimed.clear();
        for t in &self.queued {
            self.claimed.entry(t.sender).or_default().push(t.nonce);
        }
    }

    /// Removes and returns up to `limit` transactions for inclusion in a batch.
    pub fn take_batch(&mut self, limit: usize) -> Vec<Transaction> {
        self.take_batch_within(limit, usize::MAX)
    }

    /// Removes and returns the longest prefix of the queue of at most `limit`
    /// transactions whose encodings total at most `max_bytes` — always at
    /// least one transaction if any is queued.
    ///
    /// Only a prefix is ever taken: admission checked each transaction after
    /// everything ahead of it, so a prefix of the queue still executes.
    pub fn take_batch_within(&mut self, limit: usize, max_bytes: usize) -> Vec<Transaction> {
        let mut count = 0;
        let mut size = 0usize;
        for transaction in self.queued.iter().take(limit) {
            size = size.saturating_add(transaction.encode().len());
            if count > 0 && size > max_bytes {
                break;
            }
            count += 1;
        }
        let taken: Vec<_> = self.queued.drain(..count).collect();
        if let Some(tip) = &mut self.tip {
            // The queue now builds on the state after what was taken.
            tip.roots.drain(..count);
        }
        for transaction in &taken {
            self.hashes.remove(&transaction.hash());
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
        self.hashes.clear();
        self.tip = None;
        self.claimed.clear();
    }
}
