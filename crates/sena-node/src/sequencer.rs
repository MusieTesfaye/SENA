//! Block production and assertion posting.

use sena_primitives::Hash256;
use sena_state::MerkleTrie;
use sena_stf::{execute_batch, BatchError, ExecutionTrace, Transaction};
use serde::{Deserialize, Serialize};

use sena_fraudproof::{Assertion, AssertionChain, AssertionId, ChainError, PartyId};

use crate::mempool::Mempool;

/// A produced L2 block.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    /// Height, counting from one.
    pub height: u64,
    /// The transactions, in the order they were executed.
    ///
    /// This *is* the published batch data (REQ-FRAUD-007). A verifier
    /// re-executes exactly this sequence; anything the sequencer kept to itself
    /// would make its assertion unverifiable, and therefore worthless.
    pub transactions: Vec<Transaction>,
    /// State root before the block.
    pub pre_state_root: Hash256,
    /// State root after it.
    pub post_state_root: Hash256,
    /// The execution trace, retained for the challenge window so the sequencer
    /// can defend its assertion (NFR-REL-004).
    pub trace: ExecutionTrace,
}

impl Block {
    /// Returns the commitment to this block's batch data.
    ///
    /// # Panics
    ///
    /// Panics only if serialisation fails, which cannot occur.
    #[must_use]
    pub fn batch_commitment(&self) -> Hash256 {
        let encoded =
            serde_json::to_vec(&self.transactions).expect("batch serialisation cannot fail");
        Hash256::digest(&encoded)
    }
}

/// A transaction's confirmation status.
///
/// REQ-CORE-005 requires soft confirmation and L1 finality to be kept distinct
/// everywhere they are reported. Collapsing them into one "confirmed" flag is
/// how an integrator ends up releasing goods against a state root that can still
/// be reverted, so the distinction is made in the type rather than in a comment.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Confirmation {
    /// Queued but not yet executed.
    Pending,
    /// Executed and ordered by the sequencer, in seconds — but the covering
    /// assertion has not finalized, so this can still be reverted.
    SoftConfirmed {
        /// The block that included it.
        height: u64,
    },
    /// The covering assertion has finalized on Aptos L1. Irreversible, and
    /// withdrawable against.
    Finalized {
        /// The block that included it.
        height: u64,
    },
}

/// Why block production failed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProduceError {
    /// The batch would not execute.
    ///
    /// Reaching this means mempool admission let something through that the
    /// state transition function rejects, which is a bug in admission rather
    /// than a user error.
    #[error("batch execution failed: {0}")]
    Execution(#[from] BatchError),
    /// The assertion could not be posted.
    #[error("assertion rejected: {0}")]
    Assertion(#[from] ChainError),
}

/// The sequencer: orders transactions, executes them, and asserts the result.
#[derive(Debug)]
pub struct Sequencer {
    /// Canonical L2 state.
    pub state: MerkleTrie,
    /// Pending transactions.
    pub mempool: Mempool,
    /// Blocks produced, oldest first.
    pub blocks: Vec<Block>,
    /// The L1 assertion chain this sequencer posts to.
    pub chain: AssertionChain,
    /// This sequencer's identity on L1.
    pub identity: PartyId,
    /// The bond posted with each assertion.
    pub bond: u128,
    /// The assertion each block is covered by, parallel to `blocks`.
    assertions: Vec<AssertionId>,
    /// Most recent assertion, which the next one builds on.
    head: AssertionId,
}

impl Sequencer {
    /// Creates a sequencer over `state`, posting to `chain`.
    ///
    /// # Panics
    ///
    /// Panics if `chain` has no finalized assertion to build on, which
    /// [`AssertionChain::new`] always provides.
    #[must_use]
    pub fn new(state: MerkleTrie, chain: AssertionChain, identity: PartyId, bond: u128) -> Self {
        let head = chain
            .latest_finalized()
            .expect("a chain always has a finalized genesis")
            .assertion
            .id();
        Self {
            state,
            mempool: Mempool::new(4_096),
            blocks: Vec::new(),
            chain,
            identity,
            bond,
            assertions: Vec::new(),
            head,
        }
    }

    /// Produces a block from up to `limit` queued transactions and posts a
    /// bonded assertion covering it.
    ///
    /// Returns `None` if the mempool is empty.
    ///
    /// # Errors
    ///
    /// Returns [`ProduceError`] if the batch fails to execute or the assertion
    /// is refused by the chain.
    pub fn produce(&mut self, limit: usize) -> Result<Option<(Block, AssertionId)>, ProduceError> {
        let transactions = self.mempool.take_batch(limit);
        if transactions.is_empty() {
            return Ok(None);
        }

        let pre_state_root = self.state.root();

        // Execute against a copy: on failure the canonical state must be left
        // untouched, since execute_batch leaves a partially applied trie behind.
        let mut next = self.state.clone();
        let trace = execute_batch(&mut next, &transactions)?;

        let block = Block {
            height: self.blocks.len() as u64 + 1,
            transactions,
            pre_state_root,
            post_state_root: next.root(),
            trace,
        };

        let assertion = Assertion {
            parent: self.head,
            proposer: self.identity,
            pre_state_root,
            post_state_root: block.post_state_root,
            batch_commitment: block.batch_commitment(),
            trace_length: block.trace.len() as u64,
            bond: self.bond,
        };
        let id = self.chain.post(assertion)?;

        self.state = next;
        self.head = id;
        self.blocks.push(block.clone());
        self.assertions.push(id);
        Ok(Some((block, id)))
    }

    /// Returns the assertion covering a block, if it has one.
    #[must_use]
    pub fn assertion_for(&self, height: u64) -> Option<AssertionId> {
        usize::try_from(height.checked_sub(1)?)
            .ok()
            .and_then(|i| self.assertions.get(i))
            .copied()
    }

    /// Returns the confirmation status of a transaction.
    #[must_use]
    pub fn confirmation(&self, hash: &Hash256) -> Confirmation {
        for block in &self.blocks {
            if block.transactions.iter().any(|t| t.hash() == *hash) {
                let finalized = self
                    .assertion_for(block.height)
                    .and_then(|id| self.chain.status(&id))
                    .is_some_and(|s| s == sena_fraudproof::Status::Finalized);
                return if finalized {
                    Confirmation::Finalized {
                        height: block.height,
                    }
                } else {
                    Confirmation::SoftConfirmed {
                        height: block.height,
                    }
                };
            }
        }
        Confirmation::Pending
    }

    /// Returns the height of the most recent block whose assertion has
    /// finalized on L1 (REQ-CORE-005).
    #[must_use]
    pub fn finalized_height(&self) -> u64 {
        self.blocks
            .iter()
            .rev()
            .find(|block| {
                self.assertion_for(block.height)
                    .and_then(|id| self.chain.status(&id))
                    .is_some_and(|s| s == sena_fraudproof::Status::Finalized)
            })
            .map_or(0, |block| block.height)
    }
}
