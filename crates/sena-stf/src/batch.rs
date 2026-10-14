//! The batch commitment an assertion carries.
//!
//! When a dispute narrows to step `pc`, Aptos L1 must know which instruction
//! sits there. It cannot hold the whole batch, so the commitment is a Merkle
//! tree whose leaves let a single transaction be proven in isolation:
//!
//! ```text
//! leaf_i  = H(BATCH_LEAF, i, start_pc_i, tx_bytes_i)
//! node    = H(BATCH_NODE, left, right)          (padded with zero hashes)
//! header  = H(BATCH, timestamp, tx_count, root)
//! ```
//!
//! `start_pc_i` is where transaction `i`'s instructions begin in the trace.
//! L1 compiles the proven transaction itself (compilation is a pure function of
//! the transaction and the batch context), so the leaf plus its proof is enough
//! to recover the instruction at any `pc` in `[start_pc_i, start_pc_i + len)`.
//!
//! A sequencer could commit to inconsistent `start_pc`s. That is detectable
//! from two adjacent leaves and is itself fraud; see the batch-structure proofs
//! in `move/sena/sources/disputes.move`.

use sena_primitives::{domain, CanonicalEncoder, Hash256};
use serde::{Deserialize, Serialize};

/// Domain tag for a batch leaf.
const BATCH_LEAF: &[u8] = b"SENA:v1:batch-leaf";
/// Domain tag for an interior batch node.
const BATCH_NODE: &[u8] = b"SENA:v1:batch-node";

/// The hash of one transaction's leaf.
#[must_use]
pub fn leaf_hash(index: u64, start_pc: u64, tx_bytes: &[u8]) -> Hash256 {
    Hash256::commit(
        CanonicalEncoder::new(BATCH_LEAF)
            .u64(index)
            .u64(start_pc)
            .field(tx_bytes),
    )
}

fn node_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    Hash256::commit(
        CanonicalEncoder::new(BATCH_NODE)
            .field(left.as_bytes())
            .field(right.as_bytes()),
    )
}

/// The batch header commitment, as `sena::assertions::post` recomputes it.
#[must_use]
pub fn header_commitment(timestamp: u64, tx_count: u64, tx_root: &Hash256) -> Hash256 {
    Hash256::commit(
        CanonicalEncoder::new(domain::BATCH)
            .u64(timestamp)
            .u64(tx_count)
            .field(tx_root.as_bytes()),
    )
}

/// A Merkle path from one leaf to the batch root.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LeafProof {
    /// The leaf's index.
    pub index: u64,
    /// Sibling hashes from the leaf upwards.
    pub siblings: Vec<Hash256>,
}

impl LeafProof {
    /// The root this path implies for `leaf`.
    #[must_use]
    pub fn root_for(&self, leaf: &Hash256) -> Hash256 {
        let mut node = *leaf;
        let mut index = self.index;
        for sibling in &self.siblings {
            node = if index & 1 == 0 {
                node_hash(&node, sibling)
            } else {
                node_hash(sibling, &node)
            };
            index >>= 1;
        }
        node
    }
}

/// A batch's commitment tree, built by the sequencer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BatchTree {
    /// Levels from the leaves (padded to a power of two) up to the root.
    levels: Vec<Vec<Hash256>>,
    tx_count: u64,
}

impl BatchTree {
    /// Builds the tree over `(start_pc, tx_bytes)` pairs, in batch order.
    ///
    /// # Panics
    ///
    /// Panics on more than `u64::MAX` transactions, which no batch can hold.
    #[must_use]
    pub fn build(leaves: &[(u64, Vec<u8>)]) -> Self {
        let mut level: Vec<Hash256> = leaves
            .iter()
            .enumerate()
            .map(|(i, (start_pc, bytes))| {
                leaf_hash(u64::try_from(i).expect("index fits"), *start_pc, bytes)
            })
            .collect();
        let tx_count = u64::try_from(level.len()).expect("count fits");
        let width = level.len().max(1).next_power_of_two();
        level.resize(width, Hash256::ZERO);
        let mut levels = vec![level];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let below = levels.last().expect("non-empty");
            let above = below
                .chunks(2)
                .map(|pair| node_hash(&pair[0], &pair[1]))
                .collect();
            levels.push(above);
        }
        Self { levels, tx_count }
    }

    /// The tree's root.
    ///
    /// # Panics
    ///
    /// Does not panic: a tree always has a root level.
    #[must_use]
    pub fn root(&self) -> Hash256 {
        self.levels.last().expect("a root level")[0]
    }

    /// How many transactions the tree commits to.
    #[must_use]
    pub const fn tx_count(&self) -> u64 {
        self.tx_count
    }

    /// The path for leaf `index`, or `None` past the end.
    #[must_use]
    pub fn prove(&self, index: u64) -> Option<LeafProof> {
        if index >= self.tx_count {
            return None;
        }
        let mut i = usize::try_from(index).ok()?;
        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in &self.levels[..self.levels.len() - 1] {
            siblings.push(level[i ^ 1]);
            i >>= 1;
        }
        Some(LeafProof { index, siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: u64) -> Vec<(u64, Vec<u8>)> {
        (0..n)
            .map(|i| (i * 4, vec![u8::try_from(i).unwrap(); 3]))
            .collect()
    }

    #[test]
    fn every_leaf_proves_against_the_root() {
        for n in 1..=9 {
            let l = leaves(n);
            let tree = BatchTree::build(&l);
            for (i, (start, bytes)) in l.iter().enumerate() {
                let i = i as u64;
                let proof = tree.prove(i).unwrap();
                assert_eq!(
                    proof.root_for(&leaf_hash(i, *start, bytes)),
                    tree.root(),
                    "n={n} i={i}"
                );
            }
            assert!(tree.prove(n).is_none());
        }
    }

    #[test]
    fn a_leaf_cannot_be_proven_at_another_position() {
        let l = leaves(4);
        let tree = BatchTree::build(&l);
        let mut proof = tree.prove(1).unwrap();
        proof.index = 2;
        assert_ne!(proof.root_for(&leaf_hash(1, l[1].0, &l[1].1)), tree.root());
        // Nor with its index rewritten in the leaf.
        let proof = tree.prove(2).unwrap();
        assert_ne!(proof.root_for(&leaf_hash(2, l[1].0, &l[1].1)), tree.root());
    }

    #[test]
    fn a_single_transaction_batch_is_its_own_root() {
        let l = leaves(1);
        let tree = BatchTree::build(&l);
        assert_eq!(tree.root(), leaf_hash(0, l[0].0, &l[0].1));
        assert!(tree.prove(0).unwrap().siblings.is_empty());
    }
}
