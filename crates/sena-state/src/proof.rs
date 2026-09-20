//! Inclusion and non-inclusion proofs against a state root.
//!
//! These proofs are the interface between the L2 and Aptos L1. A user
//! withdrawing after a sequencer failure presents one to the bridge contract, and
//! a One-Step Proof carries several to show what state a disputed instruction
//! read. The verifier therefore has to be simple enough to reimplement in Move
//! and strict enough that nothing can be smuggled past it.

use sena_primitives::Hash256;
use serde::{Deserialize, Serialize};

use crate::node::{hash_value, Node};

/// The maximum depth of the trie, one level per key bit.
pub const MAX_DEPTH: usize = 256;

/// What the proof path ends in.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Terminal {
    /// The path ends in an empty subtree: no key with this prefix is present.
    Empty,
    /// The path ends in a leaf, which may or may not be the queried key.
    Leaf {
        /// The key actually stored at this position.
        key: Hash256,
        /// Digest of the value stored there.
        value_hash: Hash256,
    },
}

/// A proof that some key does or does not hold some value under a given root.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Sibling hashes along the path, ordered root-first. The length is the
    /// depth at which the terminal sits.
    pub siblings: Vec<Hash256>,
    /// The node the path terminates in.
    pub terminal: Terminal,
}

/// Why a proof was rejected.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProofError {
    /// The path is longer than the key has bits.
    #[error("proof depth {0} exceeds the {MAX_DEPTH}-bit key length")]
    TooDeep(usize),
    /// Recomputing the path did not reproduce the claimed root.
    #[error("recomputed root {computed} does not match expected root {expected}")]
    RootMismatch {
        /// The root the proof reconstructs to.
        computed: Hash256,
        /// The root it was checked against.
        expected: Hash256,
    },
    /// The terminal leaf does not lie on the queried key's path.
    #[error("terminal leaf diverges from the queried key at depth {0}, above the proof's depth")]
    LeafOffPath(usize),
    /// An inclusion proof was expected but the path ends empty.
    #[error("key is absent: the path terminates in an empty subtree")]
    KeyAbsent,
    /// An inclusion proof was expected but a different key sits at the terminal.
    #[error("key is absent: a different key occupies the terminal position")]
    DifferentKey,
    /// The value proved does not match the value expected.
    #[error("value digest {found} does not match expected {expected}")]
    ValueMismatch {
        /// The digest committed to in the trie.
        found: Hash256,
        /// The digest the caller expected.
        expected: Hash256,
    },
    /// A non-inclusion proof was expected but the key is present.
    #[error("key is present, so it cannot be proved absent")]
    KeyPresent,
}

impl MerkleProof {
    /// Reconstructs the root this proof implies for `key`.
    ///
    /// Reconstruction walks back up from the terminal, folding in one sibling per
    /// level. Crucially it uses the **queried** key's bits to decide whether the
    /// running hash is the left or right child at each level. A prover who
    /// supplies a terminal or siblings from elsewhere in the tree therefore
    /// reconstructs some root other than the real one, and the comparison in
    /// [`Self::verify_inclusion`] rejects it.
    fn reconstruct_root(&self, key: &Hash256) -> Result<Hash256, ProofError> {
        let depth = self.siblings.len();
        if depth > MAX_DEPTH {
            return Err(ProofError::TooDeep(depth));
        }

        if let Terminal::Leaf { key: leaf_key, .. } = &self.terminal {
            // The terminal leaf must lie on the queried key's path, i.e. agree
            // with it on every bit consumed getting here. Reconstruction would
            // usually catch a violation anyway, but checking explicitly keeps
            // the failure legible and does not rely on a hash collision argument.
            for i in 0..depth {
                if leaf_key.bit(i) != key.bit(i) {
                    return Err(ProofError::LeafOffPath(i));
                }
            }
        }

        let mut running = match &self.terminal {
            Terminal::Empty => Hash256::ZERO,
            Terminal::Leaf { key, value_hash } => Node::Leaf {
                key: *key,
                value_hash: *value_hash,
            }
            .hash(),
        };

        // Fold upward: the deepest sibling is the last element.
        for level in (0..depth).rev() {
            let sibling = self.siblings[level];
            let node = if key.bit(level) {
                Node::Internal {
                    left: sibling,
                    right: running,
                }
            } else {
                Node::Internal {
                    left: running,
                    right: sibling,
                }
            };
            running = node.hash();
        }

        Ok(running)
    }

    /// Verifies that `key` maps to `value` under `root`.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] if the path does not reconstruct to `root`, if the
    /// key is absent, or if it holds a different value.
    pub fn verify_inclusion(
        &self,
        root: &Hash256,
        key: &Hash256,
        value: &[u8],
    ) -> Result<(), ProofError> {
        self.verify_inclusion_hashed(root, key, &hash_value(value))
    }

    /// Verifies inclusion against a value digest rather than the value itself.
    ///
    /// The bridge and the one-step verifier work from digests, since they check
    /// what a step read without needing the bytes themselves.
    /// # Errors
    ///
    /// Returns [`ProofError`] if the path does not reconstruct to `root`, if the
    /// key is absent, or if the stored digest differs from `value_hash`.
    pub fn verify_inclusion_hashed(
        &self,
        root: &Hash256,
        key: &Hash256,
        value_hash: &Hash256,
    ) -> Result<(), ProofError> {
        let computed = self.reconstruct_root(key)?;
        if computed != *root {
            return Err(ProofError::RootMismatch {
                computed,
                expected: *root,
            });
        }
        match &self.terminal {
            Terminal::Empty => Err(ProofError::KeyAbsent),
            Terminal::Leaf { key: leaf_key, .. } if leaf_key != key => {
                Err(ProofError::DifferentKey)
            }
            Terminal::Leaf {
                value_hash: found, ..
            } => {
                if found == value_hash {
                    Ok(())
                } else {
                    Err(ProofError::ValueMismatch {
                        found: *found,
                        expected: *value_hash,
                    })
                }
            }
        }
    }

    /// Computes the root that results from writing `new_value_hash` at `key`,
    /// given a proof of that key's current state.
    ///
    /// This is what lets Aptos L1 adjudicate a disputed step without holding the
    /// state. The L1 contract has a pre-state root and a proof of the slot the
    /// step touches; from those alone it can derive the post-state root the step
    /// should have produced, and compare it against what the sequencer claimed.
    ///
    /// Three cases arise, and the third is the subtle one:
    ///
    /// - the slot is empty, so the new leaf takes the terminal position;
    /// - the slot holds this key, so the leaf's value is replaced;
    /// - the slot holds a *different* key, which means the tree has to grow. The
    ///   two keys share a prefix down to the terminal depth, so a chain of
    ///   internal nodes with empty siblings is built until they diverge, and
    ///   both leaves are placed there.
    ///
    /// Note that this only covers writes and insertions, never removals. That is
    /// not an oversight: removing a key can require collapsing a branch, which
    /// depends on the shape of a subtree the proof does not describe. The state
    /// transition function is therefore structurally append-only — releasing a
    /// social binding writes a vacant marker rather than deleting the entry — so
    /// this function is sufficient for every step the L1 verifier must check.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError`] if the proof is malformed or the terminal leaf does
    /// not lie on the queried key's path. The caller is responsible for first
    /// checking that the proof reconstructs to the expected pre-state root.
    pub fn compute_updated_root(
        &self,
        key: &Hash256,
        new_value_hash: &Hash256,
    ) -> Result<Hash256, ProofError> {
        let depth = self.siblings.len();
        if depth > MAX_DEPTH {
            return Err(ProofError::TooDeep(depth));
        }

        let mut running = match &self.terminal {
            Terminal::Empty => Node::Leaf {
                key: *key,
                value_hash: *new_value_hash,
            }
            .hash(),
            Terminal::Leaf { key: existing, .. } if existing == key => Node::Leaf {
                key: *key,
                value_hash: *new_value_hash,
            }
            .hash(),
            Terminal::Leaf {
                key: existing,
                value_hash: existing_value,
            } => {
                for i in 0..depth {
                    if existing.bit(i) != key.bit(i) {
                        return Err(ProofError::LeafOffPath(i));
                    }
                }
                split_hash(depth, key, new_value_hash, existing, existing_value)?
            }
        };

        for level in (0..depth).rev() {
            let sibling = self.siblings[level];
            running = if key.bit(level) {
                Node::Internal {
                    left: sibling,
                    right: running,
                }
            } else {
                Node::Internal {
                    left: running,
                    right: sibling,
                }
            }
            .hash();
        }

        Ok(running)
    }

    /// Verifies that `key` is absent under `root`.
    ///
    /// Absence is provable two ways: the path runs into an empty subtree, or it
    /// runs into a leaf holding a different key. The second case is what makes
    /// the tree compact — a leaf sits as high as it can, so a query for a key
    /// sharing its prefix terminates there rather than at a full-depth empty slot.
    /// # Errors
    ///
    /// Returns [`ProofError`] if the path does not reconstruct to `root`, or if
    /// the key turns out to be present.
    pub fn verify_non_inclusion(&self, root: &Hash256, key: &Hash256) -> Result<(), ProofError> {
        let computed = self.reconstruct_root(key)?;
        if computed != *root {
            return Err(ProofError::RootMismatch {
                computed,
                expected: *root,
            });
        }
        match &self.terminal {
            Terminal::Empty => Ok(()),
            Terminal::Leaf { key: leaf_key, .. } if leaf_key != key => Ok(()),
            Terminal::Leaf { .. } => Err(ProofError::KeyPresent),
        }
    }
}

/// Builds the subtree separating two distinct keys that share a prefix down to
/// `depth`, returning its hash.
///
/// Pure by design: the L1 verifier has no node store, so the whole subtree has
/// to be derivable from the two leaves alone.
fn split_hash(
    depth: usize,
    key_a: &Hash256,
    value_a: &Hash256,
    key_b: &Hash256,
    value_b: &Hash256,
) -> Result<Hash256, ProofError> {
    if depth >= MAX_DEPTH {
        // Unreachable for distinct 256-bit keys, but the recursion is bounded
        // explicitly rather than by argument.
        return Err(ProofError::TooDeep(depth));
    }

    let bit_a = key_a.bit(depth);
    if bit_a == key_b.bit(depth) {
        let child = split_hash(depth + 1, key_a, value_a, key_b, value_b)?;
        let node = if bit_a {
            Node::Internal {
                left: Hash256::ZERO,
                right: child,
            }
        } else {
            Node::Internal {
                left: child,
                right: Hash256::ZERO,
            }
        };
        Ok(node.hash())
    } else {
        let leaf_a = Node::Leaf {
            key: *key_a,
            value_hash: *value_a,
        }
        .hash();
        let leaf_b = Node::Leaf {
            key: *key_b,
            value_hash: *value_b,
        }
        .hash();
        let node = if bit_a {
            Node::Internal {
                left: leaf_b,
                right: leaf_a,
            }
        } else {
            Node::Internal {
                left: leaf_a,
                right: leaf_b,
            }
        };
        Ok(node.hash())
    }
}
