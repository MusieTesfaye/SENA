//! The sparse binary Merkle trie holding all L2 state.

use std::collections::BTreeMap;

use sena_primitives::Hash256;

use crate::node::{hash_value, Node};
use crate::proof::{MerkleProof, Terminal, MAX_DEPTH};

/// A Merklized key/value store.
///
/// Keys are 256-bit digests and the trie is descended one key bit per level,
/// most significant bit first. Two properties make it practical:
///
/// - an empty subtree is [`Hash256::ZERO`], so the unoccupied majority of the key
///   space costs nothing to represent;
/// - a leaf is stored at the shallowest depth at which its key is unique, so a
///   trie holding `n` keys has depth around `log2(n)` rather than 256.
///
/// Together these keep proofs small — tens of siblings, not 256 — which matters
/// because every proof is eventually verified inside an Aptos L1 transaction.
///
/// # Determinism
///
/// The node store is a [`BTreeMap`], and the root is a pure function of the
/// key/value set. Two nodes that apply the same writes in the same order get the
/// same root, and — because a trie is order-independent — so do two nodes that
/// apply them in different orders (REQ-FRAUD-031).
///
/// ```
/// use sena_state::MerkleTrie;
/// use sena_primitives::Hash256;
///
/// let mut a = MerkleTrie::new();
/// a.insert(Hash256::digest(b"k1"), b"v1");
/// a.insert(Hash256::digest(b"k2"), b"v2");
///
/// let mut b = MerkleTrie::new();
/// b.insert(Hash256::digest(b"k2"), b"v2");
/// b.insert(Hash256::digest(b"k1"), b"v1");
///
/// assert_eq!(a.root(), b.root(), "the root is independent of insertion order");
/// ```
#[derive(Clone, Debug, Default)]
pub struct MerkleTrie {
    /// Node hash to node. Nodes are never evicted, so historical roots stay
    /// provable for as long as the store is retained — which the challenge
    /// window requires (NFR-REL-004).
    nodes: BTreeMap<Hash256, Node>,
    /// Key to stored value bytes.
    values: BTreeMap<Hash256, Vec<u8>>,
    root: Hash256,
}

impl MerkleTrie {
    /// Creates an empty trie, whose root is [`Hash256::ZERO`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current state root.
    #[must_use]
    pub const fn root(&self) -> Hash256 {
        self.root
    }

    /// Returns the number of keys stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the trie holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the value stored at `key`, if any.
    #[must_use]
    pub fn get(&self, key: &Hash256) -> Option<&[u8]> {
        self.values.get(key).map(Vec::as_slice)
    }

    /// Returns an iterator over every key/value pair, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&Hash256, &[u8])> {
        self.values.iter().map(|(k, v)| (k, v.as_slice()))
    }

    /// Inserts or overwrites `key`, returning the new root.
    pub fn insert(&mut self, key: Hash256, value: impl Into<Vec<u8>>) -> Hash256 {
        let value = value.into();
        let value_hash = hash_value(&value);
        self.values.insert(key, value);
        self.root = self.insert_at(self.root, 0, key, value_hash);
        self.root
    }

    /// Removes `key`, returning the new root. Removing an absent key is a no-op.
    pub fn remove(&mut self, key: &Hash256) -> Hash256 {
        if self.values.remove(key).is_none() {
            return self.root;
        }
        self.root = self.remove_at(self.root, 0, key);
        self.root
    }

    /// Produces a proof for `key`, whether or not it is present.
    ///
    /// The same proof structure answers both questions, so a caller that does not
    /// yet know whether a key exists makes one request rather than two.
    #[must_use]
    pub fn prove(&self, key: &Hash256) -> MerkleProof {
        let mut siblings = Vec::new();
        let mut current = self.root;
        let mut depth = 0;

        loop {
            match self.nodes.get(&current) {
                None => {
                    // Either the empty sentinel or an unknown hash; both mean
                    // there is nothing further down this path.
                    return MerkleProof {
                        siblings,
                        terminal: Terminal::Empty,
                    };
                }
                Some(Node::Leaf { key: k, value_hash }) => {
                    return MerkleProof {
                        siblings,
                        terminal: Terminal::Leaf {
                            key: *k,
                            value_hash: *value_hash,
                        },
                    };
                }
                Some(Node::Internal { left, right }) => {
                    debug_assert!(depth < MAX_DEPTH, "descended past the key length");
                    let go_right = key.bit(depth);
                    let (next, sibling) = if go_right {
                        (*right, *left)
                    } else {
                        (*left, *right)
                    };
                    siblings.push(sibling);
                    current = next;
                    depth += 1;
                }
            }
        }
    }

    fn store(&mut self, node: Node) -> Hash256 {
        let hash = node.hash();
        self.nodes.insert(hash, node);
        hash
    }

    fn insert_at(
        &mut self,
        node_hash: Hash256,
        depth: usize,
        key: Hash256,
        value_hash: Hash256,
    ) -> Hash256 {
        match self.nodes.get(&node_hash).cloned() {
            // Empty slot: the leaf can live right here.
            None => self.store(Node::Leaf { key, value_hash }),

            Some(Node::Leaf {
                key: existing_key,
                value_hash: existing_value,
            }) => {
                if existing_key == key {
                    self.store(Node::Leaf { key, value_hash })
                } else {
                    // Two keys now share this slot, so push both down until the
                    // first bit at which they differ.
                    self.split(depth, key, value_hash, existing_key, existing_value)
                }
            }

            Some(Node::Internal { left, right }) => {
                if key.bit(depth) {
                    let new_right = self.insert_at(right, depth + 1, key, value_hash);
                    self.store(Node::Internal {
                        left,
                        right: new_right,
                    })
                } else {
                    let new_left = self.insert_at(left, depth + 1, key, value_hash);
                    self.store(Node::Internal {
                        left: new_left,
                        right,
                    })
                }
            }
        }
    }

    /// Builds the chain of internal nodes separating two distinct keys.
    fn split(
        &mut self,
        depth: usize,
        key_a: Hash256,
        value_a: Hash256,
        key_b: Hash256,
        value_b: Hash256,
    ) -> Hash256 {
        debug_assert_ne!(key_a, key_b, "split requires distinct keys");
        debug_assert!(
            depth < MAX_DEPTH,
            "distinct 256-bit keys must differ within 256 bits"
        );

        let bit_a = key_a.bit(depth);
        if bit_a == key_b.bit(depth) {
            // Still identical here: descend one level with an empty sibling.
            let child = self.split(depth + 1, key_a, value_a, key_b, value_b);
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
            self.store(node)
        } else {
            let leaf_a = self.store(Node::Leaf {
                key: key_a,
                value_hash: value_a,
            });
            let leaf_b = self.store(Node::Leaf {
                key: key_b,
                value_hash: value_b,
            });
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
            self.store(node)
        }
    }

    fn remove_at(&mut self, node_hash: Hash256, depth: usize, key: &Hash256) -> Hash256 {
        match self.nodes.get(&node_hash).cloned() {
            None => Hash256::ZERO,

            Some(Node::Leaf { key: existing, .. }) => {
                if existing == *key {
                    Hash256::ZERO
                } else {
                    node_hash
                }
            }

            Some(Node::Internal { left, right }) => {
                let (new_left, new_right) = if key.bit(depth) {
                    (left, self.remove_at(right, depth + 1, key))
                } else {
                    (self.remove_at(left, depth + 1, key), right)
                };

                // Collapse a branch that no longer needs to exist. Without this
                // the root would depend on deletion history rather than only on
                // the current key set, and two nodes reaching the same state by
                // different routes would disagree.
                match (self.lone_child(new_left, new_right), new_left, new_right) {
                    (Some(surviving_leaf), _, _) => surviving_leaf,
                    (None, l, r) if l == Hash256::ZERO && r == Hash256::ZERO => Hash256::ZERO,
                    (None, l, r) => self.store(Node::Internal { left: l, right: r }),
                }
            }
        }
    }

    /// If exactly one child is a non-empty leaf and the other is empty, returns
    /// that leaf so the parent can be collapsed into it.
    fn lone_child(&self, left: Hash256, right: Hash256) -> Option<Hash256> {
        let candidate = match (left == Hash256::ZERO, right == Hash256::ZERO) {
            (true, false) => right,
            (false, true) => left,
            _ => return None,
        };
        matches!(self.nodes.get(&candidate), Some(Node::Leaf { .. })).then_some(candidate)
    }
}
