//! Trie nodes and their hashing rules.

use sena_primitives::{domain, CanonicalEncoder, Hash256};
use serde::{Deserialize, Serialize};

/// A node in the sparse binary trie.
///
/// There is no explicit empty node: an empty subtree is represented by
/// [`Hash256::ZERO`], which lets the tree stay sparse without storing anything
/// for the overwhelming majority of the 2^256 key space that is unoccupied.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Node {
    /// A branch with two children, either of which may be the empty sentinel.
    Internal {
        /// Subtree of keys whose bit at this depth is 0.
        left: Hash256,
        /// Subtree of keys whose bit at this depth is 1.
        right: Hash256,
    },
    /// A key/value binding, placed at the shallowest depth at which its key is
    /// unique among the keys present.
    Leaf {
        /// The full key. Committing to it is what makes the leaf's position
        /// verifiable; see [`Node::hash`].
        key: Hash256,
        /// Digest of the stored value.
        value_hash: Hash256,
    },
}

impl Node {
    /// Returns this node's hash.
    ///
    /// A leaf commits to its **whole** key, not only to its value. Without that,
    /// a leaf sitting high in the tree would be valid at any position below it,
    /// and a prover could relocate a genuine leaf to answer a query about a
    /// different key. Committing to the key pins each leaf to exactly one path.
    ///
    /// Internal and leaf nodes are hashed in different domains, so a digest can
    /// never be reinterpreted as the other kind of node.
    #[must_use]
    pub fn hash(&self) -> Hash256 {
        match self {
            Self::Internal { left, right } => Hash256::commit(
                CanonicalEncoder::new(domain::TRIE_INTERNAL)
                    .field(left.as_bytes())
                    .field(right.as_bytes()),
            ),
            Self::Leaf { key, value_hash } => Hash256::commit(
                CanonicalEncoder::new(domain::TRIE_LEAF)
                    .field(key.as_bytes())
                    .field(value_hash.as_bytes()),
            ),
        }
    }
}

/// Hashes a stored value.
#[must_use]
pub fn hash_value(value: &[u8]) -> Hash256 {
    Hash256::digest(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_commits_to_its_key() {
        let a = Node::Leaf {
            key: Hash256::digest(b"k1"),
            value_hash: Hash256::digest(b"v"),
        };
        let b = Node::Leaf {
            key: Hash256::digest(b"k2"),
            value_hash: Hash256::digest(b"v"),
        };
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn internal_is_order_sensitive() {
        let l = Hash256::digest(b"l");
        let r = Hash256::digest(b"r");
        let a = Node::Internal { left: l, right: r };
        let b = Node::Internal { left: r, right: l };
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn leaf_and_internal_domains_are_separated() {
        let x = Hash256::digest(b"x");
        let y = Hash256::digest(b"y");
        let leaf = Node::Leaf {
            key: x,
            value_hash: y,
        };
        let internal = Node::Internal { left: x, right: y };
        assert_ne!(leaf.hash(), internal.hash());
    }
}
