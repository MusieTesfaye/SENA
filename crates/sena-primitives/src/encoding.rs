//! Canonical, unambiguous byte encoding.
//!
//! Every hash the protocol computes is a commitment to some tuple of fields, and
//! those commitments are compared across independently written implementations —
//! the Rust node and the Move contracts on Aptos L1. Any ambiguity in how a tuple
//! becomes bytes is therefore a consensus bug waiting to happen.
//!
//! The specific hazard is concatenation without framing. Hashing `aud || sub`
//! makes the pairs `("google", "12")` and `("google1", "2")` produce identical
//! preimages, so two distinct users derive the same address. Length-prefixing
//! every field removes that class of collision entirely.

/// Domain separation tags.
///
/// Two different protocol constructions must never produce the same preimage,
/// even when fed the same field values. Prefixing each construction with a
/// unique tag guarantees that a digest computed for one purpose can never be
/// replayed as a valid digest for another.
pub mod domain {
    /// Derivation of an L2 address from OIDC claims (REQ-AUTH-002).
    pub const OIDC_ADDRESS: &[u8] = b"SENA:v1:oidc-address";
    /// Hashing of a human-readable social identifier (REQ-SOCIAL-002).
    pub const SOCIAL_IDENTIFIER: &[u8] = b"SENA:v1:social-identifier";
    /// Interior node of the sparse Merkle trie.
    pub const TRIE_INTERNAL: &[u8] = b"SENA:v1:trie-internal";
    /// Leaf of the sparse Merkle trie.
    pub const TRIE_LEAF: &[u8] = b"SENA:v1:trie-leaf";
    /// Commitment to a batch of transactions.
    pub const BATCH: &[u8] = b"SENA:v1:batch";
    /// Commitment to an assertion posted to Aptos L1.
    pub const ASSERTION: &[u8] = b"SENA:v1:assertion";
    /// Commitment to a machine state within an execution trace.
    pub const MACHINE_STATE: &[u8] = b"SENA:v1:machine-state";
    /// The signing preimage of a transaction.
    pub const TRANSACTION: &[u8] = b"SENA:v1:transaction";
}

/// Accumulates length-prefixed fields into an unambiguous byte string.
///
/// Fields are encoded as a 4-byte big-endian length followed by the bytes. Big
/// endian is chosen deliberately: it is byte-order independent to read, which
/// matters because the Move implementation on Aptos L1 must agree with this one
/// exactly.
///
/// ```
/// use sena_primitives::encoding::{domain, CanonicalEncoder};
///
/// // Framing makes these two field splits distinguishable, where naive
/// // concatenation would not.
/// let a = CanonicalEncoder::new(domain::OIDC_ADDRESS).field(b"google").field(b"12").finish();
/// let b = CanonicalEncoder::new(domain::OIDC_ADDRESS).field(b"google1").field(b"2").finish();
/// assert_ne!(a, b);
/// ```
#[derive(Debug, Clone)]
pub struct CanonicalEncoder {
    buf: Vec<u8>,
}

impl CanonicalEncoder {
    /// Starts an encoding in the given domain.
    #[must_use]
    pub fn new(domain: &[u8]) -> Self {
        let mut enc = Self {
            buf: Vec::with_capacity(64),
        };
        enc.push_framed(domain);
        enc
    }

    /// Appends a length-prefixed field.
    #[must_use]
    pub fn field(mut self, bytes: &[u8]) -> Self {
        self.push_framed(bytes);
        self
    }

    /// Appends a `u64` in big-endian form as a fixed-width field.
    #[must_use]
    pub fn u64(self, value: u64) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Appends a `u128` in big-endian form as a fixed-width field.
    #[must_use]
    pub fn u128(self, value: u128) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Returns the accumulated bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn push_framed(&mut self, bytes: &[u8]) {
        // A field longer than u32::MAX cannot arise: every caller encodes either
        // a fixed-width integer, a 32-byte digest, or an identifier whose length
        // the transaction size limit bounds far below 4 GiB.
        let len = u32::try_from(bytes.len()).expect("field exceeds u32::MAX bytes");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_disambiguates_field_boundaries() {
        let a = CanonicalEncoder::new(b"d")
            .field(b"ab")
            .field(b"c")
            .finish();
        let b = CanonicalEncoder::new(b"d")
            .field(b"a")
            .field(b"bc")
            .finish();
        assert_ne!(a, b, "concatenation must not be ambiguous");
    }

    #[test]
    fn distinct_domains_never_share_a_preimage() {
        let a = CanonicalEncoder::new(domain::OIDC_ADDRESS)
            .field(b"x")
            .finish();
        let b = CanonicalEncoder::new(domain::SOCIAL_IDENTIFIER)
            .field(b"x")
            .finish();
        assert_ne!(
            a, b,
            "domain separation must hold for identical field values"
        );
    }

    #[test]
    fn empty_field_is_distinguishable_from_absent_field() {
        let with_empty = CanonicalEncoder::new(b"d").field(b"").finish();
        let without = CanonicalEncoder::new(b"d").finish();
        assert_ne!(with_empty, without);
    }

    #[test]
    fn integers_encode_big_endian() {
        let got = CanonicalEncoder::new(b"").u64(1).finish();
        assert!(got.ends_with(&[0, 0, 0, 0, 0, 0, 0, 1]));
    }
}
