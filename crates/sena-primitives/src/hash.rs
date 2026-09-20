//! The 32-byte digest used throughout the protocol.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::encoding::CanonicalEncoder;

/// A 32-byte SHA-256 digest.
///
/// SHA-256 is used rather than a faster modern hash because the Move contracts
/// on Aptos L1 must recompute these digests during dispute resolution, and
/// SHA-256 is available there as a native, cheaply-priced primitive.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// The all-zero digest, used as the empty-subtree sentinel in the trie.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hashes a byte string.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Hashes the output of a canonical encoding.
    #[must_use]
    pub fn commit(encoder: CanonicalEncoder) -> Self {
        Self::digest(&encoder.finish())
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the digest as a lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 64-character lowercase or uppercase hex string.
    ///
    /// # Errors
    ///
    /// Returns [`HashParseError`] if the string is not hexadecimal or does not
    /// decode to exactly 32 bytes.
    pub fn from_hex(s: &str) -> Result<Self, HashParseError> {
        let bytes = hex::decode(s).map_err(|_| HashParseError::NotHex)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| HashParseError::WrongLength)?;
        Ok(Self(arr))
    }

    /// Returns the bit at `index`, counting from the most significant bit of the
    /// first byte. This is the bit order the sparse Merkle trie descends in, so
    /// a key's path through the tree reads left to right like the hex string.
    #[must_use]
    pub fn bit(&self, index: usize) -> bool {
        debug_assert!(index < 256, "bit index out of range");
        let byte = self.0[index / 8];
        (byte >> (7 - (index % 8))) & 1 == 1
    }
}

/// Why a hex string could not be parsed as a [`Hash256`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HashParseError {
    /// The string contained non-hex characters.
    #[error("value is not valid hexadecimal")]
    NotHex,
    /// The string did not decode to exactly 32 bytes.
    #[error("value did not decode to exactly 32 bytes")]
    WrongLength,
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full digests make test output unreadable; the first 8 hex characters
        // are ample to tell two roots apart while debugging.
        write!(f, "Hash256({}…)", &self.to_hex()[..8])
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Hash256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_sha256_test_vector() {
        // NIST FIPS 180-4 example: SHA-256("abc").
        assert_eq!(
            Hash256::digest(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_round_trips() {
        let h = Hash256::digest(b"round trip");
        assert_eq!(Hash256::from_hex(&h.to_hex()).unwrap(), h);
    }

    #[test]
    fn rejects_malformed_hex() {
        assert_eq!(Hash256::from_hex("zz").unwrap_err(), HashParseError::NotHex);
        assert_eq!(
            Hash256::from_hex("abcd").unwrap_err(),
            HashParseError::WrongLength
        );
    }

    #[test]
    fn bits_read_most_significant_first() {
        let h = Hash256([0b1010_0000; 32]);
        assert!(h.bit(0));
        assert!(!h.bit(1));
        assert!(h.bit(2));
        assert!(!h.bit(3));
    }

    #[test]
    fn serde_uses_hex_representation() {
        let h = Hash256::digest(b"x");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", h.to_hex()));
        assert_eq!(serde_json::from_str::<Hash256>(&json).unwrap(), h);
    }

    #[test]
    fn determinism_digest_is_stable_across_calls() {
        // Guards against any future dependence on process-local state such as a
        // randomly seeded hasher (REQ-FRAUD-031).
        let a = Hash256::digest(b"stability");
        let b = Hash256::digest(b"stability");
        println!("root={a}");
        assert_eq!(a, b);
    }
}
