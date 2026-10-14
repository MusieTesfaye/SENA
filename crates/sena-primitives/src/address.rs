//! Account addresses and asset identifiers.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{domain, CanonicalEncoder};
use crate::hash::{Hash256, HashParseError};

/// A 32-byte account address on the SENA L2.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct L2Address(pub [u8; 32]);

impl L2Address {
    /// Derives the address of a keyless account (REQ-AUTH-002).
    ///
    /// A keyless account is identified, as in Aptos Keyless (AIP-61), by its
    /// issuer and an *identity commitment*:
    ///
    /// - `iss_hash` is the Poseidon hash of the OIDC issuer string, padded as
    ///   the circuit pads it, as a 32-byte little-endian field element;
    /// - `idc` is `Poseidon(pepper, H(aud), H(uid_val), H(uid_key))`, also a
    ///   little-endian field element.
    ///
    /// The commitment hides the user's identity behind a high-entropy pepper,
    /// and scopes it to the application (`aud`), so the same person signing in
    /// to two applications receives two unlinkable addresses. Both inputs are
    /// public inputs of the zero-knowledge proof, which is how the proof binds
    /// a JWT to exactly this address.
    ///
    /// ```
    /// use sena_primitives::L2Address;
    ///
    /// let a = L2Address::derive_keyless(&[1; 32], &[2; 32]);
    /// let b = L2Address::derive_keyless(&[1; 32], &[3; 32]);
    /// assert_ne!(a, b, "a different commitment is a different account");
    /// ```
    #[must_use]
    pub fn derive_keyless(iss_hash: &[u8; 32], idc: &[u8; 32]) -> Self {
        let digest = Hash256::commit(
            CanonicalEncoder::new(domain::KEYLESS_ADDRESS)
                .field(iss_hash)
                .field(idc),
        );
        Self(digest.0)
    }

    /// Wraps raw address bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the address as a `0x`-prefixed lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parses a hex address, with or without a `0x` prefix.
    ///
    /// # Errors
    ///
    /// Returns [`HashParseError`] if the body is not 32 bytes of hexadecimal.
    pub fn from_hex(s: &str) -> Result<Self, HashParseError> {
        let body = s.strip_prefix("0x").unwrap_or(s);
        Hash256::from_hex(body).map(|h| Self(h.0))
    }

    /// Returns the address as a trie key.
    #[must_use]
    pub const fn as_key(&self) -> Hash256 {
        Hash256(self.0)
    }
}

impl fmt::Debug for L2Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L2Address(0x{}…)", &hex::encode(self.0)[..8])
    }
}

impl fmt::Display for L2Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for L2Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for L2Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Identifies an asset held on the L2 — a bridged stablecoin, or the native token.
///
/// Ordering is meaningful: account balances are stored in a `BTreeMap` keyed by
/// `AssetId`, so this ordering fixes the iteration order that the account's state
/// commitment is computed over (REQ-FRAUD-031).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct AssetId(pub u32);

impl AssetId {
    /// The network's native token, `$SENA`.
    pub const NATIVE: Self = Self(0);

    /// Returns the numeric identifier.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "asset:{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyless_derivation_is_deterministic() {
        assert_eq!(
            L2Address::derive_keyless(&[1; 32], &[2; 32]),
            L2Address::derive_keyless(&[1; 32], &[2; 32])
        );
    }

    #[test]
    fn issuer_and_commitment_both_matter() {
        let base = L2Address::derive_keyless(&[1; 32], &[2; 32]);
        assert_ne!(base, L2Address::derive_keyless(&[9; 32], &[2; 32]));
        assert_ne!(base, L2Address::derive_keyless(&[1; 32], &[9; 32]));
    }

    #[test]
    fn swapping_the_fields_is_a_different_account() {
        assert_ne!(
            L2Address::derive_keyless(&[1; 32], &[2; 32]),
            L2Address::derive_keyless(&[2; 32], &[1; 32])
        );
    }

    #[test]
    fn hex_round_trips_with_and_without_prefix() {
        let addr = L2Address::derive_keyless(&[1; 32], &[2; 32]);
        assert_eq!(L2Address::from_hex(&addr.to_hex()).unwrap(), addr);
        assert_eq!(L2Address::from_hex(&hex::encode(addr.0)).unwrap(), addr);
    }
}
