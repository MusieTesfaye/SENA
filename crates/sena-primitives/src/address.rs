//! Account addresses and asset identifiers.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{domain, CanonicalEncoder};
use crate::hash::{Hash256, HashParseError};

/// A 32-byte account address on the SENA L2.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct L2Address(pub [u8; 32]);

impl L2Address {
    /// Derives the address controlled by an OIDC identity (REQ-AUTH-002).
    ///
    /// The address commits to three values:
    ///
    /// - `aud`, the application-scoped audience claim, so that the same person
    ///   signing into two different applications receives two unlinkable
    ///   addresses;
    /// - `sub`, the identity provider's stable subject identifier for the user;
    /// - `pepper`, a high-entropy blinding value the user holds privately.
    ///
    /// The pepper is what keeps the mapping one-way in practice. `aud` and `sub`
    /// are low-entropy and frequently guessable — an observer who knows someone's
    /// Google subject identifier could otherwise derive their address and
    /// deanonymise every transaction they have ever made. With a pepper the
    /// preimage is unguessable, so the address reveals nothing about the identity
    /// behind it.
    ///
    /// Losing the pepper means losing the ability to derive the address, so it is
    /// recovery-critical: wallets obtain it from a pepper service keyed to the
    /// same OIDC identity rather than generating it locally.
    ///
    /// ```
    /// use sena_primitives::L2Address;
    ///
    /// let a = L2Address::derive_from_oidc("app-1", "user-42", b"pepper");
    /// let b = L2Address::derive_from_oidc("app-2", "user-42", b"pepper");
    /// assert_ne!(a, b, "the same user is unlinkable across applications");
    /// ```
    #[must_use]
    pub fn derive_from_oidc(aud: &str, sub: &str, pepper: &[u8]) -> Self {
        let digest = Hash256::commit(
            CanonicalEncoder::new(domain::OIDC_ADDRESS)
                .field(aud.as_bytes())
                .field(sub.as_bytes())
                .field(pepper),
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

    const PEPPER: &[u8] = b"a-high-entropy-pepper-value-0123";

    #[test]
    fn derivation_is_deterministic() {
        let a = L2Address::derive_from_oidc("app", "user", PEPPER);
        let b = L2Address::derive_from_oidc("app", "user", PEPPER);
        assert_eq!(a, b);
        println!("root={}", hex::encode(a.0));
    }

    #[test]
    fn same_user_is_unlinkable_across_applications() {
        // REQ-AUTH-002: aud scoping is what prevents two applications from
        // correlating the same person.
        let app1 = L2Address::derive_from_oidc("app-1", "user", PEPPER);
        let app2 = L2Address::derive_from_oidc("app-2", "user", PEPPER);
        assert_ne!(app1, app2);
    }

    #[test]
    fn different_users_get_different_addresses() {
        let a = L2Address::derive_from_oidc("app", "alice", PEPPER);
        let b = L2Address::derive_from_oidc("app", "bob", PEPPER);
        assert_ne!(a, b);
    }

    #[test]
    fn pepper_changes_the_address() {
        let a = L2Address::derive_from_oidc("app", "user", b"pepper-one");
        let b = L2Address::derive_from_oidc("app", "user", b"pepper-two");
        assert_ne!(a, b, "the pepper must blind the derivation");
    }

    #[test]
    fn claim_boundaries_are_unambiguous() {
        // Without length-prefixed framing these two distinct identities would
        // collide, letting one user derive another's address.
        let a = L2Address::derive_from_oidc("ab", "c", PEPPER);
        let b = L2Address::derive_from_oidc("a", "bc", PEPPER);
        assert_ne!(a, b);
    }

    #[test]
    fn hex_round_trips_with_and_without_prefix() {
        let addr = L2Address::derive_from_oidc("app", "user", PEPPER);
        assert_eq!(L2Address::from_hex(&addr.to_hex()).unwrap(), addr);
        assert_eq!(L2Address::from_hex(&hex::encode(addr.0)).unwrap(), addr);
    }
}
