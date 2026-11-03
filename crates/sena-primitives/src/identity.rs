//! Privacy-preserving handling of human-readable identifiers (REQ-SOCIAL-002).

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::encoding::{domain, CanonicalEncoder};
use crate::hash::Hash256;

/// The network-wide salt mixed into every social identifier hash.
///
/// The salt is a single constant fixed at genesis, not a per-user value. That is
/// a deliberate trade-off and it bounds what this construction can promise —
/// see [`HashedIdentifier`] for what it does and does not defend against.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NetworkSalt(Vec<u8>);

impl NetworkSalt {
    /// Wraps the network's salt value.
    #[must_use]
    pub fn new(salt: impl Into<Vec<u8>>) -> Self {
        Self(salt.into())
    }

    /// Returns the salt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Identifier types, as Celo's `SocialConnect` names them
/// (`@celo/odis-identifiers` `IdentifierPrefix`).
///
/// A type is an open-ended string, not a closed list: an issuer that verifies
/// a platform not listed here — Twitch, Apple, a company directory — uses a
/// prefix of its own, and nothing on chain needs to change. Prefixes are
/// lowercase ASCII letters, digits, `.`, `+` and `-`, at most 32 bytes
/// ([`is_valid_prefix`]).
pub mod prefix {
    /// A phone number, in E.164 form.
    pub const PHONE_NUMBER: &str = "tel";
    /// An email address.
    pub const EMAIL: &str = "mailto";
    /// An X (Twitter) username.
    pub const TWITTER: &str = "twit";
    /// A Facebook username.
    pub const FACEBOOK: &str = "facebook";
    /// An Instagram username.
    pub const INSTAGRAM: &str = "instagram";
    /// A Discord username.
    pub const DISCORD: &str = "discord";
    /// A Telegram username.
    pub const TELEGRAM: &str = "telegram";
    /// A Signal username.
    pub const SIGNAL: &str = "signal";
    /// A GitHub username.
    pub const GITHUB: &str = "github";
}

/// Whether `prefix` is a well-formed identifier type: 1 to 32 bytes of
/// lowercase ASCII letters, digits, `.`, `+` or `-`, starting with a letter.
#[must_use]
pub fn is_valid_prefix(prefix: &str) -> bool {
    let b = prefix.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'+' | b'-')
        })
}

/// A social identifier stored as an opaque digest.
///
/// # What this protects
///
/// Plain-text emails, phone numbers and handles never enter the global state
/// (REQ-SOCIAL-003). A party who obtains a full dump of the L2 state learns the
/// set of addresses that have registered handles, but not what those handles are.
///
/// # What this does not protect
///
/// The salt is network-wide and public, so this construction does **not**
/// withstand enumeration. Anyone can compute the digest of every address in a
/// leaked email corpus, or of every phone number in a country's numbering plan,
/// and match them against the state. Salting defeats precomputed rainbow tables;
/// it does not defeat an attacker willing to hash a candidate list, and for
/// identifiers drawn from a small space that is a cheap attack.
///
/// The property actually delivered is therefore *non-disclosure*, not
/// *unlinkability*: the state does not publish anybody's contact details, but it
/// cannot stop a determined party confirming a guess. Anything stronger requires
/// a private set intersection or oblivious lookup protocol, which is out of
/// scope for the current design and is noted in SDD §5.3 as a known limitation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HashedIdentifier(pub Hash256);

impl HashedIdentifier {
    /// Hashes a raw identifier under the network salt.
    ///
    /// The raw value is normalised first, so that the same identifier typed with
    /// different capitalisation or stray whitespace resolves to one entry.
    ///
    /// The identifier type is a Celo prefix ([`prefix`]): `tel`, `mailto`,
    /// `twit`, `github`, or any other an issuer uses. The prefix and the
    /// plain text are committed to separately, so the same string under two
    /// types is two identifiers, as Celo's `prefix://plaintext` makes it.
    ///
    /// ```
    /// use sena_primitives::{prefix, HashedIdentifier, NetworkSalt};
    ///
    /// let salt = NetworkSalt::new(*b"network-salt");
    /// let a = HashedIdentifier::new(prefix::EMAIL, " Alice@Example.COM ", &salt);
    /// let b = HashedIdentifier::new(prefix::EMAIL, "alice@example.com", &salt);
    /// assert_eq!(a, b);
    /// assert_ne!(a, HashedIdentifier::new("twitch", "alice@example.com", &salt));
    /// ```
    #[must_use]
    pub fn new(identifier_type: &str, raw: &str, salt: &NetworkSalt) -> Self {
        let identifier_type = identifier_type.trim().to_ascii_lowercase();
        let normalised = normalise(&identifier_type, raw);
        Self(Hash256::commit(
            CanonicalEncoder::new(domain::SOCIAL_IDENTIFIER)
                .field(identifier_type.as_bytes())
                .field(normalised.as_bytes())
                .field(salt.as_bytes()),
        ))
    }

    /// Returns the underlying digest.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash256 {
        &self.0
    }

    /// Returns the digest as a trie key.
    #[must_use]
    pub const fn as_key(&self) -> Hash256 {
        self.0
    }
}

impl fmt::Debug for HashedIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashedIdentifier({}…)", &self.0.to_hex()[..8])
    }
}

/// Normalises an identifier so that cosmetic variations resolve to one entry.
///
/// Normalisation is part of the consensus rules — two nodes that normalise
/// differently compute different digests and therefore different state roots —
/// so the rules here are deliberately simple and locale-independent. ASCII
/// lowercasing is used rather than Unicode case folding because full case
/// folding is table-driven and version-dependent, which would make the state
/// root depend on the Unicode version a node was built against.
fn normalise(identifier_type: &str, raw: &str) -> String {
    let trimmed = raw.trim();
    if identifier_type == prefix::PHONE_NUMBER {
        // Phone numbers are compared by digits alone, so formatting punctuation
        // is dropped. A leading '+' is preserved to keep E.164 form meaningful.
        let mut out = String::with_capacity(trimmed.len());
        if trimmed.starts_with('+') {
            out.push('+');
        }
        out.extend(trimmed.chars().filter(char::is_ascii_digit));
        out
    } else {
        // Email domains are case-insensitive, and in practice mailbox names
        // are treated that way too by every major provider; usernames are
        // case-insensitive on every platform an issuer verifies today.
        trimmed.to_ascii_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> NetworkSalt {
        NetworkSalt::new(*b"sena-test-network-salt")
    }

    #[test]
    fn hashing_is_deterministic() {
        let a = HashedIdentifier::new(prefix::EMAIL, "user@example.com", &salt());
        let b = HashedIdentifier::new(prefix::EMAIL, "user@example.com", &salt());
        assert_eq!(a, b);
        println!("root={}", a.0.to_hex());
    }

    #[test]
    fn email_normalisation_folds_case_and_whitespace() {
        let a = HashedIdentifier::new(prefix::EMAIL, "  USER@Example.Com ", &salt());
        let b = HashedIdentifier::new(prefix::EMAIL, "user@example.com", &salt());
        assert_eq!(a, b);
    }

    #[test]
    fn phone_normalisation_drops_formatting() {
        let a = HashedIdentifier::new(prefix::PHONE_NUMBER, "+1 (555) 010-1234", &salt());
        let b = HashedIdentifier::new(prefix::PHONE_NUMBER, "+15550101234", &salt());
        assert_eq!(a, b);
    }

    #[test]
    fn phone_normalisation_keeps_country_prefix_significant() {
        let international = HashedIdentifier::new(prefix::PHONE_NUMBER, "+15550101234", &salt());
        let national = HashedIdentifier::new(prefix::PHONE_NUMBER, "15550101234", &salt());
        assert_ne!(international, national);
    }

    #[test]
    fn prefixes_follow_celo() {
        for p in [
            prefix::PHONE_NUMBER,
            prefix::EMAIL,
            prefix::TWITTER,
            prefix::GITHUB,
            "twitch",
            "apple",
        ] {
            assert!(is_valid_prefix(p), "{p}");
        }
        for p in ["", "Tel", "1tel", "tel://", "a b", &"x".repeat(33)] {
            assert!(!is_valid_prefix(p), "{p:?}");
        }
    }

    #[test]
    fn channels_are_separated() {
        // The same string registered as a handle and as an email must not collide.
        let as_email = HashedIdentifier::new(prefix::EMAIL, "alice", &salt());
        let as_handle = HashedIdentifier::new("handle", "alice", &salt());
        assert_ne!(as_email, as_handle);
    }

    #[test]
    fn a_different_salt_yields_a_different_digest() {
        let a = HashedIdentifier::new("handle", "alice", &salt());
        let b = HashedIdentifier::new("handle", "alice", &NetworkSalt::new(*b"other"));
        assert_ne!(a, b);
    }

    #[test]
    fn identifier_and_salt_boundaries_are_unambiguous() {
        let a = HashedIdentifier::new("handle", "ab", &NetworkSalt::new(*b"c"));
        let b = HashedIdentifier::new("handle", "a", &NetworkSalt::new(*b"bc"));
        assert_ne!(a, b);
    }
}
