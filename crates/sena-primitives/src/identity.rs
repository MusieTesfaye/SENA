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

/// The kind of Web2 channel an identifier belongs to.
///
/// The channel is committed to alongside the identifier so that the same string
/// registered as two different kinds of handle produces two different entries,
/// and so that a lookup cannot be answered with an entry of the wrong kind.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// An email address.
    Email,
    /// An E.164 phone number.
    Phone,
    /// A platform-specific username or handle.
    Handle,
}

impl Channel {
    /// The discriminant used in canonical binary encodings.
    ///
    /// Fixed and explicit rather than derived from declaration order, because
    /// the Move implementation hardcodes these values and reordering the enum
    /// would silently change what a stored slot means.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        match self {
            Self::Email => 0,
            Self::Phone => 1,
            Self::Handle => 2,
        }
    }

    /// The tag committed to in the identifier hash.
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::Email => b"email",
            Self::Phone => b"phone",
            Self::Handle => b"handle",
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Handle => "handle",
        })
    }
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
    /// ```
    /// use sena_primitives::{Channel, HashedIdentifier, NetworkSalt};
    ///
    /// let salt = NetworkSalt::new(*b"network-salt");
    /// let a = HashedIdentifier::new(Channel::Email, " Alice@Example.COM ", &salt);
    /// let b = HashedIdentifier::new(Channel::Email, "alice@example.com", &salt);
    /// assert_eq!(a, b);
    /// ```
    #[must_use]
    pub fn new(channel: Channel, raw: &str, salt: &NetworkSalt) -> Self {
        let normalised = normalise(channel, raw);
        Self(Hash256::commit(
            CanonicalEncoder::new(domain::SOCIAL_IDENTIFIER)
                .field(channel.tag())
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
fn normalise(channel: Channel, raw: &str) -> String {
    let trimmed = raw.trim();
    match channel {
        // Email domains are case-insensitive, and in practice mailbox names are
        // treated that way too by every major provider. Handles are likewise
        // case-insensitive on every platform SENA resolves against, so the two
        // share a rule -- they stay distinct entries because the channel tag is
        // committed to separately in `HashedIdentifier::new`.
        Channel::Email | Channel::Handle => trimmed.to_ascii_lowercase(),
        // Phone numbers are compared by digits alone, so formatting punctuation
        // is dropped. A leading '+' is preserved to keep E.164 form meaningful.
        Channel::Phone => {
            let mut out = String::with_capacity(trimmed.len());
            if trimmed.starts_with('+') {
                out.push('+');
            }
            out.extend(trimmed.chars().filter(char::is_ascii_digit));
            out
        }
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
        let a = HashedIdentifier::new(Channel::Email, "user@example.com", &salt());
        let b = HashedIdentifier::new(Channel::Email, "user@example.com", &salt());
        assert_eq!(a, b);
        println!("root={}", a.0.to_hex());
    }

    #[test]
    fn email_normalisation_folds_case_and_whitespace() {
        let a = HashedIdentifier::new(Channel::Email, "  USER@Example.Com ", &salt());
        let b = HashedIdentifier::new(Channel::Email, "user@example.com", &salt());
        assert_eq!(a, b);
    }

    #[test]
    fn phone_normalisation_drops_formatting() {
        let a = HashedIdentifier::new(Channel::Phone, "+1 (555) 010-1234", &salt());
        let b = HashedIdentifier::new(Channel::Phone, "+15550101234", &salt());
        assert_eq!(a, b);
    }

    #[test]
    fn phone_normalisation_keeps_country_prefix_significant() {
        let international = HashedIdentifier::new(Channel::Phone, "+15550101234", &salt());
        let national = HashedIdentifier::new(Channel::Phone, "15550101234", &salt());
        assert_ne!(international, national);
    }

    #[test]
    fn channels_are_separated() {
        // The same string registered as a handle and as an email must not collide.
        let as_email = HashedIdentifier::new(Channel::Email, "alice", &salt());
        let as_handle = HashedIdentifier::new(Channel::Handle, "alice", &salt());
        assert_ne!(as_email, as_handle);
    }

    #[test]
    fn a_different_salt_yields_a_different_digest() {
        let a = HashedIdentifier::new(Channel::Handle, "alice", &salt());
        let b = HashedIdentifier::new(Channel::Handle, "alice", &NetworkSalt::new(*b"other"));
        assert_ne!(a, b);
    }

    #[test]
    fn identifier_and_salt_boundaries_are_unambiguous() {
        let a = HashedIdentifier::new(Channel::Handle, "ab", &NetworkSalt::new(*b"c"));
        let b = HashedIdentifier::new(Channel::Handle, "a", &NetworkSalt::new(*b"bc"));
        assert_ne!(a, b);
    }
}
