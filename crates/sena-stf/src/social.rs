//! The Social Connect identity index (REQ-SOCIAL-001).

use sena_primitives::L2Address;
use serde::{Deserialize, Serialize};

/// What a hashed identifier currently resolves to.
///
/// [`Self::Vacant`] is stored rather than the entry being removed. See
/// [`crate::Instruction::UnbindIdentifier`] for why the trie is kept
/// structurally append-only.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SocialBinding {
    /// The identifier resolves to this address.
    Bound {
        /// The address that holds the identifier.
        address: L2Address,
    },
    /// The identifier was previously bound and has been released.
    Vacant,
}

impl SocialBinding {
    /// Returns the bound address, if any.
    #[must_use]
    pub const fn address(&self) -> Option<L2Address> {
        match self {
            Self::Bound { address } => Some(*address),
            Self::Vacant => None,
        }
    }

    /// Encodes the binding for storage.
    ///
    /// # Panics
    ///
    /// Panics only if serialising an enum of one address fails, which cannot
    /// occur.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("binding serialisation cannot fail")
    }

    /// Decodes a stored binding.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedBinding`] if the bytes are not a valid binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedBinding> {
        serde_json::from_slice(bytes).map_err(|_| MalformedBinding)
    }
}

/// The stored bytes were not a valid [`SocialBinding`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("stored social binding is malformed")]
pub struct MalformedBinding;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bound = SocialBinding::Bound {
            address: L2Address::from_bytes([1; 32]),
        };
        assert_eq!(SocialBinding::decode(&bound.encode()).unwrap(), bound);
        assert_eq!(
            SocialBinding::decode(&SocialBinding::Vacant.encode()).unwrap(),
            SocialBinding::Vacant
        );
    }

    #[test]
    fn vacant_resolves_to_nothing() {
        assert_eq!(SocialBinding::Vacant.address(), None);
    }
}
