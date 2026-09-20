//! The Social Connect identity index (REQ-SOCIAL-001).

use sena_primitives::{DecodeError, L2Address, Reader, Writer};
use serde::{Deserialize, Serialize};

/// Discriminant for a bound identifier.
const TAG_BOUND: u8 = 0;
/// Discriminant for a released identifier.
const TAG_VACANT: u8 = 1;

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
    /// A one-byte discriminant followed by the address, if any. Canonical
    /// binary rather than JSON so that `sena::osp` can decode it in Move.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Bound { address } => {
                w.u8(TAG_BOUND);
                w.bytes32(address.as_bytes());
            }
            Self::Vacant => {
                w.u8(TAG_VACANT);
            }
        }
        w.finish()
    }

    /// Decodes a stored binding.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedBinding`] if the bytes are not a canonical binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedBinding> {
        Self::decode_inner(bytes).map_err(|_| MalformedBinding)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let binding = match r.u8()? {
            TAG_BOUND => Self::Bound {
                address: L2Address::from_bytes(r.bytes32()?),
            },
            TAG_VACANT => Self::Vacant,
            other => return Err(DecodeError::UnknownVariant(other)),
        };
        r.finish()?;
        Ok(binding)
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
