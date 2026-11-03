//! Federated attestations: who an identifier belongs to, according to whom
//! (REQ-SOCIAL-001, REQ-SOCIAL-005).
//!
//! SENA follows Celo's `SocialConnect`. An *issuer* — any account that verifies
//! ownership of a phone number, email address or handle, for instance by
//! sending a code to it — signs an attestation that an identifier belongs to an
//! account. The attested account submits it — consenting to be found by that
//! identifier — or the issuer does; the chain checks the issuer's signature and
//! records it under the identifier and the issuer. Unlike Celo, where anyone
//! may submit a signed attestation, requiring the account's consent means an
//! issuer has only to verify who owns the identifier (by OAuth, OIDC, an SMS
//! code — its own choice), never who owns the account.
//! Nothing is first come, first served: an identifier has no owner on chain
//! except as some issuer attests, and a lookup names the issuers it trusts
//! (Celo's `lookupAttestations(identifier, trustedIssuers)`).
//!
//! Identifiers are hashed client-side ([`HashedIdentifier`]); the chain never
//! sees the plain text (REQ-SOCIAL-003). An account may hold attestations for
//! any number of identifiers, from any number of issuers.
//!
//! Replay: a registration must carry a later `issued_on` than the record it
//! replaces, so a signed attestation — including one since revoked — cannot be
//! resubmitted to undo a later change. Revocation keeps the record, marked
//! revoked, for the same reason.

use sena_primitives::{
    domain, CanonicalEncoder, DecodeError, Hash256, HashedIdentifier, L2Address, Reader, Writer,
};
use serde::{Deserialize, Serialize};

/// Discriminant for a standing attestation.
const TAG_ACTIVE: u8 = 0;
/// Discriminant for a revoked attestation.
const TAG_REVOKED: u8 = 1;

/// An issuer's attestation, as state holds it under (identifier, issuer).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// The account the identifier belongs to.
    pub account: L2Address,
    /// When the issuer attested it (Unix seconds, as the issuer signed it).
    pub issued_on: u64,
    /// Whether the issuer or the account has since revoked it.
    pub revoked: bool,
}

impl Attestation {
    /// Encodes the record for storage: a one-byte discriminant, the account
    /// and `issued_on`. Canonical binary so that `sena::osp` decodes it in Move.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(if self.revoked {
            TAG_REVOKED
        } else {
            TAG_ACTIVE
        })
        .bytes32(self.account.as_bytes())
        .u64(self.issued_on);
        w.finish()
    }

    /// Decodes a stored record.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedAttestation`] unless the bytes are canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedAttestation> {
        Self::decode_inner(bytes).map_err(|_| MalformedAttestation)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let revoked = match r.u8()? {
            TAG_ACTIVE => false,
            TAG_REVOKED => true,
            other => return Err(DecodeError::UnknownVariant(other)),
        };
        let account = L2Address::from_bytes(r.bytes32()?);
        let issued_on = r.u64()?;
        r.finish()?;
        Ok(Self {
            account,
            issued_on,
            revoked,
        })
    }
}

/// What an issuer signs to attest that `identifier` belongs to `account` on
/// the chain `chain_id`. The issuer's address is its Ed25519 public key.
#[must_use]
pub fn attestation_digest(
    chain_id: u64,
    identifier: &HashedIdentifier,
    issuer: &L2Address,
    account: &L2Address,
    issued_on: u64,
) -> Hash256 {
    Hash256::commit(
        CanonicalEncoder::new(domain::ATTESTATION)
            .u64(chain_id)
            .field(identifier.as_hash().as_bytes())
            .field(issuer.as_bytes())
            .field(account.as_bytes())
            .u64(issued_on),
    )
}

/// The stored bytes were not a valid [`Attestation`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("stored attestation is malformed")]
pub struct MalformedAttestation;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for revoked in [false, true] {
            let a = Attestation {
                account: L2Address::from_bytes([1; 32]),
                issued_on: 1_700_000_000,
                revoked,
            };
            assert_eq!(Attestation::decode(&a.encode()).unwrap(), a);
        }
        assert!(Attestation::decode(&[2; 41]).is_err());
    }

    #[test]
    fn the_digest_binds_every_field() {
        let id = HashedIdentifier(Hash256([3; 32]));
        let a = L2Address::from_bytes([4; 32]);
        let b = L2Address::from_bytes([5; 32]);
        let base = attestation_digest(1, &id, &a, &b, 9);
        assert_ne!(base, attestation_digest(2, &id, &a, &b, 9), "chain");
        assert_ne!(
            base,
            attestation_digest(1, &id, &b, &a, 9),
            "issuer and account"
        );
        assert_ne!(base, attestation_digest(1, &id, &a, &b, 10), "issued_on");
    }
}
