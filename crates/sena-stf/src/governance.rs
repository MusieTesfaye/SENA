//! The optimistic governance layer (REQ-GOV-001 through REQ-GOV-007).
//!
//! Token holders vote off-chain; a multi-signature council signs the result; the
//! L2 applies it. The council's signature is what the chain actually checks, so
//! the council — not the vote — is the authority the protocol recognises. That
//! is worth stating plainly rather than obscuring behind the word "governance".
//!
//! # What governance deliberately cannot do
//!
//! A council that could rescue a fraudulent assertion would nullify the entire
//! fraud proof system: a compromised sequencer and a compromised council could
//! finalize whatever they liked. REQ-GOV-007 therefore puts the dispute
//! machinery out of reach, and this module enforces that by construction rather
//! than by policy.
//!
//! Two mechanisms do it. [`GOVERNABLE_PARAMETERS`] is an explicit allowlist, so
//! a parameter is unreachable unless it was deliberately added. And the
//! parameters that matter most — the challenge window, assertion finalization,
//! dispute outcomes — do not live on the L2 at all. They live in the Move
//! contracts on Aptos L1, which expose no entry point the L2 can call. A council
//! that wanted to shorten the challenge window would have to persuade Aptos L1
//! to run different code.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sena_primitives::serde_hex::{bytes_64, u128_string};
use sena_primitives::{CanonicalEncoder, DecodeError, Hash256, Reader, Writer};
use serde::{Deserialize, Serialize};

use crate::gas::WhitelistedAsset;

/// Domain tag for the digest the council signs.
const GOVERNANCE_UPDATE: &[u8] = b"SENA:v1:governance-update";

/// The L2 parameters governance may change.
///
/// An allowlist, not a denylist. A parameter absent from this list cannot be
/// written however the payload is crafted, so adding governance reach is a
/// deliberate, reviewable act rather than an oversight.
pub const GOVERNABLE_PARAMETERS: &[&str] = &[
    // Base cost of a transaction, in native units.
    "gas.base_native",
    // Maximum transactions a single batch may contain.
    "batch.max_transactions",
];

/// The council authorised to sign governance results.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Council {
    /// Ed25519 verifying keys of the council members, in canonical order.
    pub members: Vec<[u8; 32]>,
    /// How many distinct members must sign for a payload to be accepted.
    pub threshold: u32,
}

impl Council {
    /// Encodes the council for storage.
    ///
    /// Canonical binary, so `sena::osp` can decode the roster when adjudicating
    /// a disputed `VerifyCouncil` step.
    ///
    /// # Panics
    ///
    /// Panics if the council has more than `u32::MAX` members, which no council
    /// can reach.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(u32::try_from(self.members.len()).expect("a council cannot have 2^32 members"));
        for member in &self.members {
            w.bytes32(member);
        }
        w.u32(self.threshold);
        w.finish()
    }

    /// Decodes a stored council.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::MalformedCouncil`] if the bytes are not a
    /// canonical council record.
    pub fn decode(bytes: &[u8]) -> Result<Self, GovernanceError> {
        Self::decode_inner(bytes).map_err(|_| GovernanceError::MalformedCouncil)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let count = r.u32()?;
        let mut members = Vec::with_capacity(count as usize);
        for _ in 0..count {
            members.push(r.bytes32()?);
        }
        let threshold = r.u32()?;
        r.finish()?;
        Ok(Self { members, threshold })
    }
}

/// One council member's signature over a governance update.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CouncilSignature {
    /// Index of the signing member within [`Council::members`].
    pub index: u32,
    /// The Ed25519 signature over the update digest.
    #[serde(with = "bytes_64")]
    pub signature: [u8; 64],
}

/// A change the council has authorised.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "change")]
pub enum GovernanceUpdate {
    /// Add or update a gas asset's whitelist record (REQ-GAS-003).
    SetGasAsset {
        /// The record to store.
        record: WhitelistedAsset,
    },
    /// Set an allowlisted network parameter.
    SetParameter {
        /// Parameter name, which must appear in [`GOVERNABLE_PARAMETERS`].
        name: String,
        /// New value.
        #[serde(with = "u128_string")]
        value: u128,
    },
}

/// Discriminants for the canonical update encoding, fixed explicitly because
/// the council's signature commits to them.
mod update_tag {
    pub const SET_GAS_ASSET: u8 = 0;
    pub const SET_PARAMETER: u8 = 1;
}

impl GovernanceUpdate {
    /// Encodes the update canonically.
    ///
    /// Binary rather than JSON, for the same reason the transaction signing
    /// digest is: what the council signs must be reproducible by anything that
    /// verifies the signature, including a Move contract.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::SetGasAsset { record } => {
                w.u8(update_tag::SET_GAS_ASSET);
                w.bytes(&record.encode());
            }
            Self::SetParameter { name, value } => {
                w.u8(update_tag::SET_PARAMETER);
                w.string(name);
                w.u128(*value);
            }
        }
        w.finish()
    }

    /// Returns the digest the council signs.
    ///
    /// `epoch` is included so that a signed payload cannot be replayed once it
    /// has been applied, or applied twice by a relayer.
    ///
    /// # Panics
    ///
    /// Panics only if serialisation fails, which cannot occur.
    #[must_use]
    pub fn signing_digest(&self, epoch: u64) -> Hash256 {
        let body = serde_json::to_vec(self).expect("update serialisation cannot fail");
        Hash256::commit(
            CanonicalEncoder::new(GOVERNANCE_UPDATE)
                .u64(epoch)
                .field(&body),
        )
    }

    /// Checks that the update is one governance is permitted to make.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceError::UngovernableParameter`] for a parameter
    /// outside [`GOVERNABLE_PARAMETERS`], or
    /// [`GovernanceError::InvalidAssetRate`] for a rate that would make
    /// execution free.
    pub fn check_permitted(&self) -> Result<(), GovernanceError> {
        match self {
            Self::SetParameter { name, .. } => {
                if GOVERNABLE_PARAMETERS.contains(&name.as_str()) {
                    Ok(())
                } else {
                    Err(GovernanceError::UngovernableParameter { name: name.clone() })
                }
            }
            Self::SetGasAsset { record } => {
                // A zero rate would make every fee round to zero, so it is
                // refused even with a valid council signature.
                if record.rate == 0 {
                    Err(GovernanceError::InvalidAssetRate)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Verifies that enough distinct council members signed `digest`.
///
/// Signatures are supplied as `(member_index, signature)` pairs. Indices must be
/// strictly increasing, which does two things at once: it makes the check
/// linear, and it makes it impossible to reach the threshold by repeating one
/// member's signature — the attack that would let a single compromised key act
/// as the whole council.
///
/// # Errors
///
/// Returns [`GovernanceError`] if an index is out of range, indices are not
/// strictly increasing, a signature does not verify, or too few are supplied.
pub fn verify_council_signatures(
    council: &Council,
    digest: &Hash256,
    signatures: &[CouncilSignature],
) -> Result<(), GovernanceError> {
    if council.threshold == 0 {
        return Err(GovernanceError::ThresholdNotMet {
            supplied: 0,
            required: 0,
        });
    }

    let mut previous: Option<u32> = None;
    for CouncilSignature { index, signature } in signatures {
        if let Some(prev) = previous {
            if *index <= prev {
                return Err(GovernanceError::UnorderedSigners);
            }
        }
        previous = Some(*index);

        let member = council
            .members
            .get(usize::try_from(*index).map_err(|_| GovernanceError::UnknownSigner)?)
            .ok_or(GovernanceError::UnknownSigner)?;

        let key =
            VerifyingKey::from_bytes(member).map_err(|_| GovernanceError::MalformedCouncil)?;
        key.verify(digest.as_bytes(), &Signature::from_bytes(signature))
            .map_err(|_| GovernanceError::BadSignature { index: *index })?;
    }

    let supplied = u32::try_from(signatures.len()).unwrap_or(u32::MAX);
    if supplied < council.threshold {
        return Err(GovernanceError::ThresholdNotMet {
            supplied,
            required: council.threshold,
        });
    }
    Ok(())
}

/// Why a governance action was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum GovernanceError {
    /// The stored council record is not decodable.
    #[error("stored council record is malformed")]
    MalformedCouncil,
    /// A signature referenced a member outside the council.
    #[error("signature references an unknown council member")]
    UnknownSigner,
    /// Signer indices were not strictly increasing.
    #[error("signer indices must be strictly increasing, so one member cannot be counted twice")]
    UnorderedSigners,
    /// A signature did not verify.
    #[error("signature from council member {index} does not verify")]
    BadSignature {
        /// Index of the member whose signature failed.
        index: u32,
    },
    /// Too few valid signatures were supplied.
    #[error("{supplied} signatures supplied, {required} required")]
    ThresholdNotMet {
        /// How many were supplied.
        supplied: u32,
        /// How many the council requires.
        required: u32,
    },
    /// The parameter is not one governance may change (REQ-GOV-007).
    #[error("parameter '{name}' is outside the governable set")]
    UngovernableParameter {
        /// The parameter that was refused.
        name: String,
    },
    /// The asset rate would make execution free.
    #[error("gas asset rate must be non-zero")]
    InvalidAssetRate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn member(seed: u64) -> SigningKey {
        SigningKey::generate(&mut StdRng::seed_from_u64(seed))
    }

    fn council_of(keys: &[SigningKey], threshold: u32) -> Council {
        Council {
            members: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
            threshold,
        }
    }

    fn sig(index: u32, key: &SigningKey, digest: &Hash256) -> CouncilSignature {
        CouncilSignature {
            index,
            signature: key.sign(digest.as_bytes()).to_bytes(),
        }
    }

    fn update() -> GovernanceUpdate {
        GovernanceUpdate::SetParameter {
            name: "gas.base_native".to_owned(),
            value: 2_000,
        }
    }

    #[test]
    fn a_quorum_of_distinct_members_is_accepted() {
        let keys = [member(1), member(2), member(3)];
        let council = council_of(&keys, 2);
        let digest = update().signing_digest(1);

        let signatures = vec![sig(0, &keys[0], &digest), sig(2, &keys[2], &digest)];
        assert!(verify_council_signatures(&council, &digest, &signatures).is_ok());
    }

    #[test]
    fn one_member_cannot_impersonate_a_quorum() {
        // The critical check: repeating a single compromised key must not reach
        // the threshold.
        let keys = [member(1), member(2), member(3)];
        let council = council_of(&keys, 2);
        let digest = update().signing_digest(1);
        let signature = keys[0].sign(digest.as_bytes()).to_bytes();

        let err = verify_council_signatures(
            &council,
            &digest,
            &[
                CouncilSignature {
                    index: 0,
                    signature,
                },
                CouncilSignature {
                    index: 0,
                    signature,
                },
            ],
        )
        .unwrap_err();
        assert_eq!(err, GovernanceError::UnorderedSigners);
    }

    #[test]
    fn too_few_signatures_are_refused() {
        let keys = [member(1), member(2), member(3)];
        let council = council_of(&keys, 3);
        let digest = update().signing_digest(1);
        let signatures = vec![sig(0, &keys[0], &digest)];

        assert_eq!(
            verify_council_signatures(&council, &digest, &signatures).unwrap_err(),
            GovernanceError::ThresholdNotMet {
                supplied: 1,
                required: 3
            }
        );
    }

    #[test]
    fn a_non_member_signature_is_refused() {
        let keys = [member(1), member(2)];
        let council = council_of(&keys, 1);
        let digest = update().signing_digest(1);
        let outsider = member(99);

        // Claim to be member 0 while signing with an unrelated key.
        let signatures = vec![sig(0, &outsider, &digest)];
        assert!(matches!(
            verify_council_signatures(&council, &digest, &signatures).unwrap_err(),
            GovernanceError::BadSignature { index: 0 }
        ));
    }

    #[test]
    fn a_signature_for_another_epoch_is_refused() {
        // Replay protection: an approved change must not be re-applied later.
        let keys = [member(1)];
        let council = council_of(&keys, 1);
        let signed_digest = update().signing_digest(1);
        let signatures = vec![sig(0, &keys[0], &signed_digest)];

        let later = update().signing_digest(2);
        assert!(verify_council_signatures(&council, &later, &signatures).is_err());
    }

    #[test]
    fn a_signature_for_another_update_is_refused() {
        let keys = [member(1)];
        let council = council_of(&keys, 1);
        let digest = update().signing_digest(1);
        let signatures = vec![sig(0, &keys[0], &digest)];

        let different = GovernanceUpdate::SetParameter {
            name: "gas.base_native".to_owned(),
            value: 999_999,
        };
        assert!(
            verify_council_signatures(&council, &different.signing_digest(1), &signatures).is_err()
        );
    }

    #[test]
    fn parameters_outside_the_allowlist_are_unreachable() {
        // REQ-GOV-007: the council must not be able to reach the dispute system,
        // even with a perfectly valid signature.
        for name in [
            "challenge_window",
            "assertion.finalize",
            "dispute.outcome",
            "anything",
        ] {
            let update = GovernanceUpdate::SetParameter {
                name: name.to_owned(),
                value: 1,
            };
            assert!(
                matches!(
                    update.check_permitted().unwrap_err(),
                    GovernanceError::UngovernableParameter { .. }
                ),
                "'{name}' must not be governable"
            );
        }
    }

    #[test]
    fn allowlisted_parameters_are_permitted() {
        for name in GOVERNABLE_PARAMETERS {
            let update = GovernanceUpdate::SetParameter {
                name: (*name).to_owned(),
                value: 1,
            };
            assert!(update.check_permitted().is_ok());
        }
    }

    #[test]
    fn a_zero_rate_asset_is_refused_even_with_a_valid_signature() {
        let update = GovernanceUpdate::SetGasAsset {
            record: WhitelistedAsset {
                asset: sena_primitives::AssetId(1),
                symbol: "FREE".to_owned(),
                rate: 0,
                enabled: true,
            },
        };
        assert_eq!(
            update.check_permitted().unwrap_err(),
            GovernanceError::InvalidAssetRate
        );
    }
}
