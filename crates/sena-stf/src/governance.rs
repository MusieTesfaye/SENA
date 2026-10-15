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

use ed25519_dalek::{Signature, VerifyingKey};
use sena_primitives::serde_hex::{bytes_32, bytes_64, u128_string};
use sena_primitives::{CanonicalEncoder, DecodeError, Hash256, Reader, Writer};
use serde::{Deserialize, Serialize};

use crate::gas::{FeeSplit, WhitelistedAsset};

/// Domain tag for the digest the council signs.
const GOVERNANCE_UPDATE: &[u8] = b"SENA:v1:governance-update";

/// The L2 parameters governance may change.
///
/// An allowlist, not a denylist. A parameter absent from this list cannot be
/// written however the payload is crafted, so adding governance reach is a
/// deliberate, reviewable act rather than an oversight.
pub const GOVERNABLE_PARAMETERS: &[&str] = &[
    // Maximum transactions a single batch may contain. (Fee parameters are
    // set through `SetFeeMarket`, which keeps them in the record the base fee
    // step reads.)
    "batch.max_transactions",
];

/// The council authorised to sign governance results.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Council {
    /// Ed25519 verifying keys of the council members, in canonical order.
    pub members: Vec<[u8; 32]>,
    /// How many distinct members must sign for a payload to be accepted.
    pub threshold: u32,
    /// The epoch the next governance payload must be signed for.
    ///
    /// Consumed by every applied payload, like an account nonce. Without it a
    /// signed payload could be replayed indefinitely — re-enabling a gas asset
    /// the council had since disabled, or reinstating a retired JWK.
    #[serde(default)]
    pub epoch: u64,
    /// How many members suffice to *disable* a fee asset — the fast path of
    /// the circuit breaker, like Mento's watchdogs. Zero means guardians have
    /// no fast path and disabling needs [`Council::threshold`] like any other
    /// change. Re-enabling an asset always needs the full threshold.
    #[serde(default)]
    pub guardian_threshold: u32,
}

impl Council {
    /// The signatures a payload needs: the guardian threshold for a
    /// `guardian` payload if the council has one, otherwise the threshold.
    #[must_use]
    pub const fn required(&self, guardian: bool) -> u32 {
        if guardian && self.guardian_threshold > 0 {
            self.guardian_threshold
        } else {
            self.threshold
        }
    }

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
        w.u64(self.epoch);
        w.u32(self.guardian_threshold);
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
        let epoch = r.u64()?;
        let guardian_threshold = r.u32()?;
        r.finish()?;
        Ok(Self {
            members,
            threshold,
            epoch,
            guardian_threshold,
        })
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
    /// Accept or retire an identity provider's JWK (REQ-AUTH-003).
    ///
    /// Providers rotate their signing keys every few weeks, so the set of
    /// acceptable JWKs is state, not code. Retiring is a write of
    /// `active: false` rather than a removal, keeping the trie append-only.
    SetJwk {
        /// Poseidon hash of the issuer (`sena_stf::keyless::iss_hash`).
        #[serde(with = "bytes_32")]
        iss_hash: [u8; 32],
        /// Poseidon hash of the JWK (`sena_stf::keyless::rsa_jwk_hash`).
        #[serde(with = "bytes_32")]
        jwk_hash: [u8; 32],
        /// Whether proofs against the JWK are accepted.
        active: bool,
    },
    /// Set the base fee floor and gas target (Celo's base fee floor).
    SetFeeMarket {
        /// The lowest the base fee may go, in `PRICE_SCALE`ths of a native
        /// unit per gas.
        #[serde(with = "u128_string")]
        floor: u128,
        /// The gas a window aims to use.
        target: u64,
    },
    /// Set how collected fees are shared out (Celo's `FeeHandler`).
    SetFeeSplit {
        /// The new split.
        split: FeeSplit,
    },
    /// Disable a fee asset — the circuit breaker. The only update the
    /// guardian threshold can authorise.
    DisableGasAsset {
        /// The asset to disable.
        asset: sena_primitives::AssetId,
    },
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
        crate::wire::write_update(&mut w, self);
        w.finish()
    }

    /// Returns the digest the council signs.
    ///
    /// `epoch` must equal the council's current epoch when the payload is
    /// applied, and applying it advances the epoch, so a signed payload can be
    /// applied exactly once. The update is encoded canonically so the Aptos L1
    /// verifier can recompute this digest.
    #[must_use]
    pub fn signing_digest(&self, epoch: u64) -> Hash256 {
        Hash256::commit(
            CanonicalEncoder::new(GOVERNANCE_UPDATE)
                .u64(epoch)
                .field(&self.encode()),
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
            Self::SetFeeMarket { floor, target } => {
                if *floor == 0 || *target == 0 {
                    Err(GovernanceError::InvalidFeeParameter)
                } else {
                    Ok(())
                }
            }
            Self::SetFeeSplit { split } => split
                .check()
                .map_err(|_| GovernanceError::InvalidFeeParameter),
            Self::SetJwk { .. } | Self::DisableGasAsset { .. } => Ok(()),
        }
    }

    /// Whether the guardian threshold may authorise this update.
    #[must_use]
    pub const fn guardian_may_apply(&self) -> bool {
        matches!(self, Self::DisableGasAsset { .. })
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
    guardian: bool,
) -> Result<(), GovernanceError> {
    let required = council.required(guardian);
    if required == 0 {
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

        // Strict, as Aptos L1 verifies: a lenient check would accept
        // signatures the one-step verifier refuses.
        let key =
            VerifyingKey::from_bytes(member).map_err(|_| GovernanceError::MalformedCouncil)?;
        if key.is_weak() {
            return Err(GovernanceError::MalformedCouncil);
        }
        key.verify_strict(digest.as_bytes(), &Signature::from_bytes(signature))
            .map_err(|_| GovernanceError::BadSignature { index: *index })?;
    }

    let supplied = u32::try_from(signatures.len()).unwrap_or(u32::MAX);
    if supplied < required {
        return Err(GovernanceError::ThresholdNotMet { supplied, required });
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
    /// A fee market or fee split update is malformed.
    #[error("fee floor and target must be non-zero, and fee split shares must sum to 1,000,000")]
    InvalidFeeParameter,
    /// The payload was signed for an epoch other than the council's current one:
    /// a replay of an applied payload, or one signed out of order.
    #[error("payload signed for epoch {signed}, but the council is at epoch {expected}")]
    WrongEpoch {
        /// The council's current epoch.
        expected: u64,
        /// The epoch the payload was signed for.
        signed: u64,
    },
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
            epoch: 0,
            guardian_threshold: 0,
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
            name: "batch.max_transactions".to_owned(),
            value: 2_000,
        }
    }

    #[test]
    fn a_quorum_of_distinct_members_is_accepted() {
        let keys = [member(1), member(2), member(3)];
        let council = council_of(&keys, 2);
        let digest = update().signing_digest(1);

        let signatures = vec![sig(0, &keys[0], &digest), sig(2, &keys[2], &digest)];
        assert!(verify_council_signatures(&council, &digest, &signatures, false).is_ok());
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
            false,
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
            verify_council_signatures(&council, &digest, &signatures, false).unwrap_err(),
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
            verify_council_signatures(&council, &digest, &signatures, false).unwrap_err(),
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
        assert!(verify_council_signatures(&council, &later, &signatures, false).is_err());
    }

    #[test]
    fn a_signature_for_another_update_is_refused() {
        let keys = [member(1)];
        let council = council_of(&keys, 1);
        let digest = update().signing_digest(1);
        let signatures = vec![sig(0, &keys[0], &digest)];

        let different = GovernanceUpdate::SetParameter {
            name: "batch.max_transactions".to_owned(),
            value: 999_999,
        };
        assert!(verify_council_signatures(
            &council,
            &different.signing_digest(1),
            &signatures,
            false
        )
        .is_err());
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
                intrinsic_gas: 0,
                enabled: true,
            },
        };
        assert_eq!(
            update.check_permitted().unwrap_err(),
            GovernanceError::InvalidAssetRate
        );
    }

    #[test]
    fn guardians_can_only_take_the_fast_path_to_disable() {
        let keys: Vec<_> = (0..3).map(member).collect();
        let mut council = council_of(&keys, 3);
        council.guardian_threshold = 1;
        let disable = GovernanceUpdate::DisableGasAsset {
            asset: sena_primitives::AssetId(1),
        };
        let digest = disable.signing_digest(0);
        let one = [sig(0, &keys[0], &digest)];
        assert!(disable.guardian_may_apply());
        verify_council_signatures(&council, &digest, &one, true).unwrap();
        // The same single signature is not enough for anything else.
        assert!(matches!(
            verify_council_signatures(&council, &digest, &one, false),
            Err(GovernanceError::ThresholdNotMet { required: 3, .. })
        ));
        assert!(!GovernanceUpdate::SetJwk {
            iss_hash: [0; 32],
            jwk_hash: [0; 32],
            active: true
        }
        .guardian_may_apply());
        // Without a guardian threshold, disabling needs the full council.
        council.guardian_threshold = 0;
        assert!(verify_council_signatures(&council, &digest, &one, true).is_err());
        assert_eq!(Council::decode(&council.encode()).unwrap(), council);
    }

    #[test]
    fn fee_updates_are_checked() {
        let bad = [
            GovernanceUpdate::SetFeeMarket {
                floor: 0,
                target: 1,
            },
            GovernanceUpdate::SetFeeMarket {
                floor: 1,
                target: 0,
            },
            GovernanceUpdate::SetFeeSplit {
                split: crate::gas::FeeSplit::default(),
            },
        ];
        for u in bad {
            assert_eq!(
                u.check_permitted(),
                Err(GovernanceError::InvalidFeeParameter)
            );
        }
    }
}
