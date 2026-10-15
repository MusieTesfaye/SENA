//! Transactions and how they are authenticated.

use ed25519_dalek::{Signature, VerifyingKey};
use sena_primitives::serde_hex::{bytes_32, bytes_64, u128_string};
use sena_primitives::Writer;
use sena_primitives::{
    domain, AssetId, CanonicalEncoder, Channel, Hash256, HashedIdentifier, L2Address,
};
use serde::{Deserialize, Serialize};

use crate::gas::FeeSplit;
use crate::governance::{CouncilSignature, GovernanceUpdate};
use crate::keyless::{self, KeylessContext, KeylessError, KeylessSignature};

/// What a transaction asks the chain to do.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Payload {
    /// Move an asset between accounts.
    Transfer {
        /// Recipient.
        to: L2Address,
        /// Asset to move.
        asset: AssetId,
        /// Amount to move.
        #[serde(with = "u128_string")]
        amount: u128,
    },
    /// Bind a human-readable identifier to the sender's address (REQ-SOCIAL-001).
    BindIdentifier {
        /// Which kind of channel the identifier belongs to.
        channel: Channel,
        /// The identifier, already hashed client-side so the plain text never
        /// reaches the node (REQ-SOCIAL-003).
        identifier: HashedIdentifier,
    },
    /// Release an identifier the sender currently holds.
    UnbindIdentifier {
        /// The identifier to release.
        identifier: HashedIdentifier,
    },
    /// Apply a council-authorised governance change (REQ-GOV-003).
    ///
    /// Carried as an ordinary transaction so that it is executed inside a batch
    /// and covered by the same fraud proof guarantees as anything else
    /// (REQ-GOV-006). A council signature authorising an invalid state change
    /// produces an invalid assertion, challengeable like sequencer fraud.
    Governance {
        /// Monotonic epoch, signed over, so an approved change cannot be
        /// replayed once applied.
        epoch: u64,
        /// The change the council authorised.
        update: GovernanceUpdate,
        /// Council signatures over the update digest.
        signatures: Vec<CouncilSignature>,
    },
    /// Pay `amount` of collected fees out of the fee vault according to the
    /// fee split in force (Celo's `FeeHandler.distribute`). Permissionless:
    /// the split decides who is paid, and the sender pays only its own fee.
    DistributeFees {
        /// The asset to distribute.
        asset: AssetId,
        /// How much of it to take from the vault.
        #[serde(with = "u128_string")]
        amount: u128,
        /// The split the sender believes is in force; checked in the trace.
        split: FeeSplit,
    },
}

/// How a transaction proves it was authorised.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "scheme")]
pub enum Authenticator {
    /// A plain Ed25519 signature by a key the account controls directly.
    Ed25519 {
        /// The signing key, as 32 raw bytes.
        #[serde(with = "bytes_32")]
        public_key: [u8; 32],
        /// The signature, as 64 raw bytes.
        #[serde(with = "bytes_64")]
        signature: [u8; 64],
    },
    /// An OIDC keyless authorisation over the Aptos Keyless circuit
    /// (REQ-AUTH-003, REQ-AUTH-004). See [`crate::keyless`].
    Keyless(Box<KeylessSignature>),
}

/// A transaction as submitted to the sequencer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// The account the transaction acts on behalf of.
    pub sender: L2Address,
    /// The sender's expected nonce. Must equal the account's current nonce.
    pub nonce: u64,
    /// The asset the fee is paid in (REQ-GAS-001) — Celo's `feeCurrency`.
    pub fee_asset: AssetId,
    /// The exchange rate the sender believes applies to `fee_asset`, in units
    /// per [`RATE_SCALE`](crate::gas::RATE_SCALE) native units.
    ///
    /// Declared by the sender rather than looked up during execution, so that
    /// compilation stays a pure function of the transaction. The claim is
    /// checked against the on-chain whitelist by an in-trace instruction; see
    /// [`crate::gas`].
    #[serde(with = "u128_string")]
    pub fee_rate: u128,
    /// The intrinsic gas the sender believes `fee_asset` charges; checked in
    /// the trace alongside the rate.
    pub fee_intrinsic_gas: u64,
    /// The most gas the transaction may use.
    pub gas_limit: u64,
    /// The most the sender pays per gas, base fee and tip together, in
    /// [`PRICE_SCALE`](crate::gas::PRICE_SCALE)ths of a unit of `fee_asset`.
    #[serde(with = "u128_string")]
    pub max_fee_per_gas: u128,
    /// The most tip the sender pays per gas, in the same units.
    #[serde(with = "u128_string")]
    pub max_priority_fee_per_gas: u128,
    /// What to do.
    pub payload: Payload,
    /// Proof of authorisation.
    pub authenticator: Authenticator,
}

impl Payload {
    /// Encodes the payload canonically, for the signing digest.
    ///
    /// Binary rather than JSON. What a user signs has to be reproducible by
    /// anything that verifies the signature -- including, for keyless accounts,
    /// a Move contract on Aptos L1 -- and reimplementing `serde_json` in Move
    /// well enough to agree byte for byte is not a reasonable thing to depend
    /// on. It is the same reason state values moved off JSON in Phase 7.
    ///
    /// # Panics
    ///
    /// Panics if a governance payload carries more than `u32::MAX` signatures.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        crate::wire::write_payload(&mut w, self);
        w.finish()
    }
}

impl Transaction {
    /// Returns the digest that authenticators sign.
    ///
    /// The authenticator is excluded, since it commits to this value. Every
    /// other field is included: omitting any of them would let an observer
    /// replay a captured signature with that field altered — changing the
    /// recipient, or raising the fee.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn signing_digest(&self) -> Hash256 {
        let payload = self.payload.encode();
        Hash256::commit(
            CanonicalEncoder::new(domain::TRANSACTION)
                .field(self.sender.as_bytes())
                .u64(self.nonce)
                .u64(u64::from(self.fee_asset.get()))
                .u128(self.fee_rate)
                .u64(self.fee_intrinsic_gas)
                .u64(self.gas_limit)
                .u128(self.max_fee_per_gas)
                .u128(self.max_priority_fee_per_gas)
                .field(&payload),
        )
    }

    /// Returns the transaction's identifier: the hash of its canonical
    /// encoding, authenticator included.
    #[must_use]
    pub fn hash(&self) -> Hash256 {
        Hash256::digest(&self.encode())
    }

    /// Encodes the transaction canonically, as batches publish it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    /// Decodes a canonically encoded transaction.
    ///
    /// # Errors
    ///
    /// Returns [`crate::wire::WireError`] unless `bytes` is exactly a canonical
    /// encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode(bytes)
    }

    /// Checks that the transaction is authorised.
    ///
    /// An Ed25519 account's address *is* its public key, so the key that signed
    /// must be the sender's own. Checking only that the signature matches the
    /// key carried alongside it would let any keypair spend from any account.
    /// A keyless account's address is derived from the identity the proof
    /// attests to, and [`keyless::verify`] checks the same binding.
    ///
    /// Signature verification is strict (canonical `S`, no small-order keys),
    /// because the Aptos one-step verifier uses
    /// `ed25519::signature_verify_strict`. A lenient check here would accept
    /// signatures L1 refuses, and the two would decide disputes differently.
    ///
    /// Stateless. A keyless transaction additionally needs its JWK to be
    /// current, which [`crate::Instruction::VerifyJwk`] checks in the trace.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the key is not the sender's, or a signature or
    /// proof does not verify.
    pub fn authenticate(&self, keyless_ctx: &KeylessContext<'_>) -> Result<(), AuthError> {
        match &self.authenticator {
            Authenticator::Ed25519 {
                public_key,
                signature,
            } => {
                if self.sender != L2Address::from_bytes(*public_key) {
                    return Err(AuthError::WrongSigner);
                }
                verify_ed25519_strict(public_key, signature, &self.signing_digest())
            }
            Authenticator::Keyless(sig) => {
                keyless::verify(sig, &self.sender, &self.signing_digest(), keyless_ctx)
                    .map_err(AuthError::Keyless)
            }
        }
    }
}

/// Strict Ed25519 verification of `digest`, as Aptos L1 performs it.
pub(crate) fn verify_ed25519_strict(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    digest: &Hash256,
) -> Result<(), AuthError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| AuthError::MalformedKey)?;
    if key.is_weak() {
        return Err(AuthError::MalformedKey);
    }
    let sig = Signature::from_bytes(signature);
    key.verify_strict(digest.as_bytes(), &sig)
        .map_err(|_| AuthError::BadSignature)
}

/// Why a transaction failed authentication.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AuthError {
    /// The public key is not a valid Ed25519 point.
    #[error("malformed public key")]
    MalformedKey,
    /// The signature did not verify against the signing digest.
    #[error("signature does not verify")]
    BadSignature,
    /// The signing key does not belong to the sender.
    #[error("the signing key is not the sender's")]
    WrongSigner,
    /// The keyless authorisation was refused.
    #[error("keyless authorisation refused: {0}")]
    Keyless(#[from] KeylessError),
}
