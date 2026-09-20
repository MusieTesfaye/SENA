//! Transactions and how they are authenticated.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sena_primitives::{
    domain, AssetId, CanonicalEncoder, Channel, Hash256, HashedIdentifier, L2Address,
};
use serde::{Deserialize, Serialize};

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
}

/// How a transaction proves it was authorised.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "scheme")]
pub enum Authenticator {
    /// A plain Ed25519 signature by a key the account controls directly.
    Ed25519 {
        /// The signing key, as 32 raw bytes.
        #[serde(with = "hex_bytes_32")]
        public_key: [u8; 32],
        /// The signature, as 64 raw bytes.
        #[serde(with = "hex_bytes_64")]
        signature: [u8; 64],
    },
    /// An OIDC keyless authorisation (REQ-AUTH-003, REQ-AUTH-004).
    ///
    /// # Not yet implemented
    ///
    /// The ephemeral key signature is checked, but the zero-knowledge proof that
    /// binds that ephemeral key to a genuine Web2 JWT is **not**. Accepting this
    /// scheme as-is would let anyone spend from any keyless account by
    /// generating their own ephemeral key, so [`Transaction::authenticate`]
    /// rejects it outright rather than verifying the part that is implemented
    /// and quietly skipping the part that is not.
    ///
    /// The variant exists so that the wire format, address derivation and
    /// transaction plumbing can be built and tested ahead of proof verification
    /// landing. It is deliberately inert until then.
    Keyless {
        /// The ephemeral public key that signed this transaction.
        #[serde(with = "hex_bytes_32")]
        ephemeral_public_key: [u8; 32],
        /// The ephemeral key's signature over the transaction.
        #[serde(with = "hex_bytes_64")]
        signature: [u8; 64],
        /// The proof binding the ephemeral key to a JWT. Not yet verified.
        zk_proof: Vec<u8>,
    },
}

/// A transaction as submitted to the sequencer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// The account the transaction acts on behalf of.
    pub sender: L2Address,
    /// The sender's expected nonce. Must equal the account's current nonce.
    pub nonce: u64,
    /// The asset the fee is paid in (REQ-GAS-001).
    pub fee_asset: AssetId,
    /// The maximum fee the sender will pay, in units of `fee_asset`.
    pub max_fee: u128,
    /// What to do.
    pub payload: Payload,
    /// Proof of authorisation.
    pub authenticator: Authenticator,
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
    /// Panics only if serialising the payload fails, which cannot occur.
    #[must_use]
    pub fn signing_digest(&self) -> Hash256 {
        let payload = serde_json::to_vec(&self.payload).expect("payload serialisation cannot fail");
        Hash256::commit(
            CanonicalEncoder::new(domain::TRANSACTION)
                .field(self.sender.as_bytes())
                .u64(self.nonce)
                .u64(u64::from(self.fee_asset.get()))
                .u128(self.max_fee)
                .field(&payload),
        )
    }

    /// Returns the transaction's identifier.
    ///
    /// # Panics
    ///
    /// Panics only if serialising the transaction fails, which cannot occur.
    #[must_use]
    pub fn hash(&self) -> Hash256 {
        let encoded = serde_json::to_vec(self).expect("transaction serialisation cannot fail");
        Hash256::digest(&encoded)
    }

    /// Checks that the transaction is authorised.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the signature is malformed or does not verify,
    /// or if the scheme is not yet supported.
    pub fn authenticate(&self) -> Result<(), AuthError> {
        match &self.authenticator {
            Authenticator::Ed25519 {
                public_key,
                signature,
            } => {
                let key =
                    VerifyingKey::from_bytes(public_key).map_err(|_| AuthError::MalformedKey)?;
                let sig = Signature::from_bytes(signature);
                key.verify(self.signing_digest().as_bytes(), &sig)
                    .map_err(|_| AuthError::BadSignature)
            }
            Authenticator::Keyless { .. } => Err(AuthError::KeylessNotImplemented),
        }
    }
}

/// Why a transaction failed authentication.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AuthError {
    /// The public key is not a valid Ed25519 point.
    #[error("malformed public key")]
    MalformedKey,
    /// The signature did not verify against the signing digest.
    #[error("signature does not verify")]
    BadSignature,
    /// Keyless authentication is not yet available.
    #[error(
        "keyless authentication is not implemented: the ZK proof binding the \
             ephemeral key to a JWT is not yet verified, so the scheme is rejected \
             rather than accepted unchecked"
    )]
    KeylessNotImplemented,
}

/// Hex serialisation for fixed 32-byte arrays, which serde cannot derive.
mod hex_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Hex serialisation for fixed 64-byte arrays.
mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
