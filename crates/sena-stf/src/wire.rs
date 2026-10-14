//! The canonical binary encoding of a transaction.
//!
//! This is what a batch publishes and what the batch commitment hashes. Aptos
//! L1 decodes exactly these bytes when a dispute needs a transaction
//! (`move/sena/sources/txcodec.move`), so the format is deliberately plain:
//! big-endian integers, `u32`-length-prefixed byte strings, one-byte
//! discriminants, no optional padding. Decoding is strict — every value has
//! exactly one encoding, and anything else is refused — because two encodings
//! of one transaction would let a sequencer publish data that verifiers and L1
//! read differently.

use sena_primitives::{
    AssetId, Channel, DecodeError, Hash256, HashedIdentifier, L2Address, Reader, Writer,
};

use crate::gas::WhitelistedAsset;
use crate::governance::{CouncilSignature, GovernanceUpdate};
use crate::keyless::KeylessSignature;
use crate::transaction::{Authenticator, Payload, Transaction};

/// The largest encoded transaction a batch may carry.
///
/// Bounds what Aptos L1 has to decode and hash when it adjudicates one. A
/// governance payload with a full council's signatures is the largest
/// legitimate transaction and fits comfortably.
pub const MAX_TRANSACTION_BYTES: usize = 8 * 1024;

/// The most council signatures one governance payload may carry.
pub const MAX_COUNCIL_SIGNATURES: usize = 32;

/// Why bytes are not a canonical transaction.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum WireError {
    /// The bytes are not a well-formed encoding.
    #[error("malformed transaction encoding: {0}")]
    Malformed(#[from] DecodeError),
    /// The encoding exceeds [`MAX_TRANSACTION_BYTES`].
    #[error("transaction is {0} bytes; at most {MAX_TRANSACTION_BYTES} are allowed")]
    TooLarge(usize),
    /// A governance payload carries more than [`MAX_COUNCIL_SIGNATURES`].
    #[error("too many council signatures")]
    TooManySignatures,
}

mod tag {
    pub const ED25519: u8 = 0;
    pub const KEYLESS: u8 = 1;
    pub const TRANSFER: u8 = 0;
    pub const BIND_IDENTIFIER: u8 = 1;
    pub const UNBIND_IDENTIFIER: u8 = 2;
    pub const GOVERNANCE: u8 = 3;
    pub const SET_GAS_ASSET: u8 = 0;
    pub const SET_PARAMETER: u8 = 1;
    pub const SET_JWK: u8 = 2;
}

fn write_keyless(w: &mut Writer, sig: &KeylessSignature) {
    w.bytes32(&sig.iss_hash);
    w.bytes32(&sig.idc);
    w.bytes32(&sig.ephemeral_public_key);
    w.raw(&sig.ephemeral_signature);
    w.u64(sig.exp_date_secs);
    w.u64(sig.exp_horizon_secs);
    w.bytes32(&sig.jwt_header_hash);
    w.bytes32(&sig.jwk_hash);
    match &sig.extra_field_hash {
        None => {
            w.u8(0);
        }
        Some(h) => {
            w.u8(1);
            w.bytes32(h);
        }
    }
    w.raw(&sig.proof);
}

fn read_keyless(r: &mut Reader<'_>) -> Result<KeylessSignature, DecodeError> {
    Ok(KeylessSignature {
        iss_hash: r.bytes32()?,
        idc: r.bytes32()?,
        ephemeral_public_key: r.bytes32()?,
        ephemeral_signature: r.array::<64>()?,
        exp_date_secs: r.u64()?,
        exp_horizon_secs: r.u64()?,
        jwt_header_hash: r.bytes32()?,
        jwk_hash: r.bytes32()?,
        extra_field_hash: if r.bool()? { Some(r.bytes32()?) } else { None },
        proof: r.array::<128>()?,
    })
}

/// Encodes a governance update. Also what the council signs (see
/// [`GovernanceUpdate::signing_digest`]).
pub(crate) fn write_update(w: &mut Writer, update: &GovernanceUpdate) {
    match update {
        GovernanceUpdate::SetGasAsset { record } => {
            w.u8(tag::SET_GAS_ASSET);
            w.bytes(&record.encode());
        }
        GovernanceUpdate::SetParameter { name, value } => {
            w.u8(tag::SET_PARAMETER);
            w.string(name);
            w.u128(*value);
        }
        GovernanceUpdate::SetJwk {
            iss_hash,
            jwk_hash,
            active,
        } => {
            w.u8(tag::SET_JWK);
            w.bytes32(iss_hash);
            w.bytes32(jwk_hash);
            w.bool(*active);
        }
    }
}

fn read_update(r: &mut Reader<'_>) -> Result<GovernanceUpdate, DecodeError> {
    Ok(match r.u8()? {
        tag::SET_GAS_ASSET => {
            let bytes = r.bytes()?;
            let record = WhitelistedAsset::decode(&bytes)
                .map_err(|_| DecodeError::UnknownVariant(tag::SET_GAS_ASSET))?;
            // The record must itself be canonical: re-encoding gives the same bytes.
            if record.encode() != bytes {
                return Err(DecodeError::UnknownVariant(tag::SET_GAS_ASSET));
            }
            GovernanceUpdate::SetGasAsset { record }
        }
        tag::SET_PARAMETER => GovernanceUpdate::SetParameter {
            name: r.string()?,
            value: r.u128()?,
        },
        tag::SET_JWK => GovernanceUpdate::SetJwk {
            iss_hash: r.bytes32()?,
            jwk_hash: r.bytes32()?,
            active: r.bool()?,
        },
        other => return Err(DecodeError::UnknownVariant(other)),
    })
}

/// Encodes a payload. Also part of what the sender signs.
pub(crate) fn write_payload(w: &mut Writer, payload: &Payload) {
    match payload {
        Payload::Transfer { to, asset, amount } => {
            w.u8(tag::TRANSFER);
            w.bytes32(to.as_bytes());
            w.u32(asset.get());
            w.u128(*amount);
        }
        Payload::BindIdentifier {
            channel,
            identifier,
        } => {
            w.u8(tag::BIND_IDENTIFIER);
            w.u8(channel.discriminant());
            w.bytes32(identifier.as_hash().as_bytes());
        }
        Payload::UnbindIdentifier { identifier } => {
            w.u8(tag::UNBIND_IDENTIFIER);
            w.bytes32(identifier.as_hash().as_bytes());
        }
        Payload::Governance {
            epoch,
            update,
            signatures,
        } => {
            w.u8(tag::GOVERNANCE);
            w.u64(*epoch);
            let mut inner = Writer::new();
            write_update(&mut inner, update);
            w.bytes(&inner.finish());
            w.u32(u32::try_from(signatures.len()).expect("bounded by MAX_COUNCIL_SIGNATURES"));
            for signature in signatures {
                w.u32(signature.index);
                w.bytes(&signature.signature);
            }
        }
    }
}

fn read_payload(r: &mut Reader<'_>) -> Result<Payload, WireError> {
    Ok(match r.u8()? {
        tag::TRANSFER => Payload::Transfer {
            to: L2Address::from_bytes(r.bytes32()?),
            asset: AssetId(r.u32()?),
            amount: r.u128()?,
        },
        tag::BIND_IDENTIFIER => {
            let d = r.u8()?;
            Payload::BindIdentifier {
                channel: Channel::from_discriminant(d).ok_or(DecodeError::UnknownVariant(d))?,
                identifier: HashedIdentifier(Hash256(r.bytes32()?)),
            }
        }
        tag::UNBIND_IDENTIFIER => Payload::UnbindIdentifier {
            identifier: HashedIdentifier(Hash256(r.bytes32()?)),
        },
        tag::GOVERNANCE => {
            let epoch = r.u64()?;
            let inner = r.bytes()?;
            let mut ir = Reader::new(&inner);
            let update = read_update(&mut ir)?;
            ir.finish()?;
            let count = r.u32()? as usize;
            if count > MAX_COUNCIL_SIGNATURES {
                return Err(WireError::TooManySignatures);
            }
            let mut signatures = Vec::with_capacity(count);
            for _ in 0..count {
                let index = r.u32()?;
                let sig = r.bytes()?;
                let signature: [u8; 64] =
                    sig.try_into().map_err(|_| DecodeError::LengthOverflow)?;
                signatures.push(CouncilSignature { index, signature });
            }
            Payload::Governance {
                epoch,
                update,
                signatures,
            }
        }
        other => return Err(DecodeError::UnknownVariant(other).into()),
    })
}

/// Encodes a transaction canonically.
#[must_use]
pub fn encode(tx: &Transaction) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes32(tx.sender.as_bytes());
    w.u64(tx.nonce);
    w.u32(tx.fee_asset.get());
    w.u128(tx.max_fee);
    w.u128(tx.fee_rate);
    let mut payload = Writer::new();
    write_payload(&mut payload, &tx.payload);
    w.bytes(&payload.finish());
    match &tx.authenticator {
        Authenticator::Ed25519 {
            public_key,
            signature,
        } => {
            w.u8(tag::ED25519);
            w.bytes32(public_key);
            w.raw(signature);
        }
        Authenticator::Keyless(sig) => {
            w.u8(tag::KEYLESS);
            write_keyless(&mut w, sig);
        }
    }
    w.finish()
}

/// Decodes a canonically encoded transaction.
///
/// # Errors
///
/// Returns [`WireError`] unless `bytes` is exactly the canonical encoding of a
/// transaction within the size limits.
pub fn decode(bytes: &[u8]) -> Result<Transaction, WireError> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(WireError::TooLarge(bytes.len()));
    }
    let mut r = Reader::new(bytes);
    let sender = L2Address::from_bytes(r.bytes32()?);
    let nonce = r.u64()?;
    let fee_asset = AssetId(r.u32()?);
    let max_fee = r.u128()?;
    let fee_rate = r.u128()?;
    let payload_bytes = r.bytes()?;
    let mut pr = Reader::new(&payload_bytes);
    let payload = read_payload(&mut pr)?;
    pr.finish()?;
    let authenticator = match r.u8()? {
        tag::ED25519 => Authenticator::Ed25519 {
            public_key: r.bytes32()?,
            signature: r.array::<64>()?,
        },
        tag::KEYLESS => Authenticator::Keyless(Box::new(read_keyless(&mut r)?)),
        other => return Err(DecodeError::UnknownVariant(other).into()),
    };
    r.finish()?;
    let tx = Transaction {
        sender,
        nonce,
        fee_asset,
        max_fee,
        fee_rate,
        payload,
        authenticator,
    };
    // Strictness backstop: anything that decodes must re-encode to itself.
    if encode(&tx) != bytes {
        return Err(DecodeError::UnknownVariant(0xff).into());
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyless::aptos_sample;

    fn transfer() -> Transaction {
        Transaction {
            sender: L2Address::from_bytes([1; 32]),
            nonce: 7,
            fee_asset: AssetId(1),
            max_fee: 1_000,
            fee_rate: 1_000_000,
            payload: Payload::Transfer {
                to: L2Address::from_bytes([2; 32]),
                asset: AssetId(1),
                amount: 5,
            },
            authenticator: Authenticator::Ed25519 {
                public_key: [1; 32],
                signature: [3; 64],
            },
        }
    }

    #[test]
    fn round_trips() {
        let mut txs = vec![transfer()];
        let mut keyless = transfer();
        keyless.authenticator = Authenticator::Keyless(Box::new(aptos_sample::signature()));
        txs.push(keyless);
        let mut gov = transfer();
        gov.payload = Payload::Governance {
            epoch: 3,
            update: GovernanceUpdate::SetJwk {
                iss_hash: [4; 32],
                jwk_hash: [5; 32],
                active: true,
            },
            signatures: vec![CouncilSignature {
                index: 0,
                signature: [6; 64],
            }],
        };
        txs.push(gov);
        for tx in txs {
            assert_eq!(decode(&encode(&tx)).unwrap(), tx);
        }
    }

    #[test]
    fn trailing_and_truncated_bytes_are_refused() {
        let mut bytes = encode(&transfer());
        bytes.push(0);
        assert!(decode(&bytes).is_err());
        bytes.pop();
        bytes.pop();
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn oversized_input_is_refused() {
        assert_eq!(
            decode(&vec![0; MAX_TRANSACTION_BYTES + 1]),
            Err(WireError::TooLarge(MAX_TRANSACTION_BYTES + 1))
        );
    }

    #[test]
    fn a_non_boolean_flag_is_refused() {
        let mut keyless = transfer();
        keyless.authenticator = Authenticator::Keyless(Box::new(aptos_sample::signature()));
        let mut bytes = encode(&keyless);
        // The extra-field flag sits 128 + 32 bytes before the end.
        let flag = bytes.len() - 128 - 32 - 1;
        assert_eq!(bytes[flag], 1);
        bytes[flag] = 2;
        assert!(decode(&bytes).is_err());
    }
}
