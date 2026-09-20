//! The multi-asset gas paymaster (REQ-GAS-001 through REQ-GAS-010).
//!
//! Users pay fees in a whitelisted stablecoin rather than a volatile native
//! token. The network prices work in native units; a transaction declares which
//! asset it pays in and at what rate, and the chain checks that declaration
//! against the on-chain whitelist.
//!
//! # Why the rate travels in the transaction
//!
//! It would be more natural for the sequencer to look the rate up while
//! executing. It is not permitted, because of a constraint that runs through the
//! whole fraud proof design: the instruction a disputed step contains must be
//! derivable by Aptos L1 from the batch data alone. That holds only while
//! compilation is a pure function of the transaction — see
//! [`crate::execute::compile`].
//!
//! So the sender states the rate they believe applies, the fee follows from it
//! by fixed arithmetic, and [`Instruction::VerifyGasAsset`] checks the claim
//! against state as an ordinary step in the trace. A sequencer that honours a
//! rate the whitelist does not contain produces a trace whose verification step
//! fails, which is exactly a fraud proof.
//!
//! The visible consequence is that a rate change invalidates in-flight
//! transactions, much as a gas price change does elsewhere. Wallets reread the
//! rate and resubmit.
//!
//! [`Instruction::VerifyGasAsset`]: crate::Instruction::VerifyGasAsset

use sena_primitives::serde_hex::u128_string;
use sena_primitives::{AssetId, DecodeError, Reader, Writer};
use serde::{Deserialize, Serialize};

/// Fixed-point scale for exchange rates: rates are expressed in millionths.
///
/// Integer arithmetic throughout. Floating point is denied workspace-wide
/// because rounding differs across platforms and optimisation levels, and a fee
/// that differs by one unit between two honest nodes is a chain split
/// (REQ-FRAUD-031).
pub const RATE_SCALE: u128 = 1_000_000;

/// The base cost of a transaction, in native units.
///
/// A flat charge for now. Pricing by the work a transaction actually does
/// requires metering each instruction, which is tracked as follow-up work.
pub const BASE_GAS_NATIVE: u128 = 1_000;

/// A whitelisted gas asset and its rate (REQ-GAS-003).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WhitelistedAsset {
    /// The asset this record governs.
    pub asset: AssetId,
    /// Human-readable symbol, for tooling.
    pub symbol: String,
    /// Units of this asset per [`RATE_SCALE`] native units.
    #[serde(with = "u128_string")]
    pub rate: u128,
    /// Whether the asset may currently be used for fees.
    ///
    /// Governance disables an asset rather than removing the record, both
    /// because the trie is structurally append-only and because the history of
    /// an asset having been accepted stays auditable.
    pub enabled: bool,
}

impl WhitelistedAsset {
    /// Encodes the record for storage.
    ///
    /// Canonical binary rather than JSON, so `sena::osp` can decode it in Move
    /// when adjudicating a disputed `VerifyGasAsset` step.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.asset.get());
        w.string(&self.symbol);
        w.u128(self.rate);
        w.bool(self.enabled);
        w.finish()
    }

    /// Decodes a stored record.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedAsset`] if the bytes are not a canonical record.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedAsset> {
        Self::decode_inner(bytes).map_err(|_| MalformedAsset)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let record = Self {
            asset: AssetId(r.u32()?),
            symbol: r.string()?,
            rate: r.u128()?,
            enabled: r.bool()?,
        };
        r.finish()?;
        Ok(record)
    }
}

/// The stored bytes were not a valid [`WhitelistedAsset`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("stored gas asset record is malformed")]
pub struct MalformedAsset;

/// Converts a native-unit cost into the equivalent amount of a gas asset.
///
/// Rounds **up**. Rounding down would let any cost below one unit of the fee
/// asset round to zero, making transactions free in that asset and handing an
/// attacker unlimited free execution — the rounding direction is a
/// denial-of-service control, not a matter of taste.
///
/// # Errors
///
/// Returns [`GasError`] if the rate is zero or the conversion overflows.
pub fn convert(native_amount: u128, rate: u128) -> Result<u128, GasError> {
    if rate == 0 {
        return Err(GasError::ZeroRate);
    }
    let scaled = native_amount.checked_mul(rate).ok_or(GasError::Overflow)?;
    // Ceiling division without floats: (a + b - 1) / b, with the addition
    // checked so a near-maximal product cannot wrap.
    let rounded_up = scaled
        .checked_add(RATE_SCALE - 1)
        .ok_or(GasError::Overflow)?;
    Ok(rounded_up / RATE_SCALE)
}

/// Returns the fee a transaction owes, in units of its declared gas asset.
///
/// # Errors
///
/// Returns [`GasError`] if the conversion fails.
pub fn fee_for(rate: u128) -> Result<u128, GasError> {
    convert(BASE_GAS_NATIVE, rate)
}

/// Why a gas computation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum GasError {
    /// A rate of zero would make execution free.
    #[error("gas asset rate is zero")]
    ZeroRate,
    /// The conversion exceeded the representable range.
    #[error("gas conversion overflowed")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_rate_is_the_identity() {
        assert_eq!(convert(1_000, RATE_SCALE).unwrap(), 1_000);
    }

    #[test]
    fn conversion_scales() {
        // Half the value of a native unit: twice as many units needed.
        assert_eq!(convert(1_000, 2 * RATE_SCALE).unwrap(), 2_000);
        assert_eq!(convert(1_000, RATE_SCALE / 2).unwrap(), 500);
    }

    #[test]
    fn small_fees_round_up_rather_than_to_zero() {
        // The attack this prevents: a rate low enough that every fee truncates
        // to nothing, making execution free.
        assert_eq!(convert(1, 1).unwrap(), 1);
        assert_eq!(convert(1_000, 1).unwrap(), 1);
        assert!(convert(1, RATE_SCALE - 1).unwrap() >= 1);
    }

    #[test]
    fn exact_multiples_do_not_gain_a_unit() {
        // Rounding up must not overcharge when the division is exact.
        assert_eq!(convert(2_000, RATE_SCALE).unwrap(), 2_000);
        assert_eq!(convert(3, 2 * RATE_SCALE).unwrap(), 6);
    }

    #[test]
    fn a_zero_rate_is_rejected() {
        assert_eq!(convert(1_000, 0).unwrap_err(), GasError::ZeroRate);
    }

    #[test]
    fn overflow_is_reported_rather_than_wrapping() {
        assert_eq!(
            convert(u128::MAX, 2 * RATE_SCALE).unwrap_err(),
            GasError::Overflow
        );
    }

    #[test]
    fn zero_cost_converts_to_zero() {
        assert_eq!(convert(0, RATE_SCALE).unwrap(), 0);
    }

    #[test]
    fn determinism_conversion_is_pure_integer_arithmetic() {
        let a = convert(7_919, 1_234_567).unwrap();
        let b = convert(7_919, 1_234_567).unwrap();
        println!("root={a:032x}");
        assert_eq!(a, b);
    }

    #[test]
    fn asset_record_round_trips() {
        let record = WhitelistedAsset {
            asset: AssetId(1),
            symbol: "USDC".to_owned(),
            rate: RATE_SCALE,
            enabled: true,
        };
        assert_eq!(WhitelistedAsset::decode(&record.encode()).unwrap(), record);
    }
}
