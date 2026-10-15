//! Fees: metered gas, a base fee that follows demand, and payment in any
//! whitelisted stablecoin (REQ-GAS-001 through REQ-GAS-010).
//!
//! The design follows Celo's fee abstraction, adapted to a chain with no
//! native token:
//!
//! - **Gas is metered.** Every transaction costs [`INTRINSIC_GAS`], plus its fee
//!   asset's own intrinsic gas, plus what its authenticator and payload cost
//!   ([`gas_used`]). Compilation is static, so the gas a transaction uses is
//!   known before it runs; a transaction whose limit is too low is refused
//!   rather than half-executed.
//! - **The base fee follows demand** (EIP-1559): a [`FeeMarket`] record in state
//!   raises it when the last window used more than its target and lowers it
//!   when it used less, never below a governed floor. A window is one batch
//!   timestamp, i.e. one second.
//! - **The base fee is priced in native units** — micro-dollars, since SENA has
//!   no native token — and converted into the fee asset at its whitelisted
//!   rate, rounding down as Celo's `ConvertCeloToCurrency` does.
//! - **The limit is held, the unused part refunded.** A transaction offers a
//!   gas limit, a maximum fee per gas and a maximum tip per gas, all in its fee
//!   asset. It pays the effective price — the base fee plus its tip, capped at
//!   its maximum — and `gas_limit ×` that price is debited before the payload
//!   runs; afterwards the unused gas is refunded, the tip goes to the sequencer
//!   and the base fee to [`FEE_VAULT`](crate::FEE_VAULT) ([`settle`]).
//! - **Prices are high precision.** Stablecoins have six decimals, too few to
//!   price one unit of gas, so per-gas prices are in [`PRICE_SCALE`]ths of a
//!   unit and only the totals are rounded to whole units — Celo's
//!   `FeeCurrencyAdapter`. Every rounding remainder goes to the base fee, so
//!   exactly what was held is paid out.
//! - **Collected fees are split by governance** ([`FeeSplit`]) between named
//!   beneficiaries and a burn, like Celo's `FeeHandler`.
//!
//! # Why the rate travels in the transaction
//!
//! It would be more natural for the sequencer to look the rate up while
//! executing. It is not permitted, because of a constraint that runs through the
//! whole fraud proof design: the instruction a disputed step contains must be
//! derivable by Aptos L1 from the batch data alone. That holds only while
//! compilation is a pure function of the transaction and the batch context —
//! see [`crate::execute::compile`].
//!
//! So the sender states the rate and intrinsic gas they believe apply, and the
//! sequencer states the batch's base fee in its header. The fee follows from
//! those by fixed arithmetic, and in-trace instructions check every claim
//! against state: [`Instruction::VerifyGasAsset`] the asset's record,
//! [`Instruction::ChargeBaseFee`] the fee market. A claim that does not match
//! state makes its step fail, which is exactly a fraud proof.
//!
//! [`Instruction::VerifyGasAsset`]: crate::Instruction::VerifyGasAsset
//! [`Instruction::ChargeBaseFee`]: crate::Instruction::ChargeBaseFee

use sena_primitives::serde_hex::u128_string;
use sena_primitives::{AssetId, DecodeError, L2Address, Reader, Writer};
use serde::{Deserialize, Serialize};

use crate::instruction::Instruction;
use crate::transaction::{Authenticator, Transaction};

/// Fixed-point scale for exchange rates: rates are expressed in millionths.
///
/// Integer arithmetic throughout. Floating point is denied workspace-wide
/// because rounding differs across platforms and optimisation levels, and a fee
/// that differs by one unit between two honest nodes is a chain split
/// (REQ-FRAUD-031).
pub const RATE_SCALE: u128 = 1_000_000;

/// Per-gas prices are in units of `1 / PRICE_SCALE` of a whole asset unit.
pub const PRICE_SCALE: u128 = 1_000_000_000_000;

/// Gas every transaction pays before anything else: Ethereum's 21,000.
pub const INTRINSIC_GAS: u64 = 21_000;

/// Gas for verifying a keyless authenticator (a Groth16 proof and the
/// Poseidon public-input hash), on top of [`INTRINSIC_GAS`].
pub const KEYLESS_GAS: u64 = 100_000;

/// The most gas one transaction may ask for.
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// How far the gas used in a window may exceed its target (EIP-1559).
pub const ELASTICITY: u64 = 2;

/// The base fee moves by at most `1 / BASE_FEE_CHANGE_DENOMINATOR` per window
/// (EIP-1559).
pub const BASE_FEE_CHANGE_DENOMINATOR: u128 = 8;

/// The genesis base fee floor: 0.025 native units (micro-dollars) per gas, in
/// [`PRICE_SCALE`]ths. A plain USDC transfer then costs about a tenth of a cent.
pub const DEFAULT_BASE_FEE_FLOOR: u128 = 25_000_000_000;

/// The genesis gas target per window.
pub const DEFAULT_GAS_TARGET: u64 = 5_000_000;

/// The gas a fee asset charges by default for moving fees in it.
pub const DEFAULT_ASSET_INTRINSIC_GAS: u64 = 10_000;

/// Parts per million: the denominator of every [`FeeSplit`] share.
pub const SHARE_SCALE: u32 = 1_000_000;

/// The most beneficiaries a [`FeeSplit`] may name.
pub const MAX_FEE_BENEFICIARIES: usize = 8;

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
    /// Gas a transaction paying in this asset pays on top of
    /// [`INTRINSIC_GAS`], for moving its fees (Celo's per-currency intrinsic
    /// gas).
    #[serde(default = "default_asset_intrinsic_gas")]
    pub intrinsic_gas: u64,
    /// Whether the asset may currently be used for fees.
    ///
    /// Governance disables an asset rather than removing the record, both
    /// because the trie is structurally append-only and because the history of
    /// an asset having been accepted stays auditable.
    pub enabled: bool,
}

const fn default_asset_intrinsic_gas() -> u64 {
    DEFAULT_ASSET_INTRINSIC_GAS
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
        w.u64(self.intrinsic_gas);
        w.bool(self.enabled);
        w.finish()
    }

    /// Decodes a stored record.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedRecord`] if the bytes are not a canonical record.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedRecord> {
        Self::decode_inner(bytes).map_err(|_| MalformedRecord)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let record = Self {
            asset: AssetId(r.u32()?),
            symbol: r.string()?,
            rate: r.u128()?,
            intrinsic_gas: r.u64()?,
            enabled: r.bool()?,
        };
        r.finish()?;
        Ok(record)
    }
}

/// Stored bytes were not a valid fee record.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("stored fee record is malformed")]
pub struct MalformedRecord;

/// The base fee and the demand it follows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FeeMarket {
    /// The current base fee per gas, in [`PRICE_SCALE`]ths of a native unit.
    #[serde(with = "u128_string")]
    pub base_fee: u128,
    /// The lowest the base fee may go (Celo's base fee floor). Governed.
    #[serde(with = "u128_string")]
    pub floor: u128,
    /// The gas a window aims to use. Governed. A window may use up to
    /// [`ELASTICITY`] times this.
    pub target: u64,
    /// The batch timestamp of the current window.
    pub window_ts: u64,
    /// Gas used so far in the current window.
    pub window_gas: u64,
}

impl FeeMarket {
    /// A market starting at `floor` with nothing used yet.
    #[must_use]
    pub const fn genesis(floor: u128, target: u64) -> Self {
        Self {
            base_fee: floor,
            floor,
            target,
            window_ts: 0,
            window_gas: 0,
        }
    }

    /// The most gas one window may use.
    #[must_use]
    pub const fn window_limit(&self) -> u64 {
        self.target.saturating_mul(ELASTICITY)
    }

    /// The base fee a batch stamped `timestamp` pays: the current one if it
    /// falls in the current window, otherwise one EIP-1559 step on from it.
    ///
    /// # Errors
    ///
    /// Returns [`GasError`] if the timestamp precedes the window or the update
    /// overflows.
    pub fn base_fee_at(&self, timestamp: u64) -> Result<u128, GasError> {
        Ok(self.at(timestamp)?.base_fee)
    }

    /// The market as a batch stamped `timestamp` sees it: rolled into a new
    /// window if `timestamp` is past the current one.
    ///
    /// A gap of several idle seconds advances the base fee by one step, not
    /// one per second; the floor bounds how far down it can go anyway.
    ///
    /// # Errors
    ///
    /// Returns [`GasError::TimestampRegressed`] if `timestamp` precedes the
    /// current window, and [`GasError::Overflow`] on overflow.
    pub fn at(&self, timestamp: u64) -> Result<Self, GasError> {
        if timestamp < self.window_ts {
            return Err(GasError::TimestampRegressed);
        }
        if timestamp == self.window_ts {
            return Ok(*self);
        }
        Ok(Self {
            base_fee: next_base_fee(self.base_fee, self.window_gas, self.target, self.floor)?,
            window_ts: timestamp,
            window_gas: 0,
            ..*self
        })
    }

    /// Encodes the record for storage.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u128(self.base_fee)
            .u128(self.floor)
            .u64(self.target)
            .u64(self.window_ts)
            .u64(self.window_gas);
        w.finish()
    }

    /// Decodes a stored record.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedRecord`] if the bytes are not a canonical record.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedRecord> {
        let inner = |bytes| -> Result<Self, DecodeError> {
            let mut r = Reader::new(bytes);
            let m = Self {
                base_fee: r.u128()?,
                floor: r.u128()?,
                target: r.u64()?,
                window_ts: r.u64()?,
                window_gas: r.u64()?,
            };
            r.finish()?;
            Ok(m)
        };
        inner(bytes).map_err(|_| MalformedRecord)
    }
}

/// One EIP-1559 step: the base fee after a window that used `gas` against
/// `target`, never below `floor`.
///
/// A target of zero is treated as "every window is over target", so the fee
/// only rises; governance refuses to set one.
///
/// # Errors
///
/// Returns [`GasError::Overflow`] if the fee would exceed `u128`.
pub fn next_base_fee(base: u128, gas: u64, target: u64, floor: u128) -> Result<u128, GasError> {
    let (gas, target) = (u128::from(gas), u128::from(target));
    let next = if target == 0 || gas > target {
        let excess = if target == 0 { gas } else { gas - target };
        let delta = base.checked_mul(excess).ok_or(GasError::Overflow)?
            / target.max(1)
            / BASE_FEE_CHANGE_DENOMINATOR;
        base.checked_add(delta.max(1)).ok_or(GasError::Overflow)?
    } else {
        // `base * (target - gas)` fits: target - gas <= u64::MAX, and a base
        // fee near u128::MAX / 2^64 is unreachable from any sane floor; checked
        // anyway.
        let delta = base.checked_mul(target - gas).ok_or(GasError::Overflow)?
            / target
            / BASE_FEE_CHANGE_DENOMINATOR;
        base - delta
    };
    Ok(next.max(floor))
}

/// How collected base fees are shared out (Celo's `FeeHandler`).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct FeeSplit {
    /// Each beneficiary and its share, in parts per [`SHARE_SCALE`].
    pub beneficiaries: Vec<(L2Address, u32)>,
    /// The share burned, in parts per [`SHARE_SCALE`].
    ///
    /// Burning a bridged asset on L2 leaves its backing locked in L1 custody
    /// for good.
    pub burn: u32,
}

impl FeeSplit {
    /// Checks the split is well-formed: at most [`MAX_FEE_BENEFICIARIES`]
    /// distinct beneficiaries with non-zero shares, all shares adding up to
    /// exactly [`SHARE_SCALE`].
    ///
    /// # Errors
    ///
    /// Returns [`GasError::InvalidFeeSplit`] otherwise.
    pub fn check(&self) -> Result<(), GasError> {
        if self.beneficiaries.len() > MAX_FEE_BENEFICIARIES {
            return Err(GasError::InvalidFeeSplit);
        }
        let mut total = u64::from(self.burn);
        for (i, (address, share)) in self.beneficiaries.iter().enumerate() {
            if *share == 0 || self.beneficiaries[..i].iter().any(|(a, _)| a == address) {
                return Err(GasError::InvalidFeeSplit);
            }
            total += u64::from(*share);
        }
        if total == u64::from(SHARE_SCALE) {
            Ok(())
        } else {
            Err(GasError::InvalidFeeSplit)
        }
    }

    /// What each beneficiary receives from `amount`, rounded down; the rest,
    /// rounding included, is burned.
    ///
    /// # Errors
    ///
    /// Returns [`GasError::Overflow`] on overflow.
    pub fn shares_of(&self, amount: u128) -> Result<Vec<(L2Address, u128)>, GasError> {
        self.beneficiaries
            .iter()
            .map(|(address, share)| {
                let value = amount
                    .checked_mul(u128::from(*share))
                    .ok_or(GasError::Overflow)?
                    / u128::from(SHARE_SCALE);
                Ok((*address, value))
            })
            .collect()
    }

    /// Encodes the split canonically, for storage and the wire.
    ///
    /// # Panics
    ///
    /// Does not panic for a split that passes [`FeeSplit::check`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(u32::try_from(self.beneficiaries.len()).expect("bounded by MAX_FEE_BENEFICIARIES"));
        for (address, share) in &self.beneficiaries {
            w.bytes32(address.as_bytes()).u32(*share);
        }
        w.u32(self.burn);
        w.finish()
    }

    /// Decodes a split.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedRecord`] if the bytes are not canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self, MalformedRecord> {
        let inner = |bytes| -> Result<Self, DecodeError> {
            let mut r = Reader::new(bytes);
            let count = r.u32()? as usize;
            if count > MAX_FEE_BENEFICIARIES {
                return Err(DecodeError::LengthOverflow);
            }
            let mut beneficiaries = Vec::with_capacity(count);
            for _ in 0..count {
                beneficiaries.push((L2Address::from_bytes(r.bytes32()?), r.u32()?));
            }
            let burn = r.u32()?;
            r.finish()?;
            Ok(Self {
                beneficiaries,
                burn,
            })
        };
        inner(bytes).map_err(|_| MalformedRecord)
    }
}

/// The gas one instruction of a payload costs.
///
/// The steps every transaction runs — nonce, fee checks, holding and settling
/// the fee — are covered by [`INTRINSIC_GAS`] and the asset's intrinsic gas,
/// so they cost nothing here. Writes that create state cost more than writes
/// that update it.
#[must_use]
pub fn instruction_gas(instruction: &Instruction) -> u64 {
    match instruction {
        Instruction::Debit { .. }
        | Instruction::Credit { .. }
        | Instruction::UnbindIdentifier { .. } => 5_000,
        // Bounded by the wire format's signature limit, so no overflow.
        Instruction::VerifyCouncil { signatures, .. } => 10_000 + 3_000 * signatures.len() as u64,
        Instruction::BindIdentifier { .. }
        | Instruction::SetGasAsset { .. }
        | Instruction::SetParameter { .. }
        | Instruction::SetJwk { .. }
        | Instruction::SetFeeMarket { .. }
        | Instruction::SetFeeSplit { .. }
        | Instruction::DisableGasAsset { .. } => 20_000,
        Instruction::VerifyFeeSplit { .. } => 2_000,
        Instruction::ConsumeNonce { .. }
        | Instruction::VerifyGasAsset { .. }
        | Instruction::ChargeBaseFee { .. }
        | Instruction::VerifyJwk { .. } => 0,
    }
}

/// The gas a transaction uses: [`INTRINSIC_GAS`], its fee asset's intrinsic
/// gas (as the transaction declares it), its authenticator, and its payload's
/// instructions.
///
/// # Errors
///
/// Returns [`GasError::Overflow`] if the sum overflows.
pub fn gas_used(transaction: &Transaction, payload: &[Instruction]) -> Result<u64, GasError> {
    let auth = match transaction.authenticator {
        Authenticator::Ed25519 { .. } => 0,
        Authenticator::Keyless(_) => KEYLESS_GAS,
    };
    payload.iter().try_fold(
        INTRINSIC_GAS
            .checked_add(transaction.fee_intrinsic_gas)
            .and_then(|g| g.checked_add(auth))
            .ok_or(GasError::Overflow)?,
        |total, i| {
            total
                .checked_add(instruction_gas(i))
                .ok_or(GasError::Overflow)
        },
    )
}

/// Converts a native-unit price into the fee asset at `rate`, rounding down
/// as Celo's `ConvertCeloToCurrency` does: `native × rate / RATE_SCALE`.
///
/// # Errors
///
/// Returns [`GasError`] if the rate is zero or the product overflows.
pub fn native_to_asset(native: u128, rate: u128) -> Result<u128, GasError> {
    if rate == 0 {
        return Err(GasError::ZeroRate);
    }
    Ok(native.checked_mul(rate).ok_or(GasError::Overflow)? / RATE_SCALE)
}

/// What a transaction's fee comes to, in whole units of its fee asset.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FeeCharge {
    /// Gas the transaction uses.
    pub gas_used: u64,
    /// Debited before the payload runs: `gas_limit ×` the effective price.
    pub hold: u128,
    /// Returned to the sender: the unused gas at the effective price.
    pub refund: u128,
    /// Paid to the sequencer.
    pub tip: u128,
    /// Paid to the fee vault, with every rounding remainder.
    pub base: u128,
}

/// Works out what a transaction pays, as Celo's `debitGasFees` and
/// `creditGasFees` do.
///
/// Per-gas prices are in [`PRICE_SCALE`]ths of a unit; `base_fee` is in
/// native units and converted at `rate`. The tip per gas is the sender's
/// priority fee, capped so that base fee plus tip never exceeds their maximum;
/// the effective price per gas is base fee plus tip, as in EIP-1559. Totals are
/// rounded down to whole units, and whatever the rounding leaves of the hold is
/// added to the base fee, so `refund + tip + base == hold` exactly.
///
/// # Errors
///
/// Returns [`GasError`] if the maximum fee is below the base fee, the limit is
/// below the gas used, the hold rounds to nothing, or anything overflows.
pub fn settle(
    gas_limit: u64,
    gas_used: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    base_fee: u128,
    rate: u128,
) -> Result<FeeCharge, GasError> {
    if gas_limit > MAX_GAS_LIMIT {
        return Err(GasError::GasLimitTooHigh { limit: gas_limit });
    }
    if gas_used > gas_limit {
        return Err(GasError::GasLimitTooLow {
            limit: gas_limit,
            required: gas_used,
        });
    }
    let base_per_gas = native_to_asset(base_fee, rate)?;
    if max_fee_per_gas < base_per_gas {
        return Err(GasError::FeeBelowBaseFee {
            offered: max_fee_per_gas,
            base_fee: base_per_gas,
        });
    }
    let tip_per_gas = max_priority_fee_per_gas.min(max_fee_per_gas - base_per_gas);
    // Cannot overflow: at most max_fee_per_gas.
    let price = base_per_gas + tip_per_gas;
    let total = |gas: u64, price: u128| -> Result<u128, GasError> {
        u128::from(gas)
            .checked_mul(price)
            .map(|v| v / PRICE_SCALE)
            .ok_or(GasError::Overflow)
    };
    let hold = total(gas_limit, price)?;
    if hold == 0 {
        // Celo's adapter: "Scaled debit value must be > 0." Otherwise a
        // transaction could execute for free.
        return Err(GasError::FeeRoundsToZero);
    }
    let refund = total(gas_limit - gas_used, price)?;
    let tip = total(gas_used, tip_per_gas)?;
    let base = total(gas_used, base_per_gas)?;
    // Each part is at most its exact value, and the exact values sum to at
    // most the exact hold, so the floors cannot exceed the floored hold.
    let remainder = hold - refund - tip - base;
    Ok(FeeCharge {
        gas_used,
        hold,
        refund,
        tip,
        base: base + remainder,
    })
}

/// Fills in a transaction's fee terms for paying in an asset at `rate` with
/// `intrinsic_gas`: up to `max_fee_per_gas`, no tip, and a gas limit of
/// exactly what the transaction uses (gas is static, so nothing is guessed).
/// Leaves the signature for the caller.
///
/// A payload that does not compile gets a limit of [`INTRINSIC_GAS`], which
/// compilation will refuse anyway.
pub fn fill_fees(
    transaction: &mut Transaction,
    rate: u128,
    intrinsic_gas: u64,
    max_fee_per_gas: u128,
) {
    transaction.fee_rate = rate;
    transaction.fee_intrinsic_gas = intrinsic_gas;
    transaction.max_fee_per_gas = max_fee_per_gas;
    transaction.max_priority_fee_per_gas = 0;
    transaction.gas_limit = crate::execute::gas_required(transaction).unwrap_or(INTRINSIC_GAS);
}

/// [`fill_fees`] for an asset whitelisted one-to-one with native units at the
/// default intrinsic gas, with room for the base fee to double from its
/// default floor — the development genesis's USDC.
pub fn fill_default_fees(transaction: &mut Transaction) {
    fill_fees(
        transaction,
        RATE_SCALE,
        DEFAULT_ASSET_INTRINSIC_GAS,
        2 * DEFAULT_BASE_FEE_FLOOR,
    );
}

/// Why a fee computation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum GasError {
    /// A rate of zero would make execution free.
    #[error("gas asset rate is zero")]
    ZeroRate,
    /// The computation exceeded the representable range.
    #[error("fee computation overflowed")]
    Overflow,
    /// The maximum fee per gas is below the batch's base fee.
    #[error("max fee per gas {offered} is below the base fee {base_fee}")]
    FeeBelowBaseFee {
        /// The sender's maximum per gas.
        offered: u128,
        /// The base fee per gas, in the fee asset.
        base_fee: u128,
    },
    /// The gas limit does not cover the gas the transaction uses.
    #[error("gas limit {limit} is below the {required} gas the transaction uses")]
    GasLimitTooLow {
        /// The sender's limit.
        limit: u64,
        /// What the transaction uses.
        required: u64,
    },
    /// The gas limit exceeds [`MAX_GAS_LIMIT`].
    #[error("gas limit {limit} exceeds the maximum")]
    GasLimitTooHigh {
        /// The sender's limit.
        limit: u64,
    },
    /// The most the transaction could pay rounds to zero units.
    #[error("the fee rounds to zero")]
    FeeRoundsToZero,
    /// A batch is stamped before the fee market's current window.
    #[error("batch timestamp precedes the fee market's window")]
    TimestampRegressed,
    /// A fee split is malformed.
    #[error("fee split shares must be distinct, non-zero and sum to 1,000,000")]
    InvalidFeeSplit,
    /// A fee market parameter is unusable.
    #[error("fee market floor and target must be non-zero")]
    InvalidFeeMarket,
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: u128 = RATE_SCALE; // one USDC unit per native unit

    #[test]
    fn the_base_fee_rises_with_demand_and_falls_to_its_floor() {
        let floor = 100;
        assert_eq!(next_base_fee(1_000, 10, 10, floor).unwrap(), 1_000);
        // At the elastic limit, +1/8.
        assert_eq!(next_base_fee(1_000, 20, 10, floor).unwrap(), 1_125);
        // Empty, -1/8.
        assert_eq!(next_base_fee(1_000, 0, 10, floor).unwrap(), 875);
        // Never below the floor.
        assert_eq!(next_base_fee(110, 0, 10, floor).unwrap(), floor);
        // Any excess moves it by at least one.
        assert_eq!(next_base_fee(1, 11, 10, 0).unwrap(), 2);
    }

    #[test]
    fn a_window_rolls_once_per_new_timestamp() {
        let mut m = FeeMarket::genesis(1_000, 10);
        m.window_ts = 5;
        m.window_gas = 20;
        assert_eq!(m.base_fee_at(5).unwrap(), 1_000, "same window, same fee");
        let next = m.at(9).unwrap();
        assert_eq!(
            (next.base_fee, next.window_ts, next.window_gas),
            (1_125, 9, 0)
        );
        assert_eq!(m.at(4), Err(GasError::TimestampRegressed));
    }

    #[test]
    fn settlement_pays_out_exactly_what_was_held() {
        // A transfer at the floor, paying in USDC with a small tip.
        let used = INTRINSIC_GAS + DEFAULT_ASSET_INTRINSIC_GAS + 10_000;
        let max_fee = 2 * DEFAULT_BASE_FEE_FLOOR;
        let c = settle(
            60_000,
            used,
            max_fee,
            1_000_000_000,
            DEFAULT_BASE_FEE_FLOOR,
            USDC,
        )
        .unwrap();
        // The effective price is base 0.025 + tip 0.001 = 0.026 units per gas;
        // the rest of the 0.05 maximum is never charged.
        assert_eq!(c.hold, 1_560); // 60,000 gas × 0.026
        assert_eq!(c.refund, 494); // 19,000 unused × 0.026
        assert_eq!(c.tip, 41); // 41,000 × 0.001
        assert_eq!(c.base, 1_025); // 41,000 × 0.025
        assert_eq!(c.refund + c.tip + c.base, c.hold);
    }

    #[test]
    fn rounding_remainders_go_to_the_base_fee() {
        // Prices chosen so every part has a fractional remainder.
        let c = settle(
            3,
            1,
            1_500_000_000_000,
            700_000_000_000,
            400_000_000_000,
            USDC,
        )
        .unwrap();
        // Effective price 0.4 + 0.7 = 1.1 per gas.
        assert_eq!(c.hold, 3); // 3 × 1.1 = 3.3
        assert_eq!(c.refund, 2); // 2 × 1.1 = 2.2
        assert_eq!(c.tip, 0); // 1 × 0.7
        assert_eq!(c.base, 1); // 1 × 0.4 = 0, plus the remainder 1
        assert_eq!(c.refund + c.tip + c.base, c.hold);
    }

    #[test]
    fn the_tip_never_lifts_the_price_above_the_maximum() {
        let c = settle(
            10,
            10,
            5 * PRICE_SCALE,
            100 * PRICE_SCALE,
            3 * PRICE_SCALE,
            USDC,
        )
        .unwrap();
        assert_eq!((c.base, c.tip), (30, 20));
    }

    #[test]
    fn the_base_fee_is_converted_at_the_rate_rounding_down() {
        assert_eq!(native_to_asset(1_000, 2 * RATE_SCALE).unwrap(), 2_000);
        assert_eq!(native_to_asset(3, RATE_SCALE / 2).unwrap(), 1);
        assert_eq!(native_to_asset(1, 0), Err(GasError::ZeroRate));
    }

    #[test]
    fn unpayable_transactions_are_refused() {
        let f = DEFAULT_BASE_FEE_FLOOR;
        assert!(matches!(
            settle(10, 11, f, 0, f, USDC),
            Err(GasError::GasLimitTooLow { .. })
        ));
        assert!(matches!(
            settle(10, 10, f - 1, 0, f, USDC),
            Err(GasError::FeeBelowBaseFee { .. })
        ));
        assert_eq!(
            settle(10, 10, f, 0, f, USDC),
            Err(GasError::FeeRoundsToZero)
        );
        assert!(matches!(
            settle(MAX_GAS_LIMIT + 1, 1, f, 0, f, USDC),
            Err(GasError::GasLimitTooHigh { .. })
        ));
        assert_eq!(
            settle(10, 10, u128::MAX, u128::MAX, f, USDC),
            Err(GasError::Overflow)
        );
    }

    #[test]
    fn fee_splits_must_add_up() {
        let a = L2Address::from_bytes([1; 32]);
        let b = L2Address::from_bytes([2; 32]);
        let ok = FeeSplit {
            beneficiaries: vec![(a, 600_000), (b, 300_000)],
            burn: 100_000,
        };
        ok.check().unwrap();
        assert_eq!(FeeSplit::decode(&ok.encode()).unwrap(), ok);
        assert_eq!(ok.shares_of(10).unwrap(), vec![(a, 6), (b, 3)]);
        for bad in [
            FeeSplit {
                beneficiaries: vec![(a, 600_000)],
                burn: 0,
            },
            FeeSplit {
                beneficiaries: vec![(a, 500_000), (a, 500_000)],
                burn: 0,
            },
            FeeSplit {
                beneficiaries: vec![(a, 0), (b, 1_000_000)],
                burn: 0,
            },
            FeeSplit {
                beneficiaries: vec![(a, 1); 9],
                burn: 999_991,
            },
        ] {
            assert_eq!(bad.check(), Err(GasError::InvalidFeeSplit), "{bad:?}");
        }
    }

    #[test]
    fn records_round_trip() {
        let asset = WhitelistedAsset {
            asset: AssetId(1),
            symbol: "USDC".to_owned(),
            rate: RATE_SCALE,
            intrinsic_gas: 10_000,
            enabled: true,
        };
        assert_eq!(WhitelistedAsset::decode(&asset.encode()).unwrap(), asset);
        let m = FeeMarket {
            base_fee: 7,
            floor: 5,
            target: 9,
            window_ts: 3,
            window_gas: 2,
        };
        assert_eq!(FeeMarket::decode(&m.encode()).unwrap(), m);
    }
}
