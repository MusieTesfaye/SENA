//! Account state.

use std::collections::BTreeMap;

use sena_primitives::{AssetId, DecodeError, Reader, Writer};
use serde::{Deserialize, Serialize};

/// An account's on-chain state.
///
/// Balances live in a [`BTreeMap`] rather than a `HashMap` because the account
/// is serialised into the state trie and its digest must not depend on
/// iteration order (REQ-FRAUD-031). The workspace denies `HashMap` outright for
/// this reason.
///
/// A zero balance is never stored: [`Self::credit`] and [`Self::debit`] prune
/// entries that reach zero, so an account that has held and spent an asset is
/// byte-identical to one that never held it. Without that, the state root would
/// encode spending history and two honest nodes arriving at the same balances by
/// different routes would disagree.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    /// Number of transactions this account has sent. Consumed in order, which
    /// is what prevents replay (NFR-SEC-005).
    pub nonce: u64,
    /// Balances by asset. Assets with a zero balance are absent.
    pub balances: BTreeMap<AssetId, u128>,
}

impl Account {
    /// Creates an account with no balances and a zero nonce.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the balance held in `asset`, which is zero if untracked.
    #[must_use]
    pub fn balance(&self, asset: AssetId) -> u128 {
        self.balances.get(&asset).copied().unwrap_or(0)
    }

    /// Adds `amount` to the balance in `asset`.
    ///
    /// # Errors
    ///
    /// Returns [`BalanceError::Overflow`] if the balance would exceed `u128::MAX`.
    /// This cannot arise from honest supply, but the check is not omitted on that
    /// basis: a silent wrap would mint value, and the release profile enables
    /// overflow checks precisely so arithmetic faults cannot pass unnoticed.
    pub fn credit(&mut self, asset: AssetId, amount: u128) -> Result<(), BalanceError> {
        if amount == 0 {
            return Ok(());
        }
        let current = self.balance(asset);
        let updated = current.checked_add(amount).ok_or(BalanceError::Overflow)?;
        self.balances.insert(asset, updated);
        Ok(())
    }

    /// Subtracts `amount` from the balance in `asset`.
    ///
    /// # Errors
    ///
    /// Returns [`BalanceError::Insufficient`] if the account does not hold enough.
    pub fn debit(&mut self, asset: AssetId, amount: u128) -> Result<(), BalanceError> {
        if amount == 0 {
            return Ok(());
        }
        let current = self.balance(asset);
        let updated = current
            .checked_sub(amount)
            .ok_or(BalanceError::Insufficient {
                held: current,
                required: amount,
            })?;
        if updated == 0 {
            self.balances.remove(&asset);
        } else {
            self.balances.insert(asset, updated);
        }
        Ok(())
    }

    /// Encodes the account for storage in the state trie.
    ///
    /// Uses the canonical binary codec rather than JSON, because the `sena::osp`
    /// Move contract has to decode this exact slot during one-step
    /// verification, apply the step, and re-encode it byte for byte. Balances
    /// are written in `AssetId` order, which `BTreeMap` iteration already
    /// guarantees.
    ///
    /// # Panics
    ///
    /// Panics if the account holds more than `u32::MAX` distinct assets, which
    /// no account can reach.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(self.nonce);
        w.u32(u32::try_from(self.balances.len()).expect("an account cannot hold 2^32 assets"));
        for (asset, amount) in &self.balances {
            w.u32(asset.get());
            w.u128(*amount);
        }
        w.finish()
    }

    /// Decodes an account from its stored representation.
    ///
    /// # Errors
    ///
    /// Returns [`BalanceError::Malformed`] if the bytes are not a canonical
    /// encoding of an account. Non-canonical input is rejected as well as
    /// invalid input: entries out of order, a repeated asset, or a stored zero
    /// balance would each give one account two encodings, and the trie commits
    /// to bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, BalanceError> {
        Self::decode_inner(bytes).map_err(|_| BalanceError::Malformed)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let nonce = r.u64()?;
        let count = r.u32()?;

        let mut balances = BTreeMap::new();
        let mut previous: Option<u32> = None;
        for _ in 0..count {
            let asset = r.u32()?;
            let amount = r.u128()?;
            // Strictly increasing asset ids, and no zero balances: both are
            // required for the encoding to be unique per account state.
            if previous.is_some_and(|prev| asset <= prev) || amount == 0 {
                return Err(DecodeError::UnknownVariant(0));
            }
            previous = Some(asset);
            balances.insert(AssetId(asset), amount);
        }
        r.finish()?;
        Ok(Self { nonce, balances })
    }
}

/// A fault in account arithmetic or encoding.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BalanceError {
    /// The account does not hold enough of the asset.
    #[error("insufficient balance: holds {held}, needs {required}")]
    Insufficient {
        /// What the account holds.
        held: u128,
        /// What the operation required.
        required: u128,
    },
    /// The credit would exceed the representable range.
    #[error("balance overflow")]
    Overflow,
    /// The stored bytes are not a valid account.
    #[error("stored account is malformed")]
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: AssetId = AssetId(1);

    #[test]
    fn credit_then_debit_returns_to_empty() {
        let mut a = Account::new();
        a.credit(USDC, 100).unwrap();
        a.debit(USDC, 100).unwrap();
        assert_eq!(a, Account::new(), "spent-to-zero must equal never-held");
    }

    #[test]
    fn zero_balances_are_not_stored() {
        let mut a = Account::new();
        a.credit(USDC, 5).unwrap();
        a.debit(USDC, 5).unwrap();
        assert!(a.balances.is_empty());
    }

    #[test]
    fn debiting_more_than_held_fails_and_changes_nothing() {
        let mut a = Account::new();
        a.credit(USDC, 10).unwrap();
        let before = a.clone();
        let err = a.debit(USDC, 11).unwrap_err();
        assert_eq!(
            err,
            BalanceError::Insufficient {
                held: 10,
                required: 11
            }
        );
        assert_eq!(a, before, "a failed debit must not partially apply");
    }

    #[test]
    fn credit_overflow_is_rejected_rather_than_wrapping() {
        let mut a = Account::new();
        a.credit(USDC, u128::MAX).unwrap();
        assert_eq!(a.credit(USDC, 1).unwrap_err(), BalanceError::Overflow);
        assert_eq!(
            a.balance(USDC),
            u128::MAX,
            "the failed credit must not mint"
        );
    }

    #[test]
    fn zero_amount_operations_are_no_ops() {
        let mut a = Account::new();
        a.credit(USDC, 0).unwrap();
        a.debit(USDC, 0).unwrap();
        assert!(a.balances.is_empty());
    }

    #[test]
    fn encoding_round_trips() {
        let mut a = Account::new();
        a.nonce = 7;
        a.credit(AssetId::NATIVE, 1).unwrap();
        a.credit(USDC, 2).unwrap();
        assert_eq!(Account::decode(&a.encode()).unwrap(), a);
    }

    #[test]
    fn determinism_encoding_is_independent_of_insertion_order() {
        let mut a = Account::new();
        a.credit(AssetId(9), 9).unwrap();
        a.credit(AssetId(1), 1).unwrap();

        let mut b = Account::new();
        b.credit(AssetId(1), 1).unwrap();
        b.credit(AssetId(9), 9).unwrap();

        println!(
            "root={}",
            hex::encode(sena_primitives::Hash256::digest(&a.encode()).0)
        );
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        assert_eq!(
            Account::decode(b"not an account").unwrap_err(),
            BalanceError::Malformed
        );
    }

    #[test]
    fn the_encoding_is_compact_and_binary() {
        // The Move one-step verifier has to decode this, so the layout is part
        // of the contract: nonce, count, then (asset, amount) pairs.
        let mut a = Account::new();
        a.nonce = 1;
        a.credit(USDC, 2).unwrap();
        let bytes = a.encode();
        assert_eq!(bytes.len(), 8 + 4 + (4 + 16));
        assert_eq!(&bytes[..8], &1u64.to_be_bytes());
        assert_eq!(&bytes[8..12], &1u32.to_be_bytes());
    }

    #[test]
    fn out_of_order_balances_are_rejected() {
        // Accepting them would give one account state two valid encodings, and
        // the trie commits to bytes rather than to meaning.
        let mut w = sena_primitives::Writer::new();
        w.u64(0).u32(2).u32(9).u128(1).u32(1).u128(1);
        assert_eq!(
            Account::decode(&w.finish()).unwrap_err(),
            BalanceError::Malformed
        );
    }

    #[test]
    fn a_repeated_asset_is_rejected() {
        let mut w = sena_primitives::Writer::new();
        w.u64(0).u32(2).u32(1).u128(5).u32(1).u128(7);
        assert_eq!(
            Account::decode(&w.finish()).unwrap_err(),
            BalanceError::Malformed
        );
    }

    #[test]
    fn a_stored_zero_balance_is_rejected() {
        // encode() prunes zeros, so a zero in the input would be a second
        // encoding of an account that already has one.
        let mut w = sena_primitives::Writer::new();
        w.u64(0).u32(1).u32(1).u128(0);
        assert_eq!(
            Account::decode(&w.finish()).unwrap_err(),
            BalanceError::Malformed
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = Account::new().encode();
        bytes.push(0);
        assert_eq!(
            Account::decode(&bytes).unwrap_err(),
            BalanceError::Malformed
        );
    }

    #[test]
    fn a_truncated_account_is_rejected_rather_than_panicking() {
        let mut a = Account::new();
        a.nonce = 3;
        a.credit(USDC, 9).unwrap();
        let bytes = a.encode();
        for cut in 0..bytes.len() {
            assert!(
                Account::decode(&bytes[..cut]).is_err(),
                "a {cut}-byte prefix must not decode"
            );
        }
    }
}
