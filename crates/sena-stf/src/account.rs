//! Account state.

use std::collections::BTreeMap;

use sena_primitives::AssetId;
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
    /// JSON is used for legibility while the protocol is being built out. It is
    /// deterministic here only because every field is ordered -- `serde_json`
    /// preserves struct field order and `BTreeMap` iterates in key order -- but
    /// it is not a good long-term choice for a consensus encoding, since the
    /// Move implementation on Aptos L1 would have to reproduce it exactly.
    /// Replacing this with a canonical binary encoding is tracked as a follow-up.
    ///
    /// # Panics
    ///
    /// Panics only if serialising a `BTreeMap` of integers fails, which cannot
    /// occur.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("account serialisation cannot fail")
    }

    /// Decodes an account from its stored representation.
    ///
    /// # Errors
    ///
    /// Returns [`BalanceError::Malformed`] if the bytes are not a valid account.
    pub fn decode(bytes: &[u8]) -> Result<Self, BalanceError> {
        serde_json::from_slice(bytes).map_err(|_| BalanceError::Malformed)
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
}
