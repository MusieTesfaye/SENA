//! Wallet logic for the SENA Network, without I/O.
//!
//! Everything a wallet computes — a keyless sign-in, a transaction, its fee
//! fields and its signature — is here, in the same code the node verifies
//! with, so a wallet built on it cannot drift from the chain. Sending is left
//! to the embedder: `sena-node` natively, `sena-wasm` in a browser.

pub mod keyless;

use ed25519_dalek::{Signer as _, SigningKey};
use sena_primitives::{AssetId, L2Address};
use sena_stf::{Authenticator, Payload, Transaction};

/// What a transfer pays for gas, as a node's `sena_gasPrice` quotes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FeeQuote {
    /// The fee asset.
    pub asset: AssetId,
    /// Its whitelisted rate, which the transaction declares.
    pub rate: u128,
    /// Its intrinsic gas, which the transaction declares.
    pub intrinsic_gas: u64,
    /// The most to pay per gas, base fee and tip together.
    pub max_fee_per_gas: u128,
    /// The most tip per gas.
    pub max_priority_fee_per_gas: u128,
}

/// An unsigned transfer of `amount` of `asset` from `sender` to `to`, paying
/// its fee as `fee` says, with the gas limit set to exactly what it uses.
///
/// The authenticator is a placeholder; sign with [`sign_ed25519`] or
/// [`keyless::sign`], which also sets the gas a keyless signature adds.
///
/// # Errors
///
/// Returns the compile error if the transaction cannot be metered.
pub fn transfer(
    sender: L2Address,
    nonce: u64,
    to: L2Address,
    asset: AssetId,
    amount: u128,
    fee: &FeeQuote,
) -> Result<Transaction, sena_stf::CompileError> {
    let mut tx = Transaction {
        sender,
        nonce,
        fee_asset: fee.asset,
        fee_rate: fee.rate,
        fee_intrinsic_gas: fee.intrinsic_gas,
        gas_limit: 0,
        max_fee_per_gas: fee.max_fee_per_gas,
        max_priority_fee_per_gas: fee.max_priority_fee_per_gas,
        payload: Payload::Transfer { to, asset, amount },
        authenticator: Authenticator::Ed25519 {
            public_key: [0; 32],
            signature: [0; 64],
        },
    };
    tx.gas_limit = sena_stf::gas_required(&tx)?;
    Ok(tx)
}

/// The address an Ed25519 key controls: its public key.
#[must_use]
pub fn ed25519_address(secret: &[u8; 32]) -> L2Address {
    L2Address::from_bytes(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

/// Signs `tx` with an Ed25519 key, as the account that key controls.
#[must_use]
pub fn sign_ed25519(mut tx: Transaction, secret: &[u8; 32]) -> Transaction {
    let key = SigningKey::from_bytes(secret);
    let public_key = key.verifying_key().to_bytes();
    tx.sender = L2Address::from_bytes(public_key);
    tx.authenticator = Authenticator::Ed25519 {
        public_key,
        signature: [0; 64],
    };
    let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key,
        signature,
    };
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use sena_stf::keyless::KeylessContext;

    fn usdc() -> FeeQuote {
        FeeQuote {
            asset: AssetId(1),
            rate: sena_stf::RATE_SCALE,
            intrinsic_gas: sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS,
            max_fee_per_gas: 50_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        }
    }

    #[test]
    fn a_signed_transfer_authenticates_and_is_metered_exactly() {
        let secret = [5; 32];
        let to = L2Address::from_bytes([9; 32]);
        let tx = transfer(ed25519_address(&secret), 0, to, AssetId(1), 10, &usdc()).unwrap();
        assert_eq!(tx.gas_limit, 41_000);
        let tx = sign_ed25519(tx, &secret);
        assert_eq!(tx.sender, ed25519_address(&secret));
        tx.authenticate(&KeylessContext {
            config: None,
            now: 0,
        })
        .unwrap();
    }
}
