//! Published batch data and its local store (REQ-FRAUD-007..010).
//!
//! A [`DaBlob`] is what a verifier needs to re-execute a batch. Today blobs are
//! served by the node that produced them and kept on its disk; publishing them
//! somewhere the sequencer cannot withhold them from is tracked in `STATUS.md`.

use sena_primitives::Hash256;
use sena_state::MerkleTrie;
use sena_stf::{execute_batch, BatchContext, KeylessConfig, Transaction};

use crate::sequencer::{batch_commitment, Block};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// The published data of one batch: everything a verifier needs to re-execute
/// it and check the assertion that covers it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DaBlob {
    /// Block height.
    pub height: u64,
    /// The batch timestamp, part of the batch data (keyless expiry is judged
    /// against it).
    pub timestamp: u64,
    /// Root before the batch.
    pub pre_state_root: Hash256,
    /// Asserted root after the batch.
    pub post_state_root: Hash256,
    /// The commitment the L1 assertion carries; see [`Block::batch_commitment`].
    pub batch_commitment: Hash256,
    /// The transactions, in execution order.
    pub transactions: Vec<Transaction>,
}

impl DaBlob {
    /// The blob for a sealed block.
    #[must_use]
    pub fn from_block(block: &Block) -> Self {
        Self {
            height: block.height,
            timestamp: block.timestamp,
            pre_state_root: block.pre_state_root,
            post_state_root: block.post_state_root,
            batch_commitment: block.batch_commitment(),
            transactions: block.transactions.clone(),
        }
    }

    /// The commitment these transactions and timestamp actually produce.
    #[must_use]
    pub fn computed_commitment(&self) -> Hash256 {
        batch_commitment(self.timestamp, &self.transactions)
    }

    /// Whether the stated commitment matches the contents.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.computed_commitment() == self.batch_commitment
    }

    /// Re-executes the blob from `starting_state` and checks it reaches the
    /// asserted root.
    ///
    /// # Errors
    ///
    /// Returns an error if the commitment does not match, the starting root is
    /// not the blob's pre-state, the batch does not execute, or it executes to
    /// a different root.
    pub fn verify_execution(
        &self,
        starting_state: &mut MerkleTrie,
        keyless: Option<&KeylessConfig>,
    ) -> Result<Hash256, String> {
        if !self.verify_integrity() {
            return Err("DA blob commitment does not match its contents".to_string());
        }
        if starting_state.root() != self.pre_state_root {
            return Err(format!(
                "starting state root {} does not match blob pre_state_root {}",
                starting_state.root(),
                self.pre_state_root
            ));
        }

        let ctx = BatchContext {
            timestamp: self.timestamp,
            keyless,
        };
        execute_batch(starting_state, &ctx, &self.transactions)
            .map_err(|e| format!("batch execution failed: {e}"))?;

        let final_root = starting_state.root();
        if final_root != self.post_state_root {
            return Err(format!(
                "re-executed root {final_root} does not match asserted post_state_root {}",
                self.post_state_root
            ));
        }

        Ok(final_root)
    }
}

/// An on-disk and in-memory Data Availability pipeline store.
#[derive(Clone, Debug)]
pub struct DaStore {
    dir: PathBuf,
}

impl DaStore {
    /// Opens or creates the DA store at the specified directory.
    ///
    /// # Errors
    /// Returns an IO error if directory creation fails.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Returns the directory path of the DA store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Saves a DA blob indexed by commitment and block height.
    ///
    /// # Errors
    /// Returns an IO error if writing fails.
    pub fn put(&self, blob: &DaBlob) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(blob)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let commit_file = self.dir.join(format!("{}.json", blob.batch_commitment));
        let height_file = self.dir.join(format!("height_{}.json", blob.height));

        fs::write(&commit_file, &json)?;
        let _ = fs::write(&height_file, &json);
        Ok(())
    }

    /// Retrieves a DA blob by its cryptographic commitment.
    #[must_use]
    pub fn get_by_commitment(&self, commitment: &Hash256) -> Option<DaBlob> {
        let file = self.dir.join(format!("{commitment}.json"));
        let bytes = fs::read(file).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Retrieves a DA blob by its block height.
    #[must_use]
    pub fn get_by_height(&self, height: u64) -> Option<DaBlob> {
        let file = self.dir.join(format!("height_{height}.json"));
        let bytes = fs::read(file).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{Allocation, GasAsset, GenesisConfig};
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sena_primitives::{AssetId, L2Address};
    use sena_stf::gas::fee_for;
    use sena_stf::{Authenticator, Payload, RATE_SCALE};

    const USDC: AssetId = AssetId(1);

    fn signer(seed: u64) -> SigningKey {
        SigningKey::generate(&mut StdRng::seed_from_u64(seed))
    }

    fn address_of(key: &SigningKey) -> L2Address {
        L2Address::from_bytes(key.verifying_key().to_bytes())
    }

    fn signed_tx(key: &SigningKey, nonce: u64, to: L2Address, amount: u128) -> Transaction {
        let rate = RATE_SCALE;
        let mut tx = Transaction {
            sender: address_of(key),
            nonce,
            fee_asset: USDC,
            max_fee: fee_for(rate).unwrap(),
            fee_rate: rate,
            payload: Payload::Transfer {
                to,
                asset: USDC,
                amount,
            },
            authenticator: Authenticator::Ed25519 {
                public_key: key.verifying_key().to_bytes(),
                signature: [0; 64],
            },
        };
        let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
        tx.authenticator = Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature,
        };
        tx
    }

    #[test]
    fn test_da_blob_roundtrip_and_verification() {
        let alice_key = signer(42);
        let bob_key = signer(43);
        let alice = address_of(&alice_key);
        let bob = address_of(&bob_key);

        let genesis = GenesisConfig {
            chain_id: "sena-test".to_string(),
            challenge_window_secs: 86400,
            minimum_bond: 1_000_000,
            network_salt: "test-salt".to_string(),
            gas_assets: vec![GasAsset {
                asset: 1,
                symbol: "USDC".to_string(),
                rate: RATE_SCALE,
                enabled: true,
            }],
            allocations: vec![Allocation {
                address: alice,
                asset: 1,
                amount: 1_000_000_000,
            }],
            council: None,
            keyless: None,
        };

        let starting_state = genesis.build_state().unwrap();
        let pre_root = starting_state.root();

        let tx = signed_tx(&alice_key, 0, bob, 500);

        let ctx = BatchContext::without_keyless(1_700_000_000);
        let mut exec_state = starting_state.clone();
        execute_batch(&mut exec_state, &ctx, std::slice::from_ref(&tx)).unwrap();
        let post_root = exec_state.root();

        let transactions = vec![tx];
        let da_blob = DaBlob {
            height: 1,
            timestamp: ctx.timestamp,
            pre_state_root: pre_root,
            post_state_root: post_root,
            batch_commitment: batch_commitment(ctx.timestamp, &transactions),
            transactions,
        };
        assert!(da_blob.verify_integrity());

        // Independent replay from starting state
        let mut verifier_state = starting_state.clone();
        let executed_root = da_blob.verify_execution(&mut verifier_state, None).unwrap();
        assert_eq!(executed_root, post_root);

        // The timestamp is committed to: changing it breaks integrity.
        let mut retimed = da_blob.clone();
        retimed.timestamp += 1;
        assert!(!retimed.verify_integrity());

        // Tampering test: modify commitment
        let mut tampered = da_blob.clone();
        tampered.batch_commitment = Hash256::ZERO;
        assert!(!tampered.verify_integrity());
        assert!(tampered
            .verify_execution(&mut verifier_state, None)
            .is_err());
    }
}
