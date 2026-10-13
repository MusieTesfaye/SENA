//! Ultralight mobile client verification for the SENA Network (REQ-CORE-004, REQ-FRAUD-031).
//!
//! # The Ultralight Mobile Sync Architecture
//!
//! Traditional mobile light clients must download block headers, verify proof-of-stake
//! consensus, or compute recursive SNARKs across validator epochs (like Celo's Plumo).
//!
//! On the SENA Network, a Layer 2 anchored to Aptos L1, mobile devices **never need to
//! sync block histories or verify consensus quorums**.
//!
//! A mobile client only requires:
//! 1. A trusted 32-byte state root (fetched from Aptos L1 for finalized state, or the
//!    sequencer's signed header for soft confirmations).
//! 2. A cryptographic Sparse Merkle Proof fetched via `sena_getAccountProof`.
//!
//! The client locally recomputes the trie path in **< 0.1 milliseconds** using
//! **< 1 KB of bandwidth**, mathematically verifying account balance and nonce
//! authenticity without trusting the RPC node.

use std::collections::BTreeMap;

use sena_primitives::{AssetId, Hash256, HashedIdentifier, L2Address};
use sena_state::{MerkleProof, ProofError, Terminal};
use sena_stf::{keys, Account, BalanceError, SocialBinding};
use serde::{Deserialize, Serialize};

/// The trust level of a verified state root.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Anchored to Aptos L1 settlement. Challenge window has elapsed; irreversible.
    Finalized,
    /// Authenticated by sequencer soft confirmation (2s block). Fast for UI, but pending L1 finality.
    SoftConfirmed,
}

/// A cryptographically verified account state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifiedAccount {
    /// The account's address.
    pub address: L2Address,
    /// The block height the proof was anchored to.
    pub height: u64,
    /// The account's nonce.
    pub nonce: u64,
    /// Balances held in each asset.
    pub balances: BTreeMap<AssetId, u128>,
    /// Trust level of the verification.
    pub trust_level: TrustLevel,
    /// The state root the proof was verified against.
    pub state_root: Hash256,
}

impl VerifiedAccount {
    /// Returns the balance held in `asset`, which is zero if untracked.
    #[must_use]
    pub fn balance(&self, asset: AssetId) -> u128 {
        self.balances.get(&asset).copied().unwrap_or(0)
    }

    /// Whether this account state is finalized on Aptos L1.
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        matches!(self.trust_level, TrustLevel::Finalized)
    }
}

/// An account proof payload received from the `sena_getAccountProof` RPC endpoint.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AccountProofPayload {
    /// The account's address.
    pub address: L2Address,
    /// Height the proof is anchored to.
    pub height: u64,
    /// State root the proof claims to reconstruct to.
    pub state_root: Hash256,
    /// The account's nonce.
    pub nonce: u64,
    /// Balances in asset order.
    pub balances: Vec<(u32, u128)>,
    /// Sibling hashes along the Merkle path.
    pub siblings: Vec<Hash256>,
    /// Terminal node the path ends in.
    pub terminal: Terminal,
    /// Whether this state root has finalized on L1 according to the node.
    pub finalized: bool,
}

/// Why client-side proof verification failed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum LightClientError {
    /// The proof's state root is not recognized as trusted.
    #[error("untrusted state root: {0}")]
    UntrustedRoot(Hash256),
    /// The Merkle proof could not be verified against the state root.
    #[error("cryptographic proof failure: {0}")]
    Proof(#[from] ProofError),
    /// Account encoding is malformed or invalid.
    #[error("malformed account: {0}")]
    MalformedAccount(#[from] BalanceError),
    /// Conflicting balance entries in the payload.
    #[error("duplicate or invalid asset: {0}")]
    DuplicateAsset(u32),
    /// Zero balance entry found in payload (violates canonical storage).
    #[error("zero balance stored for asset: {0}")]
    ZeroBalance(u32),
}

/// An ultralight mobile client tracking trusted state roots.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LightClient {
    /// Chain identifier.
    pub chain_id: String,
    /// Trusted finalized state root (sourced directly from Aptos L1).
    pub trusted_finalized_root: Hash256,
    /// Optional soft-confirmed state root (signed by the sequencer).
    pub trusted_soft_root: Option<Hash256>,
}

impl LightClient {
    /// Creates a new light client with a trusted finalized state root.
    #[must_use]
    pub fn new(chain_id: impl Into<String>, initial_trusted_root: Hash256) -> Self {
        Self {
            chain_id: chain_id.into(),
            trusted_finalized_root: initial_trusted_root,
            trusted_soft_root: None,
        }
    }

    /// Updates the trusted finalized root (e.g. from an Aptos L1 event or query).
    pub fn set_finalized_root(&mut self, root: Hash256) {
        self.trusted_finalized_root = root;
    }

    /// Updates the trusted soft confirmation root (e.g. from a sequencer block header).
    pub fn set_soft_root(&mut self, root: Option<Hash256>) {
        self.trusted_soft_root = root;
    }

    /// Checks if a root matches one of the client's trusted roots.
    #[must_use]
    pub fn trust_level_of(&self, root: &Hash256) -> Option<TrustLevel> {
        if *root == self.trusted_finalized_root {
            Some(TrustLevel::Finalized)
        } else if self.trusted_soft_root.as_ref() == Some(root) {
            Some(TrustLevel::SoftConfirmed)
        } else {
            None
        }
    }

    /// Verifies an [`AccountProofPayload`] against the client's trusted roots.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError`] if the state root is untrusted, the Merkle path is
    /// invalid, or the claimed balances do not match the committed leaf.
    pub fn verify_account_proof(
        &self,
        payload: &AccountProofPayload,
    ) -> Result<VerifiedAccount, LightClientError> {
        let trust_level = self
            .trust_level_of(&payload.state_root)
            .ok_or(LightClientError::UntrustedRoot(payload.state_root))?;

        let mut balances = BTreeMap::new();
        for &(asset_id, amount) in &payload.balances {
            if amount == 0 {
                return Err(LightClientError::ZeroBalance(asset_id));
            }
            if balances.insert(AssetId(asset_id), amount).is_some() {
                return Err(LightClientError::DuplicateAsset(asset_id));
            }
        }

        let slot = keys::account(&payload.address);
        let proof = MerkleProof {
            siblings: payload.siblings.clone(),
            terminal: payload.terminal.clone(),
        };

        if payload.nonce == 0 && balances.is_empty() {
            // An empty account must verify non-inclusion.
            proof.verify_non_inclusion(&payload.state_root, &slot)?;
        } else {
            // A non-empty account must encode to byte-identical representation and verify inclusion.
            let account = Account {
                nonce: payload.nonce,
                balances: balances.clone(),
            };
            let encoded = account.encode();
            proof.verify_inclusion(&payload.state_root, &slot, &encoded)?;
        }

        Ok(VerifiedAccount {
            address: payload.address,
            height: payload.height,
            nonce: payload.nonce,
            balances,
            trust_level,
            state_root: payload.state_root,
        })
    }

    /// Verifies a human-readable social identifier binding against a trusted root.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError`] if the root is untrusted or the proof does not match.
    pub fn verify_social_binding(
        &self,
        identifier: &HashedIdentifier,
        expected_address: Option<&L2Address>,
        proof: &MerkleProof,
        state_root: &Hash256,
    ) -> Result<TrustLevel, LightClientError> {
        let trust_level = self
            .trust_level_of(state_root)
            .ok_or(LightClientError::UntrustedRoot(*state_root))?;

        let slot = keys::social_by_identifier(identifier);

        match expected_address {
            Some(address) => {
                let binding = SocialBinding::Bound { address: *address };
                let encoded = binding.encode();
                proof.verify_inclusion(state_root, &slot, &encoded)?;
            }
            None => {
                // If expected to be unassigned, it either does not exist (non-inclusion)
                // or holds a Vacant tombstone.
                if proof.verify_non_inclusion(state_root, &slot).is_err() {
                    let vacant = SocialBinding::Vacant;
                    proof.verify_inclusion(state_root, &slot, &vacant.encode())?;
                }
            }
        }

        Ok(trust_level)
    }
}

/// Standalone cryptographic verification of an account against any explicit root.
///
/// # Errors
///
/// Returns [`LightClientError`] if the cryptographic proof is invalid.
pub fn verify_account_standalone(
    state_root: &Hash256,
    address: &L2Address,
    nonce: u64,
    balances: &[(u32, u128)],
    siblings: &[Hash256],
    terminal: &Terminal,
) -> Result<BTreeMap<AssetId, u128>, LightClientError> {
    let mut map = BTreeMap::new();
    for &(asset_id, amount) in balances {
        if amount == 0 {
            return Err(LightClientError::ZeroBalance(asset_id));
        }
        if map.insert(AssetId(asset_id), amount).is_some() {
            return Err(LightClientError::DuplicateAsset(asset_id));
        }
    }

    let slot = keys::account(address);
    let proof = MerkleProof {
        siblings: siblings.to_vec(),
        terminal: terminal.clone(),
    };

    if nonce == 0 && map.is_empty() {
        proof.verify_non_inclusion(state_root, &slot)?;
    } else {
        let account = Account {
            nonce,
            balances: map.clone(),
        };
        proof.verify_inclusion(state_root, &slot, &account.encode())?;
    }

    Ok(map)
}
