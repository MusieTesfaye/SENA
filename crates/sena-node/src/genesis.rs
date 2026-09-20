//! Genesis configuration.
//!
//! A chain's genesis fixes everything a node must agree on before it can
//! process a single transaction: the challenge window, the gas assets and their
//! rates, the initial allocations, the governance council, and the network salt
//! that social identifiers are hashed under.
//!
//! Two nodes given the same genesis file must reach byte-identical state roots.
//! The config is therefore applied through the ordinary instruction set, in a
//! fixed order, rather than by writing the trie directly — the same code path a
//! verifier would use, so genesis cannot diverge from execution.

use sena_primitives::serde_hex::u128_string;
use sena_primitives::{AssetId, Hash256, L2Address, NetworkSalt};
use sena_state::MerkleTrie;
use sena_stf::{apply, Council, Instruction, WhitelistedAsset};
use serde::{Deserialize, Serialize};

/// An initial balance.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Allocation {
    /// Who receives it.
    pub address: L2Address,
    /// Which asset.
    pub asset: u32,
    /// How much.
    #[serde(with = "u128_string")]
    pub amount: u128,
}

/// A gas asset enabled at genesis.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GasAsset {
    /// Asset identifier.
    pub asset: u32,
    /// Human-readable symbol.
    pub symbol: String,
    /// Units per `RATE_SCALE` native units.
    #[serde(with = "u128_string")]
    pub rate: u128,
    /// Whether it may be used for fees.
    pub enabled: bool,
}

/// The governance council at genesis.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CouncilConfig {
    /// Members' Ed25519 verifying keys, hex-encoded.
    pub members: Vec<String>,
    /// How many must sign.
    pub threshold: u32,
}

/// Everything a chain is configured with at genesis.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Identifies the network. Nodes with different chain ids are different
    /// chains and must not be confused for one another.
    pub chain_id: String,
    /// The challenge window, in seconds. Clamped to the protocol floor.
    pub challenge_window_secs: u64,
    /// The minimum bond an assertion must carry.
    #[serde(with = "u128_string")]
    pub minimum_bond: u128,
    /// The salt social identifiers are hashed under.
    pub network_salt: String,
    /// Gas assets enabled at genesis.
    pub gas_assets: Vec<GasAsset>,
    /// Initial balances.
    pub allocations: Vec<Allocation>,
    /// The governance council, if one is configured.
    pub council: Option<CouncilConfig>,
}

/// Why a genesis configuration could not be applied.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum GenesisError {
    /// A council member key was not 32 bytes of hex.
    #[error("council member {index} is not 32 bytes of hex")]
    BadCouncilKey {
        /// Which member.
        index: usize,
    },
    /// A gas asset was configured with a zero rate.
    #[error("gas asset {symbol} has a zero rate, which would make execution free")]
    ZeroRate {
        /// The offending asset.
        symbol: String,
    },
    /// The council threshold is unreachable.
    #[error("council threshold {threshold} exceeds its {members} members")]
    ImpossibleThreshold {
        /// The configured threshold.
        threshold: u32,
        /// How many members there are.
        members: usize,
    },
    /// Applying an instruction failed.
    #[error("applying genesis failed: {0}")]
    Apply(String),
}

impl GenesisConfig {
    /// A small development configuration.
    ///
    /// Used by `sena-node genesis --dev` so that a working chain is one command
    /// away. The challenge window is still the protocol floor, not something
    /// shorter: a devnet that finalizes in seconds would let developers build
    /// against timings that mainnet will never offer.
    #[must_use]
    pub fn dev(allocations: Vec<Allocation>) -> Self {
        Self {
            chain_id: "sena-devnet-1".to_owned(),
            challenge_window_secs: sena_fraudproof::CHALLENGE_WINDOW_FLOOR,
            minimum_bond: 1_000_000,
            network_salt: "sena-devnet-1-salt".to_owned(),
            gas_assets: vec![GasAsset {
                asset: 1,
                symbol: "USDC".to_owned(),
                rate: sena_stf::RATE_SCALE,
                enabled: true,
            }],
            allocations,
            council: None,
        }
    }

    /// Returns the network salt identifiers are hashed under.
    #[must_use]
    pub fn salt(&self) -> NetworkSalt {
        NetworkSalt::new(self.network_salt.as_bytes().to_vec())
    }

    /// Validates the configuration without applying it.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisError`] if a council key is malformed, a threshold is
    /// unreachable, or a gas asset has a zero rate.
    pub fn validate(&self) -> Result<(), GenesisError> {
        for asset in &self.gas_assets {
            if asset.rate == 0 {
                return Err(GenesisError::ZeroRate {
                    symbol: asset.symbol.clone(),
                });
            }
        }
        if let Some(council) = &self.council {
            if council.threshold as usize > council.members.len() || council.threshold == 0 {
                return Err(GenesisError::ImpossibleThreshold {
                    threshold: council.threshold,
                    members: council.members.len(),
                });
            }
            for (index, member) in council.members.iter().enumerate() {
                decode_key(member).ok_or(GenesisError::BadCouncilKey { index })?;
            }
        }
        Ok(())
    }

    /// Builds the genesis state.
    ///
    /// Order is fixed and documented because the resulting root is consensus:
    /// gas assets, then the council, then allocations in the order written.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisError`] if the configuration is invalid or an
    /// instruction fails to apply.
    pub fn build_state(&self) -> Result<MerkleTrie, GenesisError> {
        self.validate()?;
        let mut trie = MerkleTrie::new();

        for asset in &self.gas_assets {
            let record = WhitelistedAsset {
                asset: AssetId(asset.asset),
                symbol: asset.symbol.clone(),
                rate: asset.rate,
                enabled: asset.enabled,
            };
            apply(&mut trie, &Instruction::SetGasAsset { record })
                .map_err(|e| GenesisError::Apply(e.to_string()))?;
        }

        if let Some(config) = &self.council {
            let mut members = Vec::with_capacity(config.members.len());
            for (index, member) in config.members.iter().enumerate() {
                members.push(decode_key(member).ok_or(GenesisError::BadCouncilKey { index })?);
            }
            let council = Council {
                members,
                threshold: config.threshold,
            };
            trie.insert(sena_stf::keys::council(), council.encode());
        }

        for allocation in &self.allocations {
            apply(
                &mut trie,
                &Instruction::Credit {
                    account: allocation.address,
                    asset: AssetId(allocation.asset),
                    amount: allocation.amount,
                },
            )
            .map_err(|e| GenesisError::Apply(e.to_string()))?;
        }

        Ok(trie)
    }

    /// Returns the state root this configuration produces.
    ///
    /// Two operators comparing this value can tell whether they are on the same
    /// chain before exchanging a single transaction.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisError`] if the configuration cannot be applied.
    pub fn state_root(&self) -> Result<Hash256, GenesisError> {
        Ok(self.build_state()?.root())
    }
}

fn decode_key(hex_key: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_key.strip_prefix("0x").unwrap_or(hex_key)).ok()?;
    raw.try_into().ok()
}
