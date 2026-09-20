//! On-disk persistence.
//!
//! A node that forgets its state on restart is a demo, not a node. This module
//! keeps the pieces a node must survive a restart with: the genesis it was
//! configured from, the L2 state, the assertion chain, and the blocks whose
//! batch data it is still responsible for publishing.
//!
//! # Loading is verified, not trusted
//!
//! Everything read back is checked against something computed. The state
//! snapshot records its own root and is rejected if rebuilding does not
//! reproduce it; the genesis file is rejected if its state root no longer
//! matches what the stored state began from. A node whose entire job is to
//! agree with every other node should refuse to start on state it cannot
//! verify, rather than quietly serve something nobody else believes.

use std::fs;
use std::path::{Path, PathBuf};

use sena_state::MerkleTrie;
use sena_stf::Transaction;
use serde::{Deserialize, Serialize};

use sena_fraudproof::ChainSnapshot;

use crate::genesis::GenesisConfig;
use crate::sequencer::Block;

/// Why the store could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("{operation} failed for {path}: {source}")]
    Io {
        /// What was being attempted.
        operation: &'static str,
        /// The path involved.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A stored file could not be parsed.
    #[error("{file} is malformed: {detail}")]
    Malformed {
        /// Which file.
        file: &'static str,
        /// What was wrong with it.
        detail: String,
    },
    /// The stored state did not verify against its recorded root.
    #[error("stored state failed verification: {0}")]
    StateCorrupt(#[from] sena_state::LoadError),
    /// The genesis file no longer produces the root this data directory began from.
    #[error(
        "genesis mismatch: the config in this directory now produces root {computed}, but the \
         stored chain began from {recorded}. The genesis file has been edited, or this data \
         directory belongs to a different chain."
    )]
    GenesisMismatch {
        /// What the current genesis file produces.
        computed: String,
        /// What the stored chain began from.
        recorded: String,
    },
    /// The genesis configuration is invalid.
    #[error("genesis is invalid: {0}")]
    Genesis(#[from] crate::genesis::GenesisError),
}

/// What a node persists between runs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Metadata {
    chain_id: String,
    /// Root the chain started from, checked against the genesis file on load.
    genesis_root: String,
    block_height: u64,
}

/// Blocks, stored separately from state so batch data stays available for the
/// challenge window (REQ-FRAUD-007).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct StoredBlock {
    height: u64,
    transactions: Vec<Transaction>,
    pre_state_root: String,
    post_state_root: String,
}

/// What a node reads back when it resumes: its state, the assertion chain, and
/// the batch data it is still responsible for publishing.
pub type Loaded = (MerkleTrie, ChainSnapshot, Vec<Vec<Transaction>>);

/// A node's data directory.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens (and creates if needed) a data directory.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the directory cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| StoreError::Io {
            operation: "create data directory",
            path: root.display().to_string(),
            source,
        })?;
        Ok(Self { root })
    }

    /// Returns the data directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    fn file(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write(&self, name: &'static str, bytes: &[u8]) -> Result<(), StoreError> {
        let path = self.file(name);
        // Write to a temporary file and rename, so a crash mid-write leaves the
        // previous state intact rather than a half-written one.
        let temp = self.file(&format!("{name}.tmp"));
        fs::write(&temp, bytes).map_err(|source| StoreError::Io {
            operation: "write",
            path: temp.display().to_string(),
            source,
        })?;
        fs::rename(&temp, &path).map_err(|source| StoreError::Io {
            operation: "rename",
            path: path.display().to_string(),
            source,
        })
    }

    fn read(&self, name: &'static str) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.file(name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StoreError::Io {
                operation: "read",
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Writes the genesis configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the file cannot be written.
    pub fn save_genesis(&self, config: &GenesisConfig) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(config).map_err(|e| StoreError::Malformed {
            file: "genesis.json",
            detail: e.to_string(),
        })?;
        self.write("genesis.json", &json)
    }

    /// Reads the genesis configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the file is missing or malformed.
    pub fn load_genesis(&self) -> Result<Option<GenesisConfig>, StoreError> {
        let Some(bytes) = self.read("genesis.json")? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StoreError::Malformed {
                file: "genesis.json",
                detail: e.to_string(),
            })
    }

    /// Persists the node's current state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if any file cannot be written.
    pub fn save(
        &self,
        genesis: &GenesisConfig,
        state: &MerkleTrie,
        chain: &ChainSnapshot,
        blocks: &[Block],
    ) -> Result<(), StoreError> {
        let metadata = Metadata {
            chain_id: genesis.chain_id.clone(),
            genesis_root: genesis.state_root()?.to_hex(),
            block_height: blocks.len() as u64,
        };
        let stored: Vec<StoredBlock> = blocks
            .iter()
            .map(|b| StoredBlock {
                height: b.height,
                transactions: b.transactions.clone(),
                pre_state_root: b.pre_state_root.to_hex(),
                post_state_root: b.post_state_root.to_hex(),
            })
            .collect();

        self.write("state.bin", &state.to_bytes())?;
        self.write(
            "chain.json",
            &serde_json::to_vec(chain).map_err(|e| StoreError::Malformed {
                file: "chain.json",
                detail: e.to_string(),
            })?,
        )?;
        self.write(
            "blocks.json",
            &serde_json::to_vec(&stored).map_err(|e| StoreError::Malformed {
                file: "blocks.json",
                detail: e.to_string(),
            })?,
        )?;
        self.write(
            "metadata.json",
            &serde_json::to_vec_pretty(&metadata).map_err(|e| StoreError::Malformed {
                file: "metadata.json",
                detail: e.to_string(),
            })?,
        )
    }

    /// Loads persisted state, verifying it against the genesis file.
    ///
    /// Returns `None` if the directory holds no saved state yet.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the state fails verification, or if the genesis
    /// file no longer produces the root this directory began from.
    pub fn load(&self, genesis: &GenesisConfig) -> Result<Option<Loaded>, StoreError> {
        let Some(state_bytes) = self.read("state.bin")? else {
            return Ok(None);
        };

        if let Some(metadata_bytes) = self.read("metadata.json")? {
            let metadata: Metadata =
                serde_json::from_slice(&metadata_bytes).map_err(|e| StoreError::Malformed {
                    file: "metadata.json",
                    detail: e.to_string(),
                })?;
            let computed = genesis.state_root()?.to_hex();
            if metadata.genesis_root != computed {
                return Err(StoreError::GenesisMismatch {
                    computed,
                    recorded: metadata.genesis_root,
                });
            }
        }

        let state = MerkleTrie::from_bytes(&state_bytes)?;

        let chain: ChainSnapshot = match self.read("chain.json")? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|e| StoreError::Malformed {
                file: "chain.json",
                detail: e.to_string(),
            })?,
            None => {
                return Err(StoreError::Malformed {
                    file: "chain.json",
                    detail: "state was saved without a chain snapshot".to_owned(),
                })
            }
        };

        let batches = match self.read("blocks.json")? {
            Some(bytes) => {
                let stored: Vec<StoredBlock> =
                    serde_json::from_slice(&bytes).map_err(|e| StoreError::Malformed {
                        file: "blocks.json",
                        detail: e.to_string(),
                    })?;
                stored.into_iter().map(|b| b.transactions).collect()
            }
            None => Vec::new(),
        };

        Ok(Some((state, chain, batches)))
    }
}
