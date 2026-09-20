//! The SENA node.
//!
//! One binary, two modes. As a **sequencer** it admits transactions, orders and
//! executes them, publishes the batch, and posts a bonded assertion. As a
//! **verifier** it re-executes published batches independently and challenges
//! anything that disagrees.
//!
//! Sharing a binary between the two is deliberate (NFR-MAINT-004). Separate
//! implementations would eventually drift, and a verifier whose execution
//! differs from an honest sequencer's opens disputes it deserves to lose.
//!
//! ```
//! use sena_fraudproof::{AssertionChain, PartyId, DEFAULT_CHALLENGE_WINDOW};
//! use sena_node::{Sequencer, VerifierNode};
//! use sena_state::MerkleTrie;
//!
//! let genesis = MerkleTrie::new();
//! let chain = AssertionChain::new(genesis.root(), DEFAULT_CHALLENGE_WINDOW, 1_000_000);
//!
//! let sequencer = Sequencer::new(genesis.clone(), chain, PartyId(1), 1_000_000);
//! // A verifier starts from the same genesis and rebuilds everything itself.
//! let verifier = VerifierNode::new(genesis, PartyId(2));
//!
//! assert_eq!(sequencer.finalized_height(), 0);
//! assert_eq!(verifier.state.root(), sequencer.state.root());
//! ```

#![doc(html_root_url = "https://docs.rs/sena-node")]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod genesis;
pub mod mempool;
pub mod rpc;
pub mod sequencer;
pub mod server;
pub mod store;
pub mod verifier_node;

pub use genesis::{Allocation, GenesisConfig, GenesisError};
pub use mempool::{Mempool, RejectReason};
pub use rpc::{handle, Request, Response};
pub use sequencer::{Block, Confirmation, ProduceError, Sequencer};
pub use server::{ServerConfig, ServerError};
pub use store::{Store, StoreError};
pub use verifier_node::{Outcome, VerifierNode};
