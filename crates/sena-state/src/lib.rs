//! Merklized state for the SENA Network.
//!
//! All L2 state — accounts, balances, social links, whitelisted assets,
//! governance parameters — lives in one sparse binary Merkle trie. The root of
//! that trie is what the sequencer commits to Aptos L1 in an assertion, and what
//! a fraud proof ultimately disputes.
//!
//! Two operations matter to the protocol beyond ordinary reads and writes:
//!
//! - **Inclusion proofs** let a user withdraw from the L1 bridge against a
//!   finalized root without the sequencer's cooperation (REQ-CORE-004).
//! - **Non-inclusion proofs** let a One-Step Proof show that a disputed
//!   instruction read an empty slot (REQ-FRAUD-016).
//!
//! ```
//! use sena_state::MerkleTrie;
//! use sena_primitives::Hash256;
//!
//! let mut trie = MerkleTrie::new();
//! let alice = Hash256::digest(b"alice");
//! trie.insert(alice, b"1000");
//! let root = trie.root();
//!
//! // Anyone holding the root can check the balance without trusting the node.
//! let proof = trie.prove(&alice);
//! assert!(proof.verify_inclusion(&root, &alice, b"1000").is_ok());
//!
//! // And can show that an unused account is genuinely absent.
//! let bob = Hash256::digest(b"bob");
//! assert!(trie.prove(&bob).verify_non_inclusion(&root, &bob).is_ok());
//! ```

#![doc(html_root_url = "https://docs.rs/sena-state")]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod node;
pub mod proof;
pub mod trie;

pub use node::{hash_value, Node};
pub use proof::{MerkleProof, ProofError, Terminal, MAX_DEPTH};
pub use trie::MerkleTrie;
