//! Deterministic core types shared by every SENA component.
//!
//! This crate sits underneath the state trie, the state transition function, the
//! node and the fraud proof engine. Everything in it is pure: no clock, no
//! entropy, no I/O, no floating point, and no unordered collection ever reaches
//! a digest. That restraint is not stylistic. SENA's security rests on an
//! honest verifier re-executing the chain and getting byte-identical results
//! (SRS REQ-FRAUD-031); a primitive that varies between machines would make
//! honest parties disagree and hand a dishonest sequencer a defence.
//!
//! # Layout
//!
//! - [`encoding`] — unambiguous, domain-separated byte encoding for commitments
//! - [`hash`] — the 32-byte digest used throughout
//! - [`address`] — account addresses and asset identifiers
//! - [`identity`] — privacy-preserving social identifier hashing
//!
//! # Example
//!
//! ```
//! use sena_primitives::{Channel, HashedIdentifier, L2Address, NetworkSalt};
//!
//! // An account derived from a Google sign-in, with no key material involved.
//! let address = L2Address::derive_from_oidc(
//!     "sena-wallet.example",   // aud: the application
//!     "108241...",             // sub: the provider's subject identifier
//!     b"user-specific-pepper", // pepper: held privately by the user
//! );
//!
//! // The handle that resolves to it, stored as an opaque digest.
//! let salt = NetworkSalt::new(*b"sena-mainnet-salt");
//! let handle = HashedIdentifier::new(Channel::Handle, "@alice", &salt);
//!
//! assert_eq!(address, L2Address::derive_from_oidc(
//!     "sena-wallet.example", "108241...", b"user-specific-pepper"));
//! assert_eq!(handle, HashedIdentifier::new(Channel::Handle, "@ALICE", &salt));
//! ```

#![doc(html_root_url = "https://docs.rs/sena-primitives")]
#![warn(missing_docs, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod address;
pub mod codec;
pub mod encoding;
pub mod hash;
pub mod identity;
pub mod serde_hex;

pub use address::{AssetId, L2Address};
pub use codec::{DecodeError, Reader, Writer};
pub use encoding::{domain, CanonicalEncoder};
pub use hash::{Hash256, HashParseError};
pub use identity::{Channel, HashedIdentifier, NetworkSalt};
