//! SENA Keyless Prover Service & Production Ceremony Pipeline.
//!
//! Provides:
//! - Full BN254 Groth16 R1CS Circuit for OpenID Connect verification.
//! - Phase 2 Ceremony parameter generation and disk serialization.
//! - Google & Apple JWK certificate caching and RSA-2048 validation.
//! - Heavy Groth16 Prover and external HTTP REST service daemon.

pub mod ceremony;
pub mod circuit;
pub mod jwk;
pub mod prover;
pub mod server;

pub use ceremony::{load_ceremony_keys, run_ceremony, save_ceremony_keys, CeremonyError};
pub use circuit::{KeylessPublicStatement, KeylessWitness};
pub use jwk::JwkManager;
pub use prover::{KeylessProver, ProofResult};
pub use server::run_prover_server;
