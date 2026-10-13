//! SENA Keyless Prover Service & Production Ceremony Pipeline.
//!
//! Provides:
//! - Full BN254 Groth16 R1CS Circuit for OpenID Connect verification.
//! - Phase 2 Ceremony parameter generation and disk serialization.
//! - Google & Apple JWK certificate caching and RSA-2048 validation.
//! - Heavy Groth16 Prover and external HTTP REST service daemon.
//! - Production Byzantine-Fault-Tolerant Distributed Pepper Storage (tOPRF).

pub mod ceremony;
pub mod circuit;
pub mod jwk;
pub mod odis;
pub mod pepper;
pub mod prover;
pub mod server;

pub use ceremony::{load_ceremony_keys, run_ceremony, save_ceremony_keys, CeremonyError};
pub use circuit::{KeylessPublicStatement, KeylessWitness};
pub use jwk::JwkManager;
pub use odis::{
    client_blind_identifier, client_unblind_identifier, hash_identifier_to_curve, OdisEvaluateRequest,
    OdisEvaluateResponse, OdisService,
};
pub use pepper::{
    client_blind_identity, client_unblind_threshold_pepper, export_cluster_keys,
    generate_threshold_shares, run_guardian_node, ClusterConfig, DistributedPepperClient, DleqProof,
    GuardianNodeConfig, GuardianShare,
};
pub use prover::{KeylessProver, ProofResult};
pub use server::run_prover_server;
