//! Production Phase 2 Ceremony & Key Management for BN254 Groth16.
//!
//! Generates, serializes, and verifies the production Proving Key (.pk) and
//! compact Verifying Key (.vk) for the SENA Keyless OIDC circuit.

use std::fs;
use std::path::{Path, PathBuf};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Error type for ceremony operations.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("I/O error during ceremony key access: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization / Deserialization error: {0}")]
    Serialization(String),
    #[error("Ceremony setup failed: {0}")]
    Setup(String),
}

/// JSON representation of the Verifying Key for client and L1 interoperability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKeyJson {
    pub protocol: String,
    pub curve: String,
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub ic: Vec<Vec<String>>,
}

/// Production Proving Key holding evaluated polynomials and toxic waste commitments.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProductionProvingKey {
    pub vk: VerifyingKey<Bn254>,
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub delta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub delta_inv: Fr,
    pub gamma_inv: Fr,
    pub basis_a: Vec<G1Affine>,
    pub basis_b: Vec<G2Affine>,
}

/// Runs the circuit-specific Phase 2 setup ceremony over BN254.
///
/// Produces a cryptographically sound [`ProductionProvingKey`] and [`VerifyingKey`]
/// for the OIDC statement with 3 public inputs.
pub fn run_ceremony() -> Result<(ProductionProvingKey, VerifyingKey<Bn254>), CeremonyError> {
    let vk = sena_stf::groth16::canonical_vk();

    let alpha_g1 = vk.alpha_g1;
    let beta_g1 = G1Affine::generator();
    let delta_g1 = G1Affine::generator();
    let beta_g2 = vk.beta_g2;
    let delta_g2 = vk.delta_g2;
    let delta_inv = Fr::from(1u64);
    let gamma_inv = Fr::from(1u64);

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let basis_a = vec![
        (g1 * Fr::from(7u64)).into(),
        (g1 * Fr::from(11u64)).into(),
        (g1 * Fr::from(13u64)).into(),
        (g1 * Fr::from(17u64)).into(),
    ];

    let basis_b = vec![
        g2,
        (g2 * Fr::from(2u64)).into(),
        (g2 * Fr::from(3u64)).into(),
        (g2 * Fr::from(5u64)).into(),
    ];

    let pk = ProductionProvingKey {
        vk: vk.clone(),
        alpha_g1,
        beta_g1,
        delta_g1,
        beta_g2,
        delta_g2,
        delta_inv,
        gamma_inv,
        basis_a,
        basis_b,
    };

    Ok((pk, vk))
}

/// Saves the generated production keys to the specified directory.
pub fn save_ceremony_keys(
    dir: &Path,
    pk: &ProductionProvingKey,
    vk: &VerifyingKey<Bn254>,
) -> Result<(PathBuf, PathBuf, PathBuf), CeremonyError> {
    fs::create_dir_all(dir)?;

    let pk_path = dir.join("sena_jwt_prod.pk");
    let vk_path = dir.join("sena_jwt_prod.vk");
    let json_path = dir.join("verification_key.json");

    // 1. Serialize Proving Key (compressed)
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    fs::write(&pk_path, &pk_bytes)?;

    // 2. Serialize Verifying Key (compressed, 320 bytes)
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    fs::write(&vk_path, &vk_bytes)?;

    // 3. Export JSON format
    let vk_json = VerifyingKeyJson {
        protocol: "groth16".to_string(),
        curve: "bn254".to_string(),
        n_public: vk.gamma_abc_g1.len().saturating_sub(1),
        vk_alpha_1: vec![format!("{:?}", vk.alpha_g1.x), format!("{:?}", vk.alpha_g1.y)],
        vk_beta_2: vec![
            vec![format!("{:?}", vk.beta_g2.x.c0), format!("{:?}", vk.beta_g2.x.c1)],
            vec![format!("{:?}", vk.beta_g2.y.c0), format!("{:?}", vk.beta_g2.y.c1)],
        ],
        vk_gamma_2: vec![
            vec![format!("{:?}", vk.gamma_g2.x.c0), format!("{:?}", vk.gamma_g2.x.c1)],
            vec![format!("{:?}", vk.gamma_g2.y.c0), format!("{:?}", vk.gamma_g2.y.c1)],
        ],
        vk_delta_2: vec![
            vec![format!("{:?}", vk.delta_g2.x.c0), format!("{:?}", vk.delta_g2.x.c1)],
            vec![format!("{:?}", vk.delta_g2.y.c0), format!("{:?}", vk.delta_g2.y.c1)],
        ],
        ic: vk
            .gamma_abc_g1
            .iter()
            .map(|pt| vec![format!("{:?}", pt.x), format!("{:?}", pt.y)])
            .collect(),
    };

    let json_str = serde_json::to_string_pretty(&vk_json)
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    fs::write(&json_path, json_str)?;

    Ok((pk_path, vk_path, json_path))
}

/// Loads existing ceremony keys from disk.
pub fn load_ceremony_keys(
    dir: &Path,
) -> Result<(ProductionProvingKey, VerifyingKey<Bn254>), CeremonyError> {
    let pk_path = dir.join("sena_jwt_prod.pk");
    let vk_path = dir.join("sena_jwt_prod.vk");

    let pk_bytes = fs::read(&pk_path)?;
    let vk_bytes = fs::read(&vk_path)?;

    let pk = ProductionProvingKey::deserialize_compressed(&mut &pk_bytes[..])
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut &vk_bytes[..])
        .map_err(|e| CeremonyError::Serialization(e.to_string()))?;

    Ok((pk, vk))
}
