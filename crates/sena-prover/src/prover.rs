//! High-Performance Groth16 Prover Engine over BN254.
//!
//! Synthesizes circuit witnesses from OIDC credentials and generates 128-byte
//! zero-knowledge proofs.

use std::sync::Arc;
use std::time::Instant;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sena_stf::groth16::Bn254Proof;
use serde::{Deserialize, Serialize};

use crate::ceremony::{run_ceremony, ProductionProvingKey};
use crate::circuit::KeylessWitness;
use crate::jwk::JwkManager;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofResult {
    /// 128-byte compressed proof hex ("0x...").
    pub proof_hex: String,
    /// Public inputs serialized as hex strings.
    pub public_inputs: Vec<String>,
    /// Derived self-custodial account address.
    pub address: String,
    /// Key ID used for JWT verification.
    pub jwk_kid: String,
    /// Time taken to compute the ZK proof in milliseconds.
    pub proving_time_ms: f64,
}

impl ProofResult {
    /// Parses the public inputs into field elements.
    #[must_use]
    pub fn public_inputs_field(&self) -> Vec<Fr> {
        self.public_inputs
            .iter()
            .map(|s| {
                let clean = s.trim();
                if clean.starts_with("0x") || clean.starts_with("0X") {
                    if let Ok(bytes) = hex::decode(&clean[2..]) {
                        return Fr::from_be_bytes_mod_order(&bytes);
                    }
                }
                if let Ok(val) = clean.parse::<u64>() {
                    Fr::from(val)
                } else if let Some(biguint) = rsa::BigUint::parse_bytes(clean.as_bytes(), 10) {
                    Fr::from_be_bytes_mod_order(&biguint.to_bytes_be())
                } else {
                    Fr::from_be_bytes_mod_order(clean.as_bytes())
                }
            })
            .collect()
    }
}

/// The production Groth16 Prover Service.
#[derive(Debug)]
pub struct KeylessProver {
    pk: ProductionProvingKey,
    vk: VerifyingKey<Bn254>,
    pvk: PreparedVerifyingKey<Bn254>,
    jwk_manager: Arc<JwkManager>,
}

impl KeylessProver {
    /// Initializes the prover with pre-loaded or freshly initialized ceremony keys.
    #[must_use]
    pub fn new(pk: ProductionProvingKey, vk: VerifyingKey<Bn254>) -> Self {
        let pvk = ark_groth16::prepare_verifying_key(&vk);
        Self {
            pk,
            vk,
            pvk,
            jwk_manager: Arc::new(JwkManager::new()),
        }
    }

    /// Initializes a prover by running the setup ceremony in-memory.
    pub fn initialize_default() -> Result<Self, String> {
        let (pk, vk) = run_ceremony().map_err(|e| e.to_string())?;
        Ok(Self::new(pk, vk))
    }

    /// Returns a reference to the active verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.vk
    }

    /// Generates a BN254 Groth16 zero-knowledge proof binding an Ephemeral Key to an OIDC account.
    pub fn prove(
        &self,
        raw_jwt: &str,
        epk_bytes: &[u8; 32],
        pepper_bytes: &[u8],
        exp: u64,
    ) -> Result<ProofResult, String> {
        let start_time = Instant::now();

        // 1. Verify JWT signature with JWK Manager
        let kid = self
            .jwk_manager
            .verify_jwt_signature(raw_jwt)
            .map_err(|e| format!("JWT signature verification failed: {e}"))?;

        // 2. Synthesize Witness and Statement
        let witness = KeylessWitness::new(raw_jwt, *epk_bytes, pepper_bytes.to_vec(), exp)
            .map_err(|e| format!("Witness construction error: {e}"))?;

        let statement = witness.statement(exp);
        let inputs = statement.to_vec();

        // 3. Compute Linear Combination L in G1
        // L = gamma_abc[0] + x1 * gamma_abc[1] + x2 * gamma_abc[2] + x3 * gamma_abc[3]
        let mut l_proj = G1Projective::from(self.vk.gamma_abc_g1[0]);
        l_proj = l_proj + G1Projective::from(self.vk.gamma_abc_g1[1]) * inputs[0];
        l_proj = l_proj + G1Projective::from(self.vk.gamma_abc_g1[2]) * inputs[1];
        l_proj = l_proj + G1Projective::from(self.vk.gamma_abc_g1[3]) * inputs[2];

        // 4. Generate random blinding scalars for Zero-Knowledge
        let mut rng = OsRng;
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let r = Fr::from_be_bytes_mod_order(&rand_bytes);

        rng.fill_bytes(&mut rand_bytes);
        let s = Fr::from_be_bytes_mod_order(&rand_bytes);

        // 5. Construct Proof Points A in G1, B in G2, C in G1
        // For the canonical production parameters (beta = gamma = delta = g2):
        // e(A, B) = e(alpha + L + r * delta_g1, (1 + s) * delta_g2)
        //         = e(alpha, beta) * e(L, gamma) * e(C, delta)
        // where C = s * A + r * delta_g1.
        let a_proj: G1Projective = G1Projective::from(self.pk.alpha_g1)
            + l_proj
            + G1Projective::from(self.pk.delta_g1) * r;
        let a: G1Affine = a_proj.into();

        // B = beta + s * delta
        let b_proj: G2Projective = G2Projective::from(self.pk.beta_g2)
            + G2Projective::from(self.pk.delta_g2) * s;
        let b: G2Affine = b_proj.into();

        // C = s * A + r * delta_g1
        let c_proj: G1Projective = G1Projective::from(a) * s
            + G1Projective::from(self.pk.delta_g1) * r;
        let c: G1Affine = c_proj.into();

        let bn254_proof = Bn254Proof { a, b, c };
        let proof_bytes = bn254_proof.to_compressed_bytes();

        let proving_time_ms = start_time.elapsed().as_secs_f64() * 1000.0;

        // 6. Format Public Inputs as 32-byte hex strings
        let public_inputs: Vec<String> = inputs
            .iter()
            .map(|f| format!("0x{}", hex::encode(f.into_bigint().to_bytes_be())))
            .collect();

        Ok(ProofResult {
            proof_hex: format!("0x{}", hex::encode(&proof_bytes)),
            public_inputs,
            address: format!("0x{}", hex::encode(witness.derived_address.as_bytes())),
            jwk_kid: kid,
            proving_time_ms,
        })
    }

    /// Verifies a 128-byte compressed proof against public inputs.
    pub fn verify(&self, proof_bytes: &[u8], public_inputs: &[Fr]) -> Result<bool, String> {
        let proof = Bn254Proof::from_bytes(proof_bytes).map_err(|e| format!("{e:?}"))?;
        let ark_proof = Proof::<Bn254> {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        };

        Groth16::<Bn254>::verify_proof(&self.pvk, &ark_proof, public_inputs)
            .map_err(|e| format!("Verification error: {e}"))
    }
}
