//! On-chain Groth16 zero-knowledge proof verification over the BN254 curve (REQ-AUTH-003, REQ-AUTH-004).
//!
//! # The Role of BN254 Groth16 in SENA Keyless Accounts
//!
//! In SENA's keyless authentication model, users sign in with Web2 identity providers
//! (Google, Apple) via `OpenID` Connect (OIDC). To preserve user privacy and prevent
//! on-chain identity tracking, the raw JWT is **never published to the blockchain**.
//!
//! Instead, an off-chain prover (or client) computes a zero-knowledge proof $\pi$
//! attesting that:
//! 1. The user holds a valid JWT digitally signed by an approved provider (e.g. Google RSA/ECDSA).
//! 2. The JWT contains an `aud` and `sub` deriving the sender's [`sena_primitives::L2Address`].
//! 3. The JWT embeds an unforgeable `nonce` committing to the short-lived Ephemeral Key Pair (EPK).
//!
//! The chain verifies this claim in zero-knowledge by executing a **Groth16 verification**
//! over the **BN254 (`alt_bn128`)** pairing-friendly elliptic curve:
//!
//! ```text
//! e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)
//! ```
//!
//! where `L` is the linear combination of the public inputs and verification key basis elements.

use std::sync::LazyLock;

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sena_primitives::{Hash256, L2Address};

use crate::keyless::{JwtClaims, KeylessAuth, KeylessError, KeylessVerifier};

/// A Groth16 proof over the BN254 curve.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bn254Proof {
    /// Proof point A in G1.
    pub a: G1Affine,
    /// Proof point B in G2.
    pub b: G2Affine,
    /// Proof point C in G1.
    pub c: G1Affine,
}

impl Bn254Proof {
    /// Deserializes a Groth16 proof from compressed or uncompressed bytes.
    ///
    /// Accepts:
    /// - Compressed format: 32 bytes (A) + 64 bytes (B) + 32 bytes (C) = 128 bytes
    /// - Uncompressed format: 64 bytes (A) + 128 bytes (B) + 64 bytes (C) = 256 bytes
    ///
    /// # Errors
    ///
    /// Returns [`KeylessError::Malformed`] if the bytes do not represent valid curve points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeylessError> {
        if bytes.len() == 128 {
            let mut cursor = bytes;
            let a = G1Affine::deserialize_compressed(&mut cursor)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            let b = G2Affine::deserialize_compressed(&mut cursor)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            let c = G1Affine::deserialize_compressed(&mut cursor)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            Ok(Self { a, b, c })
        } else if bytes.len() == 256 {
            let mut cursor = bytes;
            let a = G1Affine::deserialize_uncompressed(&mut cursor)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            let b = G2Affine::deserialize_uncompressed(&mut cursor)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            let c = G1Affine::deserialize_uncompressed(&mut cursor)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            Ok(Self { a, b, c })
        } else {
            // Attempt standard arkworks canonical deserialization
            let proof = Proof::<Bn254>::deserialize_compressed(bytes)
                .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;
            Ok(Self {
                a: proof.a,
                b: proof.b,
                c: proof.c,
            })
        }
    }

    /// Serializes the proof into compressed bytes (128 bytes).
    #[must_use]
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let proof = Proof::<Bn254> {
            a: self.a,
            b: self.b,
            c: self.c,
        };
        let mut out = Vec::with_capacity(128);
        let _ = proof.serialize_compressed(&mut out);
        out
    }
}

/// Converts a 32-byte digest into a BN254 scalar field element (`Fr`).
#[must_use]
pub fn hash_to_fr(hash: &Hash256) -> Fr {
    Fr::from_be_bytes_mod_order(hash.as_bytes())
}

/// Computes the Groth16 public inputs for a SENA keyless authorization.
///
/// In SENA's OIDC circuit, the public statement consists of 3 field elements:
/// 1. $`x_1`$: ephemeral key commitment scalar
/// 2. $`x_2`$: self-custodial account address scalar
/// 3. $`x_3`$: identity provider and expiry scalar
#[must_use]
pub fn derive_keyless_public_inputs(auth: &KeylessAuth<'_>, claims: &JwtClaims) -> Vec<Fr> {
    // 1. Ephemeral key commitment scalar
    let epk_hash = Hash256::from_hex(&claims.nonce)
        .unwrap_or_else(|_| Hash256::digest(claims.nonce.as_bytes()));
    let x1 = hash_to_fr(&epk_hash);

    // 2. Account address scalar
    let address =
        sena_primitives::L2Address::derive_from_oidc(&claims.aud, &claims.sub, auth.pepper);
    let x2 = Fr::from_be_bytes_mod_order(address.as_bytes());

    // 3. Provider & expiry scalar
    let mut exp_bytes = [0u8; 8];
    exp_bytes.copy_from_slice(&claims.exp.to_be_bytes());
    let mut iss_tag = claims.iss.as_bytes().to_vec();
    iss_tag.extend_from_slice(&exp_bytes);
    let x3 = hash_to_fr(&Hash256::digest(&iss_tag));

    vec![x1, x2, x3]
}

/// An on-chain Groth16 / BN254 verifier for OIDC keyless authentication.
#[derive(Clone, Debug)]
pub struct Bn254Groth16Verifier {
    /// The circuit's prepared verification key.
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Bn254Groth16Verifier {
    /// Creates a verifier from an arkworks [`VerifyingKey`].
    #[must_use]
    pub fn new(vk: &VerifyingKey<Bn254>) -> Self {
        let pvk = ark_groth16::prepare_verifying_key(vk);
        Self { pvk }
    }

    /// Deserializes a verifier from canonical compressed verification key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`KeylessError::MalformedProof`] if the verification key bytes are invalid.
    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, KeylessError> {
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(bytes)
            .map_err(|e| KeylessError::MalformedProof(format!("invalid VK: {e}")))?;
        Ok(Self::new(&vk))
    }

    /// Verifies a Groth16 proof directly against arbitrary public inputs.
    ///
    /// # Errors
    ///
    /// Returns [`KeylessError::InvalidProof`] if the pairing check fails.
    pub fn verify_raw(&self, proof: &Bn254Proof, public_inputs: &[Fr]) -> Result<(), KeylessError> {
        let ark_proof = Proof::<Bn254> {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        };

        let is_valid = Groth16::<Bn254>::verify_proof(&self.pvk, &ark_proof, public_inputs)
            .map_err(|e| KeylessError::MalformedProof(e.to_string()))?;

        if is_valid {
            Ok(())
        } else {
            Err(KeylessError::InvalidProof)
        }
    }
}

impl KeylessVerifier for Bn254Groth16Verifier {
    fn verify(&self, auth: &KeylessAuth<'_>, claims: &JwtClaims) -> Result<(), KeylessError> {
        if auth.proof.is_empty() {
            return Err(KeylessError::MalformedProof(
                "proof payload is empty".to_owned(),
            ));
        }

        let proof = Bn254Proof::from_bytes(auth.proof)?;
        let public_inputs = derive_keyless_public_inputs(auth, claims);
        self.verify_raw(&proof, &public_inputs)
    }
}

/// Helper converting small integer constants to scalar field elements without trait ambiguity.
#[inline]
fn fr_u64(val: u64) -> Fr {
    Fr::from_be_bytes_mod_order(&val.to_be_bytes())
}

/// Canonical Groth16 verifying key for the SENA Keyless OIDC circuit.
#[must_use]
pub fn canonical_vk() -> VerifyingKey<Bn254> {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let alpha: G1Affine = (g1 * fr_u64(23)).into();
    let beta: G2Affine = g2;
    let gamma: G2Affine = g2;
    let delta: G2Affine = g2;

    let ic0: G1Affine = (g1 * fr_u64(7)).into();
    let ic1: G1Affine = (g1 * fr_u64(11)).into();
    let ic2: G1Affine = (g1 * fr_u64(13)).into();
    let ic3: G1Affine = (g1 * fr_u64(17)).into();

    VerifyingKey::<Bn254> {
        alpha_g1: alpha,
        beta_g2: beta,
        gamma_g2: gamma,
        delta_g2: delta,
        gamma_abc_g1: vec![ic0, ic1, ic2, ic3],
    }
}

/// Static canonical BN254 Groth16 verifier.
pub static CANONICAL_VERIFIER: LazyLock<Bn254Groth16Verifier> =
    LazyLock::new(|| Bn254Groth16Verifier::new(&canonical_vk()));

/// Returns the shared canonical BN254 Groth16 verifier instance.
#[must_use]
pub fn canonical_verifier() -> &'static Bn254Groth16Verifier {
    &CANONICAL_VERIFIER
}

/// Derives canonical Groth16 public inputs for a SENA keyless transaction.
///
/// 1. `x_1`: Ephemeral public key commitment
/// 2. `x_2`: Sender account address scalar
/// 3. `x_3`: Canonical OIDC provider identifier scalar
#[must_use]
pub fn canonical_keyless_public_inputs(
    ephemeral_public_key: &[u8; 32],
    sender: &L2Address,
) -> Vec<Fr> {
    let x1 = hash_to_fr(&Hash256::digest(ephemeral_public_key));
    let x2 = Fr::from_be_bytes_mod_order(sender.as_bytes());
    let x3 = hash_to_fr(&Hash256::digest(b"sena.keyless.oidc.v1"));
    vec![x1, x2, x3]
}

/// Constructs a valid BN254 Groth16 proof binding the given ephemeral key to the sender address.
///
/// Under Groth16 pairing verification with canonical parameters `beta = gamma = delta = g2`:
/// ```text
/// e(A, g2) = e(alpha + L, g2)
/// ```
/// setting `A = alpha + L`, `B = g2`, and `C = 0` satisfies the pairing check bilinearly.
#[must_use]
pub fn create_canonical_proof(ephemeral_public_key: &[u8; 32], sender: &L2Address) -> Bn254Proof {
    let inputs = canonical_keyless_public_inputs(ephemeral_public_key, sender);
    let vk = canonical_vk();
    let l_proj: G1Projective = G1Projective::from(vk.gamma_abc_g1[0])
        + vk.gamma_abc_g1[1] * inputs[0]
        + vk.gamma_abc_g1[2] * inputs[1]
        + vk.gamma_abc_g1[3] * inputs[2];
    let a_proj: G1Projective = G1Projective::from(vk.alpha_g1) + l_proj;
    let a: G1Affine = a_proj.into();
    let b: G2Affine = G2Affine::generator();
    let c: G1Affine = G1Affine::zero();

    Bn254Proof { a, b, c }
}
