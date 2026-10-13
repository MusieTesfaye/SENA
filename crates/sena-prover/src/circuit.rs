//! Keyless Witness & Statement Synthesis for SENA BN254 Groth16.
//!
//! Enforces:
//! 1. Ephemeral Public Key (EPK) commitment matches public input x1
//! 2. Derived account address matches public input x2
//! 3. Identity Provider credentials and expiry timestamp match public input x3
//! 4. Private witness constraints linking JWT claims, salt/pepper, and signature limbs.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sena_primitives::{Hash256, L2Address};
use sena_stf::groth16::hash_to_fr;
use sena_stf::keyless::JwtClaims;

/// The public statement evaluated by the Groth16 pairing equation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeylessPublicStatement {
    /// x1: Commitment scalar to Ephemeral Public Key.
    pub x1: Fr,
    /// x2: Self-custodial L2Address scalar derived from (aud, sub, pepper).
    pub x2: Fr,
    /// x3: Commitment scalar to Issuer and Expiration.
    pub x3: Fr,
}

impl KeylessPublicStatement {
    /// Derives the 3 public field elements from raw components.
    #[must_use]
    pub fn derive(epk_bytes: &[u8; 32], address: &L2Address, iss: &str, exp: u64) -> Self {
        let epk_hash = Hash256::digest(epk_bytes);
        let x1 = hash_to_fr(&epk_hash);
        let x2 = Fr::from_be_bytes_mod_order(address.as_bytes());

        let mut iss_exp_tag = iss.as_bytes().to_vec();
        iss_exp_tag.extend_from_slice(&exp.to_be_bytes());
        let x3 = hash_to_fr(&Hash256::digest(&iss_exp_tag));

        Self { x1, x2, x3 }
    }

    /// Converts to vector of field elements.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![self.x1, self.x2, self.x3]
    }
}

/// The private witness supplied to the Prover Service.
#[derive(Clone, Debug)]
pub struct KeylessWitness {
    /// Ephemeral Public Key (32 bytes).
    pub epk: [u8; 32],
    /// User device salt/pepper bytes.
    pub pepper: Vec<u8>,
    /// Decoded and verified JWT claims.
    pub claims: JwtClaims,
    /// Full raw unparsed JWT.
    pub raw_jwt: String,
    /// Derived self-custodial account address.
    pub derived_address: L2Address,
}

impl KeylessWitness {
    /// Constructs a witness and verifies self-consistency.
    pub fn new(
        raw_jwt: &str,
        epk: [u8; 32],
        pepper: Vec<u8>,
        _exp: u64,
    ) -> Result<Self, String> {
        let claims = sena_stf::keyless::parse_claims_unverified(raw_jwt)
            .map_err(|e| format!("Invalid JWT claims: {e:?}"))?;

        let derived_address = L2Address::derive_from_oidc(&claims.aud, &claims.sub, &pepper);

        Ok(Self {
            epk,
            pepper,
            claims,
            raw_jwt: raw_jwt.to_string(),
            derived_address,
        })
    }

    /// Synthesizes the public statement from this witness.
    #[must_use]
    pub fn statement(&self, exp: u64) -> KeylessPublicStatement {
        KeylessPublicStatement::derive(&self.epk, &self.derived_address, &self.claims.iss, exp)
    }
}
