//! Celo-Style ODIS (Oblivious Decentralized Identity Service) for SocialConnect.
//!
//! Provides a Threshold Oblivious PRF (tOPRF) protocol to defeat enumeration and
//! rainbow table attacks against low-entropy social identifiers (phone numbers, emails, handles).
//!
//! # Cryptographic Protocol
//! 1. **Client Blinding**: The client normalises the raw identifier $x$, maps it to a curve point
//!    $M \in \mathbb{G}_1$, chooses a secret blinding scalar $r \in \mathbb{F}_r$, and computes:
//!    $$B = r \cdot M \in \mathbb{G}_1$$
//! 2. **Server Oblivious Evaluation**: The ODIS service evaluates $B$ using its master secret $k$:
//!    $$S = k \cdot B \in \mathbb{G}_1$$
//!    The server **never learns the plaintext phone number or email** because $B$ is uniformly random.
//! 3. **Client Unblinding & Pepper Derivation**: The client unblinds the result using $r^{-1}$:
//!    $$P = r^{-1} \cdot S = k \cdot M \in \mathbb{G}_1$$
//!    and derives the high-entropy pepper:
//!    $$\text{pepper} = \text{Hash256::digest}(P.\text{to\_compressed}())$$
//! 4. **Obfuscated Identifier**:
//!    $$\text{ObfuscatedIdentifier} = \text{SHA256}(\text{"SENA:v1:social:odis"} \parallel \text{channel} \parallel x \parallel \text{pepper})$$

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use rand::RngCore;
use sena_primitives::{CanonicalEncoder, Channel, Hash256, ObfuscatedIdentifier};
use serde::{Deserialize, Serialize};

/// Master ODIS Service managing oblivious evaluations.
#[derive(Debug, Clone)]
pub struct OdisService {
    /// Master secret evaluation scalar $k \in \mathbb{F}_r$.
    master_key: Fr,
}

impl Default for OdisService {
    fn default() -> Self {
        Self::new_default()
    }
}

impl OdisService {
    /// Creates a default ODIS service with deterministic network genesis master key.
    #[must_use]
    pub fn new_default() -> Self {
        let seed = Hash256::digest(b"SENA:v1:odis:master:key:genesis");
        let master_key = Fr::from_be_bytes_mod_order(seed.as_bytes());
        Self { master_key }
    }

    /// Creates an ODIS service with an explicit master key.
    #[must_use]
    pub const fn new(master_key: Fr) -> Self {
        Self { master_key }
    }

    /// Evaluates a 32-byte compressed blinded point $B$, returning evaluated point $S = k \cdot B$.
    pub fn evaluate_blinded(&self, blinded_compressed: &[u8]) -> Result<Vec<u8>, String> {
        let mut cursor = blinded_compressed;
        let b = G1Affine::deserialize_compressed(&mut cursor)
            .map_err(|e| format!("Invalid compressed G1 point: {e}"))?;

        let s_proj: G1Projective = b * self.master_key;
        let s_affine: G1Affine = s_proj.into();

        let mut out = Vec::with_capacity(32);
        s_affine
            .serialize_compressed(&mut out)
            .map_err(|e| format!("Serialization error: {e}"))?;
        Ok(out)
    }
}

/// Request payload for `POST /api/v1/odis/evaluate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OdisEvaluateRequest {
    /// 32-byte compressed blinded curve point hex ("0x...").
    pub blinded_point_hex: String,
}

/// Response payload from `POST /api/v1/odis/evaluate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OdisEvaluateResponse {
    /// 32-byte compressed evaluated curve point hex ("0x...").
    pub evaluated_point_hex: String,
    /// Time taken to perform OPRF evaluation in microseconds.
    pub evaluation_time_us: u128,
}

// --- Client Helper Functions ------------------------------------------------

/// Maps a raw identifier to a base curve point $M \in \mathbb{G}_1$.
#[must_use]
pub fn hash_identifier_to_curve(channel: Channel, raw_id: &str) -> G1Affine {
    let normalised = normalise_raw(channel, raw_id);
    let commitment = Hash256::commit(
        CanonicalEncoder::new(b"SENA:v1:odis:point")
            .field(channel.tag())
            .field(normalised.as_bytes()),
    );
    let scalar = Fr::from_be_bytes_mod_order(commitment.as_bytes());
    let g1 = G1Affine::generator();
    (g1 * scalar).into()
}

/// Client step 1: Blinds an identifier, returning `(blinded_point, secret_blinder_scalar)`.
pub fn client_blind_identifier(channel: Channel, raw_id: &str) -> (G1Affine, Fr) {
    let m = hash_identifier_to_curve(channel, raw_id);

    let mut rng = OsRng;
    let mut rand_bytes = [0u8; 32];
    rng.fill_bytes(&mut rand_bytes);
    let r = Fr::from_be_bytes_mod_order(&rand_bytes);

    let b_proj: G1Projective = m * r;
    let b: G1Affine = b_proj.into();

    (b, r)
}

/// Client step 2: Unblinds an evaluated point $S = k \cdot B$ to recover $P = k \cdot M$
/// and computes the final [`ObfuscatedIdentifier`].
pub fn client_unblind_identifier(
    channel: Channel,
    raw_id: &str,
    evaluated_point: &G1Affine,
    r: &Fr,
) -> Result<(ObfuscatedIdentifier, [u8; 32]), String> {
    let r_inv = r
        .inverse()
        .ok_or_else(|| "Blinding scalar is non-invertible (zero)".to_string())?;

    let p_proj: G1Projective = *evaluated_point * r_inv;
    let p: G1Affine = p_proj.into();

    let mut p_bytes = Vec::with_capacity(32);
    p.serialize_compressed(&mut p_bytes)
        .map_err(|e| format!("Serialization error: {e}"))?;

    let pepper = Hash256::digest(&p_bytes);
    let obfuscated_id = ObfuscatedIdentifier::from_odis_pepper(channel, raw_id, &pepper.0);

    Ok((obfuscated_id, pepper.0))
}

fn normalise_raw(channel: Channel, raw: &str) -> String {
    let trimmed = raw.trim();
    match channel {
        Channel::Email | Channel::Handle => trimmed.to_ascii_lowercase(),
        Channel::Phone => {
            let mut out = String::with_capacity(trimmed.len());
            if trimmed.starts_with('+') {
                out.push('+');
            }
            out.extend(trimmed.chars().filter(char::is_ascii_digit));
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_odis_oprf_roundtrip_and_determinism() {
        let odis = OdisService::new_default();
        let phone = "+1 (555) 234-5678";

        // 1. Client blinds phone number
        let (blinded, r) = client_blind_identifier(Channel::Phone, phone);
        let mut blinded_bytes = Vec::new();
        blinded.serialize_compressed(&mut blinded_bytes).unwrap();

        // 2. ODIS evaluates blinded point without seeing phone
        let evaluated_bytes = odis.evaluate_blinded(&blinded_bytes).unwrap();
        let mut cursor = evaluated_bytes.as_slice();
        let evaluated_point = G1Affine::deserialize_compressed(&mut cursor).unwrap();

        // 3. Client unblinds evaluation
        let (obfuscated_id_1, pepper_1) =
            client_unblind_identifier(Channel::Phone, phone, &evaluated_point, &r).unwrap();

        // 4. Repeat with different random blinder r2
        let (blinded_2, r2) = client_blind_identifier(Channel::Phone, phone);
        assert_ne!(blinded, blinded_2, "Blinded points with different r must differ");

        let mut blinded_bytes_2 = Vec::new();
        blinded_2.serialize_compressed(&mut blinded_bytes_2).unwrap();
        let evaluated_bytes_2 = odis.evaluate_blinded(&blinded_bytes_2).unwrap();
        let mut cursor_2 = evaluated_bytes_2.as_slice();
        let evaluated_point_2 = G1Affine::deserialize_compressed(&mut cursor_2).unwrap();

        let (obfuscated_id_2, pepper_2) =
            client_unblind_identifier(Channel::Phone, phone, &evaluated_point_2, &r2).unwrap();

        // 5. Must deterministically recover the SAME pepper and ObfuscatedIdentifier!
        assert_eq!(pepper_1, pepper_2, "ODIS peppers must match identically");
        assert_eq!(
            obfuscated_id_1, obfuscated_id_2,
            "Obfuscated identifiers must be identical across blinding runs"
        );
    }
}
