//! Keyless accounts on the Aptos Keyless circuit (REQ-AUTH-002..004).
//!
//! # The relation
//!
//! A keyless account is controlled by whoever can sign in to a Web2 identity
//! provider as one particular user. The chain never sees the JWT. Instead the
//! wallet obtains a Groth16 proof, over the audited Aptos Keyless circom
//! circuit (`aptos-labs/keyless-zk-proofs`, tag `circuit-v1.0.1`), that it
//! holds a JWT which:
//!
//! - is RSA-signed by the JWK whose Poseidon hash is `jwk_hash`;
//! - was issued by the issuer whose Poseidon hash is `iss_hash`;
//! - names a user and application whose identity commitment, blinded by a
//!   secret pepper, is `idc`;
//! - carries a `nonce` committing to the ephemeral public key that signed this
//!   transaction and to its expiry `exp_date_secs`.
//!
//! The circuit has one public input: the Poseidon hash of all of the above
//! ([`public_inputs_hash`]). The node recomputes it from the authenticator and
//! checks the proof against the ceremony verification key. Aptos L1 recomputes
//! it the same way in `move/sena/sources/keyless.move` when a dispute reaches a
//! keyless transaction, which is why every function here is written to be
//! mirrored there.
//!
//! # What is checked where
//!
//! Compilation (stateless, [`verify`]): the sender is the address the
//! authenticator names, every field element is canonical, the expiry horizon
//! is within policy, the ephemeral key has not expired at the batch timestamp,
//! the ephemeral signature verifies, and the proof verifies.
//!
//! Execution (stateful, [`Instruction::VerifyJwk`](crate::Instruction)): the
//! JWK is one the network currently accepts for that issuer. JWKs rotate, so
//! they live in state under council governance rather than in code.
//!
//! # Compatibility
//!
//! Every hash in this module was checked against aptos-core's own
//! implementation (`types/src/keyless`, at the commit the Move framework is
//! pinned to), including Aptos's sample proof, which verifies here under the
//! devnet verification key. Wallets can therefore use any prover that serves
//! the Aptos Keyless circuit.

use std::sync::{Arc, LazyLock};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sena_primitives::serde_hex::{bytes_128, bytes_32, bytes_64, opt_bytes_32};
use sena_primitives::{Hash256, L2Address};
use serde::{Deserialize, Serialize};

use crate::poseidon;

/// Circuit limits, fixed by `circuit-v1.0.1`. Changing any of them changes
/// every hash below, and so every keyless address.
pub mod limits {
    /// Longest `aud` value the circuit accepts.
    pub const MAX_AUD_VAL_BYTES: usize = 120;
    /// Longest name of the user-id claim (`sub`, `email`).
    pub const MAX_UID_KEY_BYTES: usize = 30;
    /// Longest value of the user-id claim.
    pub const MAX_UID_VAL_BYTES: usize = 330;
    /// Longest `iss` value.
    pub const MAX_ISS_VAL_BYTES: usize = 120;
    /// Longest revealed extra JWT field.
    pub const MAX_EXTRA_FIELD_BYTES: usize = 350;
    /// Longest base64url JWT header, including the trailing `.`.
    pub const MAX_JWT_HEADER_B64_BYTES: usize = 300;
    /// Room for the committed ephemeral public key: three 31-byte scalars.
    pub const MAX_COMMITTED_EPK_BYTES: usize = 93;
    /// RSA modulus size the circuit verifies (RSA-2048).
    pub const RSA_MODULUS_BYTES: usize = 256;
    /// Bytes packed into one field element.
    pub const BYTES_PER_SCALAR: usize = 31;
    /// Length of a pepper.
    pub const PEPPER_BYTES: usize = 31;
}

use limits::{BYTES_PER_SCALAR, MAX_COMMITTED_EPK_BYTES};

/// Why a keyless authorisation was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum KeylessError {
    /// The network was configured without keyless accounts.
    #[error("keyless accounts are not enabled on this network")]
    Disabled,
    /// The sender is not the address the authenticator's identity derives.
    #[error("the keyless identity does not derive the sender's address")]
    WrongSender,
    /// A 32-byte field element was not the canonical encoding of a scalar.
    #[error("{0} is not a canonical BN254 scalar")]
    NonCanonicalScalar(&'static str),
    /// An input is longer than the circuit admits.
    #[error("{field} is {len} bytes; the circuit admits at most {max}")]
    TooLong {
        /// Which input.
        field: &'static str,
        /// Its length.
        len: usize,
        /// The circuit's limit.
        max: usize,
    },
    /// The ephemeral key's expiry horizon exceeds the network's policy.
    #[error("expiry horizon of {horizon}s exceeds the network maximum of {max}s")]
    HorizonTooLong {
        /// The horizon the proof was made for.
        horizon: u64,
        /// The network's limit.
        max: u64,
    },
    /// The ephemeral key had expired at the batch timestamp.
    #[error("the ephemeral key expired at {expiry}, before the batch time {now}")]
    Expired {
        /// When the ephemeral key expired.
        expiry: u64,
        /// The batch timestamp.
        now: u64,
    },
    /// The ephemeral public key is not a valid, non-weak Ed25519 key.
    #[error("malformed ephemeral public key")]
    MalformedEphemeralKey,
    /// The ephemeral signature did not verify.
    #[error("the ephemeral signature does not verify")]
    BadEphemeralSignature,
    /// The proof bytes are not three valid, in-subgroup curve points.
    #[error("malformed Groth16 proof")]
    MalformedProof,
    /// The proof does not verify against the public inputs.
    #[error("the zero-knowledge proof does not verify")]
    InvalidProof,
    /// A JWK modulus was not the size the circuit verifies.
    #[error("RSA modulus must be {expected} bytes, got {got}")]
    BadModulus {
        /// Required length.
        expected: usize,
        /// Supplied length.
        got: usize,
    },
}

// --- Field packing -----------------------------------------------------------

/// Packs up to 31 bytes, little-endian, into one field element.
fn pack_one(chunk: &[u8]) -> Fr {
    debug_assert!(chunk.len() <= BYTES_PER_SCALAR);
    Fr::from_le_bytes_mod_order(chunk)
}

/// Zero-pads `bytes` to `max`, packs 31 bytes per scalar, and appends the
/// original length as a final scalar — the circuit's string encoding.
fn pad_and_pack_with_len(
    field: &'static str,
    bytes: &[u8],
    max: usize,
) -> Result<Vec<Fr>, KeylessError> {
    if bytes.len() > max {
        return Err(KeylessError::TooLong {
            field,
            len: bytes.len(),
            max,
        });
    }
    let mut padded = bytes.to_vec();
    padded.resize(max, 0);
    let mut scalars: Vec<Fr> = padded.chunks(BYTES_PER_SCALAR).map(pack_one).collect();
    scalars.push(Fr::from(bytes.len() as u64));
    Ok(scalars)
}

fn hash_scalars(scalars: &[Fr]) -> Fr {
    poseidon::hash(scalars).expect("every packing here stays within 16 scalars")
}

/// Hashes a string the way the circuit hashes its string inputs.
///
/// # Errors
///
/// Returns [`KeylessError::TooLong`] if `s` exceeds `max` bytes.
pub fn pad_and_hash_string(field: &'static str, s: &str, max: usize) -> Result<Fr, KeylessError> {
    Ok(hash_scalars(&pad_and_pack_with_len(
        field,
        s.as_bytes(),
        max,
    )?))
}

/// Encodes a scalar as the 32 little-endian bytes the authenticator carries.
///
/// # Panics
///
/// Does not panic: a BN254 scalar always serialises to 32 bytes.
#[must_use]
pub fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    fr.into_bigint()
        .to_bytes_le()
        .try_into()
        .expect("a BN254 scalar is 32 bytes")
}

/// Decodes a scalar, refusing any encoding of a value at or above the modulus.
///
/// Reducing instead would give one scalar two encodings — and Aptos L1, whose
/// deserialiser rejects them, would disagree with the node about which
/// transactions are valid.
///
/// # Errors
///
/// Returns [`KeylessError::NonCanonicalScalar`] naming `field`.
pub fn fr_from_bytes(field: &'static str, bytes: &[u8; 32]) -> Result<Fr, KeylessError> {
    let fr = Fr::from_le_bytes_mod_order(bytes);
    if fr_to_bytes(&fr) == *bytes {
        Ok(fr)
    } else {
        Err(KeylessError::NonCanonicalScalar(field))
    }
}

// --- Client-side derivations -------------------------------------------------

/// The issuer hash a keyless address commits to.
///
/// # Errors
///
/// Returns [`KeylessError::TooLong`] for an over-long issuer.
pub fn iss_hash(iss: &str) -> Result<[u8; 32], KeylessError> {
    Ok(fr_to_bytes(&pad_and_hash_string(
        "iss",
        iss,
        limits::MAX_ISS_VAL_BYTES,
    )?))
}

/// The identity commitment: `Poseidon(pepper, H(aud), H(uid_val), H(uid_key))`.
///
/// `uid_key` is the claim that identifies the user — normally `"sub"`.
///
/// # Errors
///
/// Returns [`KeylessError::TooLong`] if any input exceeds the circuit's limit.
pub fn id_commitment(
    pepper: &[u8; limits::PEPPER_BYTES],
    aud: &str,
    uid_key: &str,
    uid_val: &str,
) -> Result<[u8; 32], KeylessError> {
    let aud_hash = pad_and_hash_string("aud", aud, limits::MAX_AUD_VAL_BYTES)?;
    let uid_key_hash = pad_and_hash_string("uid_key", uid_key, limits::MAX_UID_KEY_BYTES)?;
    let uid_val_hash = pad_and_hash_string("uid_val", uid_val, limits::MAX_UID_VAL_BYTES)?;
    let idc = hash_scalars(&[pack_one(pepper), aud_hash, uid_val_hash, uid_key_hash]);
    Ok(fr_to_bytes(&idc))
}

/// The address of the keyless account for an issuer and user.
///
/// # Errors
///
/// Returns [`KeylessError::TooLong`] if any input exceeds the circuit's limit.
pub fn derive_address(
    iss: &str,
    pepper: &[u8; limits::PEPPER_BYTES],
    aud: &str,
    uid_key: &str,
    uid_val: &str,
) -> Result<L2Address, KeylessError> {
    Ok(L2Address::derive_keyless(
        &iss_hash(iss)?,
        &id_commitment(pepper, aud, uid_key, uid_val)?,
    ))
}

/// The hash of an RSA-2048 JWK, from its big-endian modulus.
///
/// The circuit consumes the modulus as little-endian 64-bit limbs, three to a
/// scalar, so the bytes are reversed and packed 24 at a time.
///
/// # Errors
///
/// Returns [`KeylessError::BadModulus`] unless the modulus is 256 bytes.
pub fn rsa_jwk_hash(modulus_be: &[u8]) -> Result<[u8; 32], KeylessError> {
    if modulus_be.len() != limits::RSA_MODULUS_BYTES {
        return Err(KeylessError::BadModulus {
            expected: limits::RSA_MODULUS_BYTES,
            got: modulus_be.len(),
        });
    }
    let mut le = modulus_be.to_vec();
    le.reverse();
    let mut scalars: Vec<Fr> = le.chunks(24).map(Fr::from_le_bytes_mod_order).collect();
    scalars.push(Fr::from(limits::RSA_MODULUS_BYTES as u64));
    Ok(fr_to_bytes(&hash_scalars(&scalars)))
}

/// The hash of a JWK given as its base64url `n` member.
///
/// # Errors
///
/// Returns [`KeylessError::BadModulus`] if `n` is not base64url or not 2048 bits.
pub fn rsa_jwk_hash_b64(n: &str) -> Result<[u8; 32], KeylessError> {
    let modulus = URL_SAFE_NO_PAD
        .decode(n)
        .map_err(|_| KeylessError::BadModulus {
            expected: limits::RSA_MODULUS_BYTES,
            got: 0,
        })?;
    rsa_jwk_hash(&modulus)
}

/// The hash of a decoded JWT header, as the circuit sees it: base64url, with
/// the `.` separator appended.
///
/// # Errors
///
/// Returns [`KeylessError::TooLong`] for an over-long header.
pub fn jwt_header_hash(header_json: &str) -> Result<[u8; 32], KeylessError> {
    let b64 = format!("{}.", URL_SAFE_NO_PAD.encode(header_json));
    Ok(fr_to_bytes(&pad_and_hash_string(
        "jwt_header",
        &b64,
        limits::MAX_JWT_HEADER_B64_BYTES,
    )?))
}

/// The hash of a revealed extra JWT field, such as `"family_name":"Doe",`.
///
/// # Errors
///
/// Returns [`KeylessError::TooLong`] for an over-long field.
pub fn extra_field_hash(extra_field: &str) -> Result<[u8; 32], KeylessError> {
    Ok(fr_to_bytes(&pad_and_hash_string(
        "extra_field",
        extra_field,
        limits::MAX_EXTRA_FIELD_BYTES,
    )?))
}

/// The ephemeral public key as the circuit commits to it: its Aptos BCS
/// encoding (`0x00` for Ed25519, `0x20` for the length, then the key), padded
/// to 93 bytes, packed, with the length appended.
///
/// # Panics
///
/// Does not panic: 34 bytes always fit the 93-byte limit.
#[must_use]
pub fn epk_scalars(ephemeral_public_key: &[u8; 32]) -> Vec<Fr> {
    let mut bcs = Vec::with_capacity(34);
    bcs.push(0x00);
    bcs.push(0x20);
    bcs.extend_from_slice(ephemeral_public_key);
    pad_and_pack_with_len("epk", &bcs, MAX_COMMITTED_EPK_BYTES)
        .expect("a 34-byte key fits in 93 bytes")
}

/// The OAuth `nonce` a wallet asks the identity provider to embed, committing
/// to the ephemeral key and its expiry. Decimal, as the circuit expects.
#[must_use]
pub fn oauth_nonce(
    ephemeral_public_key: &[u8; 32],
    exp_date_secs: u64,
    epk_blinder: &[u8; limits::BYTES_PER_SCALAR],
) -> String {
    let mut scalars = epk_scalars(ephemeral_public_key);
    scalars.push(Fr::from(exp_date_secs));
    scalars.push(pack_one(epk_blinder));
    hash_scalars(&scalars).to_string()
}

/// `H(" ")` padded to the extra-field limit: what the circuit hashes when no
/// extra field is revealed.
static EMPTY_EXTRA_FIELD_HASH: LazyLock<Fr> = LazyLock::new(|| {
    pad_and_hash_string("extra_field", " ", limits::MAX_EXTRA_FIELD_BYTES)
        .expect("a one-byte string fits")
});

/// `H("")` padded to the `aud` limit: the override-`aud` slot, which SENA
/// never uses (Aptos uses it for account recovery).
static EMPTY_OVERRIDE_AUD_HASH: LazyLock<Fr> = LazyLock::new(|| {
    pad_and_hash_string("override_aud", "", limits::MAX_AUD_VAL_BYTES)
        .expect("an empty string fits")
});

// --- The authenticator -------------------------------------------------------

/// A keyless authorisation, as carried by a transaction.
///
/// Field elements travel as 32 little-endian bytes and must be canonical.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeylessSignature {
    /// Poseidon hash of the issuer, from [`iss_hash`].
    #[serde(with = "bytes_32")]
    pub iss_hash: [u8; 32],
    /// The identity commitment, from [`id_commitment`].
    #[serde(with = "bytes_32")]
    pub idc: [u8; 32],
    /// The ephemeral Ed25519 public key committed to in the JWT `nonce`.
    #[serde(with = "bytes_32")]
    pub ephemeral_public_key: [u8; 32],
    /// The ephemeral key's signature over the transaction's signing digest.
    #[serde(with = "bytes_64")]
    pub ephemeral_signature: [u8; 64],
    /// When the ephemeral key expires (Unix seconds), as committed in the nonce.
    pub exp_date_secs: u64,
    /// The horizon the proof enforces: `exp_date_secs < iat + exp_horizon_secs`.
    pub exp_horizon_secs: u64,
    /// Hash of the JWT header, from [`jwt_header_hash`].
    #[serde(with = "bytes_32")]
    pub jwt_header_hash: [u8; 32],
    /// Hash of the signing JWK, from [`rsa_jwk_hash`].
    #[serde(with = "bytes_32")]
    pub jwk_hash: [u8; 32],
    /// Hash of a revealed extra field, if the proof reveals one.
    #[serde(with = "opt_bytes_32", default)]
    pub extra_field_hash: Option<[u8; 32]>,
    /// The Groth16 proof: A (G1, 32 bytes), B (G2, 64 bytes), C (G1, 32 bytes),
    /// each arkworks-compressed.
    #[serde(with = "bytes_128")]
    pub proof: [u8; 128],
}

impl KeylessSignature {
    /// The address this authorisation controls.
    #[must_use]
    pub fn address(&self) -> L2Address {
        L2Address::derive_keyless(&self.iss_hash, &self.idc)
    }
}

/// Computes the circuit's single public input from an authenticator.
///
/// The order and encoding are fixed by the circuit; see aptos-core
/// `types/src/keyless/bn254_circom.rs::hash_public_inputs`.
///
/// # Errors
///
/// Returns [`KeylessError::NonCanonicalScalar`] if any field element is not
/// canonically encoded.
pub fn public_inputs_hash(sig: &KeylessSignature) -> Result<Fr, KeylessError> {
    let (has_extra_field, extra_field_hash) = match &sig.extra_field_hash {
        Some(h) => (Fr::from(1u64), fr_from_bytes("extra_field_hash", h)?),
        None => (Fr::from(0u64), *EMPTY_EXTRA_FIELD_HASH),
    };

    let mut scalars = epk_scalars(&sig.ephemeral_public_key);
    scalars.push(fr_from_bytes("idc", &sig.idc)?);
    scalars.push(Fr::from(sig.exp_date_secs));
    scalars.push(Fr::from(sig.exp_horizon_secs));
    scalars.push(fr_from_bytes("iss_hash", &sig.iss_hash)?);
    scalars.push(has_extra_field);
    scalars.push(extra_field_hash);
    scalars.push(fr_from_bytes("jwt_header_hash", &sig.jwt_header_hash)?);
    scalars.push(fr_from_bytes("jwk_hash", &sig.jwk_hash)?);
    scalars.push(*EMPTY_OVERRIDE_AUD_HASH);
    scalars.push(Fr::from(0u64)); // use_override_aud
    Ok(hash_scalars(&scalars))
}

/// Parses a compressed proof, with subgroup checks.
///
/// # Errors
///
/// Returns [`KeylessError::MalformedProof`] if any point is invalid.
pub fn parse_proof(bytes: &[u8; 128]) -> Result<Proof<Bn254>, KeylessError> {
    let a =
        G1Affine::deserialize_compressed(&bytes[..32]).map_err(|_| KeylessError::MalformedProof)?;
    let b = G2Affine::deserialize_compressed(&bytes[32..96])
        .map_err(|_| KeylessError::MalformedProof)?;
    let c =
        G1Affine::deserialize_compressed(&bytes[96..]).map_err(|_| KeylessError::MalformedProof)?;
    Ok(Proof { a, b, c })
}

// --- Network configuration ---------------------------------------------------

/// A network's keyless parameters.
///
/// Part of the chain's identity: the Aptos L1 contracts are initialised with
/// the same verification key, and the two must never differ.
#[derive(Clone, Debug)]
pub struct KeylessConfig {
    /// A stable name for the parameter set.
    pub name: &'static str,
    /// The Groth16 verification key of the keyless circuit.
    pub vk: PreparedVerifyingKey<Bn254>,
    /// The longest expiry horizon a proof may be made for.
    pub max_exp_horizon_secs: u64,
}

/// Parses a snarkjs-style decimal coordinate.
fn fq(s: &str) -> Fq {
    s.parse().expect("a decimal BN254 base-field element")
}

fn g1(x: &str, y: &str) -> G1Affine {
    let p = G1Affine::new(fq(x), fq(y));
    assert!(p.is_in_correct_subgroup_assuming_on_curve());
    p
}

fn g2(x: [&str; 2], y: [&str; 2]) -> G2Affine {
    let p = G2Affine::new(Fq2::new(fq(x[0]), fq(x[1])), Fq2::new(fq(y[0]), fq(y[1])));
    assert!(p.is_in_correct_subgroup_assuming_on_curve());
    p
}

/// Alpha, beta and gamma are shared by every Aptos Keyless setup to date.
fn aptos_alpha_beta_gamma() -> (G1Affine, G2Affine, G2Affine) {
    (
        g1(
            "20491192805390485299153009773594534940189261866228447918068658471970481763042",
            "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        ),
        g2(
            [
                "6375614351688725206403948262868962793625744043794305715222011528459656738731",
                "4252822878758300859123897981450591353533073413197771768651442665752259397132",
            ],
            [
                "10505242626370262277552901082094356697409835680220590971873171140371331206856",
                "21847035105528745403288232691147584728191162732299865338377159692350059136679",
            ],
        ),
        g2(
            [
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            ],
            [
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            ],
        ),
    )
}

/// The Aptos mainnet keyless setup: the January 2025 multi-party ceremony for
/// circuit `v1.0.1`.
///
/// Source: `aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025`,
/// `verification_key.json` (SHA-256 `2ed0ac4f…c249fa`). Aptos's `vk-diff` tool
/// documents it as the key deployed on Aptos mainnet.
static APTOS_MAINNET: LazyLock<Arc<KeylessConfig>> = LazyLock::new(|| {
    let (alpha_g1, beta_g2, gamma_g2) = aptos_alpha_beta_gamma();
    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2: g2(
            [
                "17162062080650451261943733387263844607642798219395293362030080188706675820209",
                "7207443324687706445558765100094213065454271490816675926314200508330750349345",
            ],
            [
                "15470523348154855835539041785993823311983047881301276140184021698308326650242",
                "19832950273961457994090486607255894099155589946051539771703725139678445562680",
            ],
        ),
        gamma_abc_g1: vec![
            g1(
                "12058717740710411878050078966381695054977836914208917805525163973755155129185",
                "1327570937043852822321112267886510566303372973447701163228257432628576947785",
            ),
            g1(
                "1678946948893294049678945266983034375621988749256524114442575653286687844658",
                "16084340961022335811703913914889749159145715327231972004027826836229434497404",
            ),
        ],
    };
    Arc::new(KeylessConfig {
        name: "aptos-keyless-mainnet-2025-01",
        vk: PreparedVerifyingKey::from(vk),
        // Aptos's own policy: about 115 days.
        max_exp_horizon_secs: 10_000_000,
    })
});

/// The Aptos *devnet* test setup (`aptos-labs/devnet-groth16-keys`, commit
/// `02e5675f`).
///
/// **Insecure: a single-party setup whose toxic waste is not known to have
/// been destroyed.** It exists because Aptos publishes a real circuit proof
/// for it, which is the only end-to-end test vector available. Never use it
/// for a network that holds value.
static APTOS_DEVNET_INSECURE: LazyLock<Arc<KeylessConfig>> = LazyLock::new(|| {
    let (alpha_g1, beta_g2, gamma_g2) = aptos_alpha_beta_gamma();
    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2: g2(
            [
                "6309950375468367434079888575625734658722834850554198467265341412057133512289",
                "290788916745604303732014379515714703987358626088033030814233237684691015915",
            ],
            [
                "18062633083579661887564610476476551517623934510295133920710347041696656037149",
                "18531177357310703535722548657431805690263733685063962985389260695754645724386",
            ],
        ),
        gamma_abc_g1: vec![
            g1(
                "3314139460766150258181182511839382093976747705712051605578952681462625768062",
                "15177929890957116336235565528373348502554233971408496072173139426537995658198",
            ),
            g1(
                "11040819149070528816396253292991080175919431363817777522273571096667537087166",
                "13976660124609527451731647657081915019685631850685519260597009755390746148997",
            ),
        ],
    };
    Arc::new(KeylessConfig {
        name: "aptos-keyless-devnet-insecure",
        vk: PreparedVerifyingKey::from(vk),
        // Aptos's sample proof uses a horizon of 999,999,999,999 seconds.
        max_exp_horizon_secs: 1_000_000_000_000,
    })
});

impl KeylessConfig {
    /// The Aptos mainnet ceremony parameters. Use this for any real network.
    #[must_use]
    pub fn aptos_mainnet() -> Arc<Self> {
        Arc::clone(&APTOS_MAINNET)
    }

    /// The Aptos *devnet* test parameters (`aptos-labs/devnet-groth16-keys`).
    ///
    /// **Insecure**: a single-party setup. It exists because Aptos publishes a
    /// real circuit proof for it, the only end-to-end test vector available.
    #[must_use]
    pub fn aptos_devnet_insecure() -> Arc<Self> {
        Arc::clone(&APTOS_DEVNET_INSECURE)
    }

    /// Looks a parameter set up by name.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Arc<Self>> {
        [Self::aptos_mainnet(), Self::aptos_devnet_insecure()]
            .into_iter()
            .find(|c| c.name == name)
    }

    /// The id `sena::keyless` on Aptos L1 gives this parameter set; 0 means
    /// keyless is disabled.
    #[must_use]
    pub fn l1_setup_id(config: Option<&Self>) -> u8 {
        match config.map(|c| c.name) {
            None => 0,
            Some(n) if n == APTOS_MAINNET.name => 1,
            Some(_) => 2,
        }
    }
}

/// Everything a keyless check needs that is not in the transaction.
#[derive(Clone, Debug)]
pub struct KeylessContext<'a> {
    /// The network's parameters, or `None` if keyless is disabled.
    pub config: Option<&'a KeylessConfig>,
    /// The batch timestamp, against which ephemeral-key expiry is judged.
    pub now: u64,
}

/// Verifies a keyless authorisation of `digest` on behalf of `sender`.
///
/// Stateless. The JWK is checked separately, against state, by
/// [`Instruction::VerifyJwk`](crate::Instruction).
///
/// # Errors
///
/// Returns the first [`KeylessError`] encountered, checking cheap conditions
/// before the pairing.
pub fn verify(
    sig: &KeylessSignature,
    sender: &L2Address,
    digest: &Hash256,
    ctx: &KeylessContext<'_>,
) -> Result<(), KeylessError> {
    let config = ctx.config.ok_or(KeylessError::Disabled)?;
    if sig.address() != *sender {
        return Err(KeylessError::WrongSender);
    }
    if sig.exp_horizon_secs > config.max_exp_horizon_secs {
        return Err(KeylessError::HorizonTooLong {
            horizon: sig.exp_horizon_secs,
            max: config.max_exp_horizon_secs,
        });
    }
    if ctx.now >= sig.exp_date_secs {
        return Err(KeylessError::Expired {
            expiry: sig.exp_date_secs,
            now: ctx.now,
        });
    }
    crate::transaction::verify_ed25519_strict(
        &sig.ephemeral_public_key,
        &sig.ephemeral_signature,
        digest,
    )
    .map_err(|e| match e {
        crate::AuthError::MalformedKey => KeylessError::MalformedEphemeralKey,
        _ => KeylessError::BadEphemeralSignature,
    })?;

    let public_input = public_inputs_hash(sig)?;
    let proof = parse_proof(&sig.proof)?;
    match Groth16::<Bn254>::verify_proof(&config.vk, &proof, &[public_input]) {
        Ok(true) => Ok(()),
        _ => Err(KeylessError::InvalidProof),
    }
}

/// Aptos's published keyless test vector.
///
/// aptos-core ships one real proof over the Aptos Keyless circuit
/// (`types/src/keyless/circuit_testcases.rs`), made under the **insecure**
/// devnet setup for a sample JWT signed by a throwaway test RSA key. It is the
/// only end-to-end vector in existence, so it is exposed here for tests and
/// examples. Everything in it is public; nothing here controls real funds.
pub mod aptos_sample {
    use super::{
        extra_field_hash, id_commitment, iss_hash, jwt_header_hash, rsa_jwk_hash_b64,
        KeylessSignature,
    };

    /// The sample issuer.
    pub const ISS: &str = "test.oidc.provider";
    /// The sample application (`aud`).
    pub const AUD: &str = "407408718192.apps.googleusercontent.com";
    /// The user-id claim.
    pub const UID_KEY: &str = "sub";
    /// The sample user.
    pub const UID_VAL: &str = "113990307082899718775";
    /// The decoded JWT header.
    pub const JWT_HEADER_JSON: &str = r#"{"alg":"RS256","typ":"JWT","kid":"test-rsa"}"#;
    /// The revealed extra field.
    pub const EXTRA_FIELD: &str = r#""family_name":"Straka","#;
    /// The test RSA JWK's modulus (`n`), base64url.
    pub const JWK_N: &str = "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw";
    /// The ephemeral secret key (Ed25519 seed), hex.
    pub const EPHEMERAL_SECRET_KEY: &str =
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7";
    /// The ephemeral public key, hex.
    pub const EPHEMERAL_PUBLIC_KEY: &str =
        "20fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a144";
    /// The ephemeral key's expiry, as committed in the nonce.
    pub const EXP_DATE_SECS: u64 = 111_111_111_111;
    /// The proof's expiry horizon.
    pub const EXP_HORIZON_SECS: u64 = 999_999_999_999;
    /// The proof (A ‖ B ‖ C, arkworks-compressed), hex.
    pub const PROOF: &str = concat!(
        "3304cc0defd488d770af0439480ec24c8473b30dbcbfad9fdf99ca62256bd908",
        "2f432b9459375ed2032bcb1ff3ccc1dd5d05a752d6956d2bb003f4e3b42d0b24",
        "2cf4ab4d3dc8dc700ede17bbfeaddedd42033691e3d85ff8d6621663cb2e779a",
        "d44ee2772f4b48fdb0dbd8d870d3fb4401cd3a28fbdde535e9c57bac9a263f9c",
    );

    /// The sample pepper: `Pepper::from_number(76)`.
    #[must_use]
    pub fn pepper() -> [u8; 31] {
        let mut p = [0u8; 31];
        p[0] = 76;
        p
    }

    /// The sample authenticator, with the ephemeral signature left zero for
    /// the caller to fill in over its own transaction.
    ///
    /// # Panics
    ///
    /// Does not panic: every input is a fixed, valid constant.
    #[must_use]
    pub fn signature() -> KeylessSignature {
        let decode32 = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
        KeylessSignature {
            iss_hash: iss_hash(ISS).unwrap(),
            idc: id_commitment(&pepper(), AUD, UID_KEY, UID_VAL).unwrap(),
            ephemeral_public_key: decode32(EPHEMERAL_PUBLIC_KEY),
            ephemeral_signature: [0; 64],
            exp_date_secs: EXP_DATE_SECS,
            exp_horizon_secs: EXP_HORIZON_SECS,
            jwt_header_hash: jwt_header_hash(JWT_HEADER_JSON).unwrap(),
            jwk_hash: rsa_jwk_hash_b64(JWK_N).unwrap(),
            extra_field_hash: Some(extra_field_hash(EXTRA_FIELD).unwrap()),
            proof: hex::decode(PROOF).unwrap().try_into().unwrap(),
        }
    }

    /// The ephemeral secret key as 32 bytes.
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[must_use]
    pub fn ephemeral_secret_key() -> [u8; 32] {
        hex::decode(EPHEMERAL_SECRET_KEY)
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn fr(s: &str) -> Fr {
        Fr::from_str(s).unwrap()
    }

    #[test]
    fn empty_field_hashes_match_aptos() {
        assert_eq!(
            *EMPTY_EXTRA_FIELD_HASH,
            fr("8441624714246672702469557419929302030072955765775944993548127422079350103481")
        );
        assert_eq!(
            *EMPTY_OVERRIDE_AUD_HASH,
            fr("14655542659562014735865511769057053982292279840403315552050801315682099828156")
        );
    }

    #[test]
    fn scalars_must_be_canonical() {
        // The modulus itself, little-endian.
        let p = fr_to_bytes(&(Fr::from(0u64) - Fr::from(1u64)));
        let mut over = p;
        over[0] = over[0].wrapping_add(1);
        assert_eq!(
            fr_from_bytes("x", &over),
            Err(KeylessError::NonCanonicalScalar("x"))
        );
        assert!(fr_from_bytes("x", &p).is_ok());
    }

    #[test]
    fn over_long_inputs_are_refused() {
        let long = "x".repeat(limits::MAX_ISS_VAL_BYTES + 1);
        assert!(matches!(
            iss_hash(&long),
            Err(KeylessError::TooLong { field: "iss", .. })
        ));
        assert!(matches!(
            rsa_jwk_hash(&[1; 255]),
            Err(KeylessError::BadModulus { got: 255, .. })
        ));
    }

    #[test]
    fn configs_are_found_by_name() {
        assert_eq!(
            KeylessConfig::by_name("aptos-keyless-mainnet-2025-01")
                .unwrap()
                .name,
            "aptos-keyless-mainnet-2025-01"
        );
        assert!(KeylessConfig::by_name("made-up").is_none());
    }
}
