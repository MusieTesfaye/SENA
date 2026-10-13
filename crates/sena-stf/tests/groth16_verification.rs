//! Integration tests for On-Chain Groth16 / BN254 ZK Verifier (REQ-AUTH-003, REQ-AUTH-004).

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::VerifyingKey;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, Hash256, L2Address};
use sena_stf::groth16::{
    derive_keyless_public_inputs, hash_to_fr, Bn254Groth16Verifier, Bn254Proof,
};
use sena_stf::keyless::{epk_commitment, JwtClaims, KeylessAuth, KeylessError, KeylessVerifier};
use sena_stf::transaction::{AuthError, Authenticator, Payload, Transaction};

/// Constructs a valid Groth16 `VerifyingKey` and `Proof` over BN254 for a 3-public-input statement.
///
/// Under Groth16:
/// ```text
/// e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)
/// ```
/// where `L = gamma_abc[0] + x_1 * gamma_abc[1] + x_2 * gamma_abc[2] + x_3 * gamma_abc[3]`.
///
/// By constructing:
/// ```text
/// A = alpha, B = beta, C = 0
/// ```
/// and setting:
/// ```text
/// gamma_abc[0] = - (x_1 * gamma_abc[1] + x_2 * gamma_abc[2] + x_3 * gamma_abc[3])
/// ```
/// we have `L = 0`, so `e(L, gamma) = 1` and `e(C, delta) = 1`.
/// Thus `e(A, B) = e(alpha, beta)`, satisfying the pairing check equation.
fn fr_u64(val: u64) -> Fr {
    Fr::from_be_bytes_mod_order(&val.to_be_bytes())
}

fn setup_mock_bn254_keypair_and_proof(x1: Fr, x2: Fr, x3: Fr) -> (VerifyingKey<Bn254>, Bn254Proof) {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let alpha: G1Affine = (g1 * fr_u64(11)).into();
    let beta: G2Affine = (g2 * fr_u64(13)).into();
    let gamma: G2Affine = (g2 * fr_u64(17)).into();
    let delta: G2Affine = (g2 * fr_u64(19)).into();

    let ic1: G1Affine = (g1 * fr_u64(23)).into();
    let ic2: G1Affine = (g1 * fr_u64(29)).into();
    let ic3: G1Affine = (g1 * fr_u64(31)).into();

    // L_rest = x1 * ic1 + x2 * ic2 + x3 * ic3
    let l_rest: G1Projective = ic1 * x1 + ic2 * x2 + ic3 * x3;
    // ic0 = - l_rest, so that ic0 + l_rest = 0
    let ic0: G1Affine = (-l_rest).into();

    let vk = VerifyingKey::<Bn254> {
        alpha_g1: alpha,
        beta_g2: beta,
        gamma_g2: gamma,
        delta_g2: delta,
        gamma_abc_g1: vec![ic0, ic1, ic2, ic3],
    };

    let proof = Bn254Proof {
        a: alpha,
        b: beta,
        c: G1Affine::zero(),
    };

    (vk, proof)
}

#[test]
fn test_bn254_proof_bytes_serialization_and_validation() {
    let (_vk, proof) = setup_mock_bn254_keypair_and_proof(fr_u64(101), fr_u64(202), fr_u64(303));

    // 1. Compressed serialization is exactly 128 bytes
    let compressed_bytes = proof.to_compressed_bytes();
    assert_eq!(compressed_bytes.len(), 128);

    // 2. Roundtrip from compressed bytes
    let deserialized =
        Bn254Proof::from_bytes(&compressed_bytes).expect("deserialization must succeed");
    assert_eq!(proof, deserialized);

    // 3. Rejects truncated bytes
    assert!(matches!(
        Bn254Proof::from_bytes(&compressed_bytes[..64]),
        Err(KeylessError::MalformedProof(_))
    ));

    // 4. Rejects corrupted point bytes (e.g. elements exceeding field modulus)
    let invalid_points = vec![0xFF; 128];
    assert!(Bn254Proof::from_bytes(&invalid_points).is_err());
}

#[test]
fn test_derive_keyless_public_inputs_determinism() {
    let epk = [15u8; 32];
    let expiry = 2_000_000u64;
    let blinder = b"client_blinder_99";
    let pepper = b"user_pepper_42";

    let claims = JwtClaims {
        iss: "https://accounts.google.com".to_owned(),
        aud: "sena_mobile_wallet".to_owned(),
        sub: "google-oauth2|10928374".to_owned(),
        exp: expiry,
        iat: expiry - 3600,
        nonce: epk_commitment(&epk, expiry, blinder),
    };

    let auth = KeylessAuth {
        token: "dummy.jwt.token",
        ephemeral_public_key: &epk,
        ephemeral_expiry: expiry,
        blinder,
        pepper,
        proof: &[],
    };

    let inputs = derive_keyless_public_inputs(&auth, &claims);
    assert_eq!(inputs.len(), 3);

    // Altering pepper alters x2 (address)
    let auth_diff_pepper = KeylessAuth {
        pepper: b"other_pepper",
        ..auth
    };
    let inputs_diff_pepper = derive_keyless_public_inputs(&auth_diff_pepper, &claims);
    assert_eq!(inputs[0], inputs_diff_pepper[0]);
    assert_ne!(inputs[1], inputs_diff_pepper[1]);
    assert_eq!(inputs[2], inputs_diff_pepper[2]);

    // Altering expiry alters x3
    let mut claims_diff_exp = claims.clone();
    claims_diff_exp.exp = expiry + 7200;
    let inputs_diff_exp = derive_keyless_public_inputs(&auth, &claims_diff_exp);
    assert_ne!(inputs[2], inputs_diff_exp[2]);
}

#[test]
fn test_groth16_bn254_verifier_soundness() {
    let x1 = hash_to_fr(&Hash256::digest(b"epk_commitment"));
    let x2 = hash_to_fr(&Hash256::digest(b"account_address"));
    let x3 = hash_to_fr(&Hash256::digest(b"google_issuer_and_exp"));

    let (vk, proof) = setup_mock_bn254_keypair_and_proof(x1, x2, x3);
    let verifier = Bn254Groth16Verifier::new(&vk);

    // 1. Honest verification succeeds
    let valid_inputs = vec![x1, x2, x3];
    assert!(verifier.verify_raw(&proof, &valid_inputs).is_ok());

    // 2. Tampered public input fails (forged epk)
    let forged_x1 = hash_to_fr(&Hash256::digest(b"attacker_epk"));
    let forged_inputs = vec![forged_x1, x2, x3];
    assert_eq!(
        verifier.verify_raw(&proof, &forged_inputs).unwrap_err(),
        KeylessError::InvalidProof
    );

    // 3. Tampered account address fails (stealing account)
    let forged_x2 = hash_to_fr(&Hash256::digest(b"victim_address"));
    let forged_address_inputs = vec![x1, forged_x2, x3];
    assert_eq!(
        verifier
            .verify_raw(&proof, &forged_address_inputs)
            .unwrap_err(),
        KeylessError::InvalidProof
    );

    // 4. Missing / mismatched public input length fails
    assert!(verifier.verify_raw(&proof, &[x1, x2]).is_err());
}

#[test]
fn test_transaction_keyless_authentication_with_groth16() {
    let mut rng = StdRng::seed_from_u64(999);

    // Ephemeral key pair (client)
    let epk_signing_key = SigningKey::generate(&mut rng);
    let epk_verifying_key = epk_signing_key.verifying_key();
    let epk_bytes = epk_verifying_key.to_bytes();

    let sender = L2Address::from_bytes([0x42; 32]);
    let x1 = hash_to_fr(&Hash256::digest(&epk_bytes));
    let x2 = hash_to_fr(&Hash256::digest(sender.as_bytes()));
    let x3 = hash_to_fr(&Hash256::digest(b"google_oidc"));
    let public_inputs = vec![x1, x2, x3];

    let (vk, proof) = setup_mock_bn254_keypair_and_proof(x1, x2, x3);
    let verifier = Bn254Groth16Verifier::new(&vk);
    let proof_bytes = proof.to_compressed_bytes();

    let mut tx = Transaction {
        sender,
        nonce: 0,
        fee_asset: AssetId::NATIVE,
        max_fee: 10_000,
        fee_rate: 1_000_000,
        payload: Payload::Transfer {
            to: L2Address::from_bytes([0x99; 32]),
            asset: AssetId::NATIVE,
            amount: 500,
        },
        authenticator: Authenticator::Keyless {
            ephemeral_public_key: epk_bytes,
            signature: [0u8; 64],
            zk_proof: proof_bytes.clone(),
        },
    };

    // Sign the transaction digest with the ephemeral key
    let sig = epk_signing_key.sign(tx.signing_digest().as_bytes());
    tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: epk_bytes,
        signature: sig.to_bytes(),
        zk_proof: proof_bytes,
    };

    // 1. Verification succeeds with valid signature and valid Groth16 proof
    assert!(tx
        .authenticate_with_groth16(&verifier, &public_inputs)
        .is_ok());

    // 2. Fails if public inputs mismatch (e.g. forged sender)
    let forged_x2 = hash_to_fr(&Hash256::digest(b"other_account"));
    let forged_inputs = vec![x1, forged_x2, x3];
    assert_eq!(
        tx.authenticate_with_groth16(&verifier, &forged_inputs)
            .unwrap_err(),
        AuthError::InvalidZkProof
    );

    // 3. Fails if transaction payload is altered (tampered amount)
    let mut tampered_tx = tx.clone();
    tampered_tx.payload = Payload::Transfer {
        to: L2Address::from_bytes([0x99; 32]),
        asset: AssetId::NATIVE,
        amount: 999_999,
    };
    assert_eq!(
        tampered_tx
            .authenticate_with_groth16(&verifier, &public_inputs)
            .unwrap_err(),
        AuthError::BadSignature
    );

    // 4. Default authenticate() rejects mock proof not matching canonical parameters
    assert_eq!(tx.authenticate().unwrap_err(), AuthError::InvalidZkProof);

    // 5. Default authenticate() rejects non-128-byte proof with KeylessNotImplemented
    let mut incomplete_tx = tx.clone();
    incomplete_tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: epk_bytes,
        signature: sig.to_bytes(),
        zk_proof: vec![0u8; 32],
    };
    assert_eq!(
        incomplete_tx.authenticate().unwrap_err(),
        AuthError::KeylessNotImplemented
    );

    // 6. Default authenticate() accepts valid canonical Groth16 proof
    let canonical_proof = sena_stf::groth16::create_canonical_proof(&epk_bytes, &tx.sender);
    let mut canonical_tx = tx.clone();
    canonical_tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: epk_bytes,
        signature: sig.to_bytes(),
        zk_proof: canonical_proof.to_compressed_bytes(),
    };
    assert!(canonical_tx.authenticate().is_ok());
}

#[test]
fn test_keyless_verifier_trait_impl() {
    let epk = [21u8; 32];
    let expiry = 5_000_000u64;
    let blinder = b"blinder_123";
    let pepper = b"pepper_abc";

    let claims = JwtClaims {
        iss: "https://accounts.google.com".to_owned(),
        aud: "sena_wallet".to_owned(),
        sub: "user_sub_101".to_owned(),
        exp: expiry,
        iat: expiry - 3600,
        nonce: epk_commitment(&epk, expiry, blinder),
    };

    let auth_base = KeylessAuth {
        token: "jwt.token.val",
        ephemeral_public_key: &epk,
        ephemeral_expiry: expiry,
        blinder,
        pepper,
        proof: &[],
    };

    let public_inputs = derive_keyless_public_inputs(&auth_base, &claims);
    let (vk, proof) =
        setup_mock_bn254_keypair_and_proof(public_inputs[0], public_inputs[1], public_inputs[2]);
    let verifier = Bn254Groth16Verifier::new(&vk);
    let proof_bytes = proof.to_compressed_bytes();

    let auth_with_proof = KeylessAuth {
        proof: &proof_bytes,
        ..auth_base
    };

    // 1. Verify via KeylessVerifier trait succeeds
    assert!(verifier.verify(&auth_with_proof, &claims).is_ok());

    // 2. Empty proof fails with MalformedProof
    assert!(matches!(
        verifier.verify(&auth_base, &claims),
        Err(KeylessError::MalformedProof(_))
    ));
}
