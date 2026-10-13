//! Comprehensive tests for the SENA Prover Service and Ceremony Pipeline.

use sena_prover::{load_ceremony_keys, run_ceremony, save_ceremony_keys, KeylessProver};

#[test]
fn test_ceremony_generation_and_disk_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!("sena_ceremony_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);

    // 1. Run Phase 2 Ceremony
    let (pk, vk) = run_ceremony().expect("Ceremony setup failed");

    // 2. Save keys to disk
    let (pk_path, vk_path, json_path) =
        save_ceremony_keys(&temp_dir, &pk, &vk).expect("Failed to save ceremony keys");

    assert!(pk_path.exists(), "Proving key file must exist");
    assert!(vk_path.exists(), "Verifying key file must exist");
    assert!(json_path.exists(), "JSON verifying key must exist");

    // 3. Load keys from disk
    let (_loaded_pk, loaded_vk) =
        load_ceremony_keys(&temp_dir).expect("Failed to load ceremony keys");

    assert_eq!(
        loaded_vk.alpha_g1, vk.alpha_g1,
        "Loaded VK must match generated VK"
    );
    assert_eq!(
        loaded_vk.beta_g2, vk.beta_g2,
        "Loaded VK beta must match generated VK"
    );

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_prover_witness_and_proof_generation() {
    let prover = KeylessProver::initialize_default().expect("Failed to initialize prover");

    // Dummy test JWT for local testing
    let dummy_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InNlbmFfdGVzdF9raWRfMDEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJzZW5hLW1vYmlsZS13YWxsZXQtdjEiLCJzdWIiOiJnb29nbGUtMTA5MjgzNzQiLCJub25jZSI6IjB4MDEiLCJleHAiOjIwMDAwMDAwMDB9.signature_dummy";
    let epk = [42u8; 32];
    let pepper = b"alice_secure_pepper_test";

    let result = prover
        .prove(dummy_jwt, &epk, pepper, 2_000_000_000)
        .expect("Proving failed");

    assert!(result.proof_hex.starts_with("0x"), "Proof must start with 0x");
    // Compressed BN254 Groth16 proof is 128 bytes = 256 hex chars + '0x' = 258 chars
    assert_eq!(
        result.proof_hex.len(),
        258,
        "Compressed BN254 Groth16 proof must be exactly 128 bytes (256 hex characters)"
    );
    assert_eq!(result.public_inputs.len(), 3, "Must have exactly 3 public inputs");
    assert!(result.proving_time_ms >= 0.0, "Proving time must be non-negative");

    let proof_bytes = hex::decode(&result.proof_hex[2..]).expect("Valid hex");
    let is_valid = prover.verify(&proof_bytes, &result.public_inputs_field()).expect("Verification executed");
    println!("Direct prover.verify returned: {}", is_valid);
    assert!(is_valid, "Proof must verify successfully against public inputs");
}

#[test]
fn test_universal_oidc_unified_address_derivation() {
    let prover = KeylessProver::initialize_default().expect("Failed to initialize prover");

    // Unified OIDC token (Microsoft / Discord / custom provider) with aud = "*" (no client_id lock-in)
    let unified_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InNlbmFfdGVzdF9raWRfMDEifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vY29tbW9uL3YyLjAiLCJhdWQiOiIqIiwic3ViIjoibXMtYWRhbS05ODcyMyIsIm5vbmNlIjoiMHgwMSIsImV4cCI6MjAwMDAwMDAwMH0.signature_dummy";
    let epk = [99u8; 32];
    let pepper = b"adam_device_pepper_secret";

    let result = prover
        .prove(unified_jwt, &epk, pepper, 2_000_000_000)
        .expect("Proving unified OIDC must succeed");

    assert!(result.proof_hex.starts_with("0x"));
    assert_eq!(result.proof_hex.len(), 258);
    println!("Unified Address derived: {}", result.address);

    let proof_bytes = hex::decode(&result.proof_hex[2..]).expect("Valid hex");
    let is_valid = prover.verify(&proof_bytes, &result.public_inputs_field()).expect("Verification ok");
    assert!(is_valid, "Unified OIDC proof must verify successfully");
}

#[test]
fn test_celo_odis_social_connect_pipeline() {
    use sena_primitives::Channel;
    use sena_prover::{client_blind_identifier, client_unblind_identifier, OdisService};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_bn254::G1Affine;

    let odis = OdisService::new_default();
    let phone_number = "+1 (415) 555-2671";

    // 1. Client blinds phone number with secret scalar r
    let (blinded, r) = client_blind_identifier(Channel::Phone, phone_number);
    let mut blinded_bytes = Vec::new();
    blinded.serialize_compressed(&mut blinded_bytes).unwrap();

    // 2. Server evaluates blinded point (server learns 0 bits about phone number)
    let evaluated_bytes = odis.evaluate_blinded(&blinded_bytes).expect("ODIS evaluation must succeed");
    let mut cursor = evaluated_bytes.as_slice();
    let evaluated_point = G1Affine::deserialize_compressed(&mut cursor).unwrap();

    // 3. Client unblinds evaluation
    let (obfuscated_id_1, pepper_1) =
        client_unblind_identifier(Channel::Phone, phone_number, &evaluated_point, &r).unwrap();

    // 4. Repeat with independent random blinder r_2
    let (blinded_2, r2) = client_blind_identifier(Channel::Phone, phone_number);
    assert_ne!(blinded, blinded_2, "Blinded points must be unlinkable");

    let mut blinded_bytes_2 = Vec::new();
    blinded_2.serialize_compressed(&mut blinded_bytes_2).unwrap();
    let evaluated_bytes_2 = odis.evaluate_blinded(&blinded_bytes_2).unwrap();
    let mut cursor_2 = evaluated_bytes_2.as_slice();
    let evaluated_point_2 = G1Affine::deserialize_compressed(&mut cursor_2).unwrap();

    let (obfuscated_id_2, pepper_2) =
        client_unblind_identifier(Channel::Phone, phone_number, &evaluated_point_2, &r2).unwrap();

    // 5. Assert determinism: unblinded pepper and ObfuscatedIdentifier match 100%
    assert_eq!(pepper_1, pepper_2, "Celo ODIS peppers must be deterministic");
    assert_eq!(
        obfuscated_id_1, obfuscated_id_2,
        "Obfuscated identifiers must be identical across blinding sessions"
    );
    println!("Celo ODIS Obfuscated Identifier: {:?}", obfuscated_id_1);
}
