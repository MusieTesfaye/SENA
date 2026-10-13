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
