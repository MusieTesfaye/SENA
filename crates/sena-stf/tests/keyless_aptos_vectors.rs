//! Keyless accounts against Aptos's own test vectors.
//!
//! Aptos publishes one real proof over the Aptos Keyless circuit
//! (`SAMPLE_PROOF` in aptos-core `types/src/keyless/circuit_testcases.rs`),
//! made under its devnet test setup for a sample JWT. Every intermediate value
//! below was printed by aptos-core itself at the commit the Move framework is
//! pinned to, so a mismatch localises exactly which encoding diverged.
//!
//! If these tests pass, SENA computes the circuit's public input exactly as
//! Aptos does, and a proof from any Aptos-compatible prover will verify.

use std::str::FromStr;

use ark_bn254::Fr;
use ed25519_dalek::{Signer, SigningKey};
use sena_primitives::{AssetId, L2Address};
use sena_state::MerkleTrie;
use sena_stf::execute::{encode_jwk_record, genesis_credit};
use sena_stf::gas::fee_for;
use sena_stf::keyless::{self, KeylessConfig, KeylessError, KeylessSignature};
use sena_stf::{
    apply, compile, execute_batch, keys, Account, AuthError, Authenticator, BatchContext,
    BatchError, CompileError, Instruction, Payload, StepError, Transaction, WhitelistedAsset,
    RATE_SCALE,
};

use keyless::aptos_sample::{
    pepper, AUD, EPHEMERAL_PUBLIC_KEY as EPK, EXP_DATE_SECS as EXP_DATE, ISS, JWK_N, UID_KEY,
    UID_VAL,
};

fn fr(s: &str) -> Fr {
    Fr::from_str(s).unwrap()
}

fn esk() -> SigningKey {
    SigningKey::from_bytes(&keyless::aptos_sample::ephemeral_secret_key())
}

fn sample_signature() -> KeylessSignature {
    keyless::aptos_sample::signature()
}

fn devnet() -> std::sync::Arc<KeylessConfig> {
    KeylessConfig::aptos_devnet_insecure()
}

// --- Intermediate values -----------------------------------------------------

#[test]
fn the_ephemeral_key_is_the_aptos_sample_key() {
    assert_eq!(hex::encode(esk().verifying_key().to_bytes()), EPK);
}

#[test]
fn every_hash_matches_aptos() {
    let le = |s: &str| keyless::fr_to_bytes(&fr(s));
    assert_eq!(
        keyless::iss_hash(ISS).unwrap(),
        le("5832611597959427633926665973272710211662885437116269482737244671258641689241")
    );
    assert_eq!(
        keyless::rsa_jwk_hash_b64(JWK_N).unwrap(),
        le("7512354524287453180666073731161369957868279524147997909581062460530221794792")
    );
    assert_eq!(
        hex::encode(keyless::id_commitment(&pepper(), AUD, UID_KEY, UID_VAL).unwrap()),
        "c390842e61c06e1ec945fc8504ad0830652ec1b6fc7bb0a095026be7551e001d"
    );
    let mut blinder = [0u8; 31];
    blinder[0] = 42;
    assert_eq!(
        keyless::oauth_nonce(&esk().verifying_key().to_bytes(), EXP_DATE, &blinder),
        "2284473333442251804379681643965308154311773667525398119496797545594705356495"
    );
}

#[test]
fn the_public_inputs_hash_matches_aptos() {
    let sig = sample_signature();
    assert_eq!(
        keyless::public_inputs_hash(&sig).unwrap(),
        fr("16135305688213891292970912871721660547134358458946400949576655993305634528499")
    );
    let no_extra = KeylessSignature {
        extra_field_hash: None,
        ..sig
    };
    assert_eq!(
        keyless::public_inputs_hash(&no_extra).unwrap(),
        fr("11569417488899904347978840848237527198589549025678107600463909558549516598428")
    );
}

// --- End to end --------------------------------------------------------------

const USDC: AssetId = AssetId(1);

fn sender() -> L2Address {
    sample_signature().address()
}

fn transfer(sig: KeylessSignature, signer: &SigningKey) -> Transaction {
    transfer_from(sender(), sig, signer)
}

fn transfer_from(from: L2Address, sig: KeylessSignature, signer: &SigningKey) -> Transaction {
    let mut tx = Transaction {
        sender: from,
        nonce: 0,
        fee_asset: USDC,
        max_fee: fee_for(RATE_SCALE).unwrap(),
        fee_rate: RATE_SCALE,
        payload: Payload::Transfer {
            to: L2Address::from_bytes([9; 32]),
            asset: USDC,
            amount: 1_000,
        },
        authenticator: Authenticator::Keyless(Box::new(sig)),
    };
    let signature = signer.sign(tx.signing_digest().as_bytes()).to_bytes();
    if let Authenticator::Keyless(sig) = &mut tx.authenticator {
        sig.ephemeral_signature = signature;
    }
    tx
}

fn signed() -> Transaction {
    transfer(sample_signature(), &esk())
}

/// A state with USDC whitelisted, the sample account funded and, unless
/// `jwk` is `None`, a JWK record for the sample issuer.
fn state(jwk: Option<bool>) -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    apply(
        &mut trie,
        &Instruction::SetGasAsset {
            record: WhitelistedAsset {
                asset: USDC,
                symbol: "USDC".into(),
                rate: RATE_SCALE,
                enabled: true,
            },
        },
    )
    .unwrap();
    genesis_credit(&mut trie, sender(), USDC, 1_000_000);
    if let Some(active) = jwk {
        let sig = sample_signature();
        trie.insert(
            keys::jwk(&sig.iss_hash, &sig.jwk_hash),
            encode_jwk_record(active),
        );
    }
    trie
}

fn ctx(config: &KeylessConfig) -> BatchContext<'_> {
    BatchContext {
        timestamp: 1_700_000_000,
        keyless: Some(config),
    }
}

fn auth_err(tx: &Transaction, config: &KeylessConfig) -> KeylessError {
    match compile(tx, &ctx(config)).unwrap_err() {
        CompileError::Auth(AuthError::Keyless(e)) => e,
        other => panic!("expected a keyless error, got {other:?}"),
    }
}

#[test]
fn a_keyless_transfer_executes_end_to_end() {
    let config = devnet();
    let mut trie = state(Some(true));
    let trace = execute_batch(&mut trie, &ctx(&config), &[signed()]).expect("keyless transfer");
    assert!(matches!(
        trace.instructions[0],
        Instruction::VerifyJwk { .. }
    ));
    let recipient = Account::decode(
        trie.get(&keys::account(&L2Address::from_bytes([9; 32])))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(recipient.balance(USDC), 1_000);
}

#[test]
fn a_proof_under_another_setup_is_refused() {
    // The mainnet ceremony key must not accept a devnet proof.
    let mainnet = KeylessConfig::aptos_mainnet();
    let tx = transfer(
        KeylessSignature {
            exp_horizon_secs: 10_000_000,
            ..sample_signature()
        },
        &esk(),
    );
    assert_eq!(auth_err(&tx, &mainnet), KeylessError::InvalidProof);
}

#[test]
fn keyless_is_refused_when_disabled() {
    let tx = signed();
    assert_eq!(
        compile(&tx, &BatchContext::without_keyless(1_700_000_000)).unwrap_err(),
        CompileError::Auth(AuthError::Keyless(KeylessError::Disabled))
    );
}

#[test]
fn an_unregistered_jwk_fails_in_the_trace() {
    let config = devnet();
    let mut trie = state(None);
    assert!(matches!(
        execute_batch(&mut trie, &ctx(&config), &[signed()]),
        Err(BatchError::Step {
            source: StepError::JwkNotAccepted,
            ..
        })
    ));
}

#[test]
fn a_retired_jwk_fails_in_the_trace() {
    let config = devnet();
    let mut trie = state(Some(false));
    assert!(matches!(
        execute_batch(&mut trie, &ctx(&config), &[signed()]),
        Err(BatchError::Step {
            source: StepError::JwkNotAccepted,
            ..
        })
    ));
}

#[test]
fn a_jwk_accepted_for_another_issuer_does_not_count() {
    let config = devnet();
    let mut trie = state(None);
    let sig = sample_signature();
    let other_iss = keyless::iss_hash("https://accounts.google.com").unwrap();
    trie.insert(
        keys::jwk(&other_iss, &sig.jwk_hash),
        encode_jwk_record(true),
    );
    assert!(execute_batch(&mut trie, &ctx(&config), &[signed()]).is_err());
}

#[test]
fn the_proof_cannot_be_moved_to_another_account() {
    let config = devnet();
    let tx = transfer_from(L2Address::from_bytes([7; 32]), sample_signature(), &esk());
    assert_eq!(auth_err(&tx, &config), KeylessError::WrongSender);

    // Nor can the identity be swapped for another user's: the address follows
    // the commitment, and the proof does not.
    let other_idc = keyless::id_commitment(&pepper(), AUD, UID_KEY, "someone-else").unwrap();
    let forged = KeylessSignature {
        idc: other_idc,
        ..sample_signature()
    };
    let tx = transfer_from(forged.address(), forged, &esk());
    assert_eq!(auth_err(&tx, &config), KeylessError::InvalidProof);
}

#[test]
fn another_ephemeral_key_cannot_use_the_proof() {
    // A thief with the proof but not the ephemeral secret key signs with their
    // own key and substitutes it: the proof is bound to the original key.
    let config = devnet();
    let thief = SigningKey::from_bytes(&[5; 32]);
    let sig = KeylessSignature {
        ephemeral_public_key: thief.verifying_key().to_bytes(),
        ..sample_signature()
    };
    assert_eq!(
        auth_err(&transfer(sig, &thief), &config),
        KeylessError::InvalidProof
    );

    // Keeping the original key but signing with another fails the signature.
    assert_eq!(
        auth_err(&transfer(sample_signature(), &thief), &config),
        KeylessError::BadEphemeralSignature
    );
}

#[test]
fn every_public_input_is_bound() {
    let config = devnet();
    let mutations: [fn(&mut KeylessSignature); 6] = [
        |s| s.exp_date_secs += 1,
        |s| s.exp_horizon_secs -= 1,
        |s| s.jwt_header_hash = keyless::jwt_header_hash(r#"{"alg":"RS256"}"#).unwrap(),
        |s| s.jwk_hash = keyless::fr_to_bytes(&Fr::from(5u64)),
        |s| s.extra_field_hash = None,
        |s| s.proof[0] ^= 1,
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut sig = sample_signature();
        mutate(&mut sig);
        let err = auth_err(&transfer(sig, &esk()), &config);
        assert!(
            matches!(
                err,
                KeylessError::InvalidProof | KeylessError::MalformedProof
            ),
            "mutation {i} gave {err:?}"
        );
    }
}

#[test]
fn an_expired_ephemeral_key_is_refused() {
    let config = devnet();
    let tx = signed();
    let late = BatchContext {
        timestamp: EXP_DATE,
        keyless: Some(&config),
    };
    assert!(matches!(
        compile(&tx, &late).unwrap_err(),
        CompileError::Auth(AuthError::Keyless(KeylessError::Expired { .. }))
    ));
}

#[test]
fn an_over_long_horizon_is_refused() {
    let mainnet = KeylessConfig::aptos_mainnet();
    // The sample's horizon is far beyond mainnet policy.
    assert!(matches!(
        auth_err(&signed(), &mainnet),
        KeylessError::HorizonTooLong { .. }
    ));
}

#[test]
fn non_canonical_scalars_are_refused() {
    let config = devnet();
    let mut sig = sample_signature();
    sig.jwk_hash = [0xff; 32];
    assert_eq!(
        auth_err(&transfer(sig, &esk()), &config),
        KeylessError::NonCanonicalScalar("jwk_hash")
    );
}

#[test]
fn the_wire_format_round_trips() {
    let tx = signed();
    let json = serde_json::to_string(&tx).unwrap();
    assert_eq!(serde_json::from_str::<Transaction>(&json).unwrap(), tx);
}
