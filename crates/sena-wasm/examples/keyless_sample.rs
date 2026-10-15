//! Prints Aptos's published keyless sample as the inputs a wallet has after a
//! sign-in — a JWT carrying the sample's claims and a nonce for the sample's
//! ephemeral key, the pepper, and the prover's response — so the browser
//! bindings can be tested end to end against a node, without an identity
//! provider. The proof is Aptos's real circuit proof, for the insecure devnet
//! parameters.
//!
//! ```sh
//! cargo run -q -p sena-wasm --example keyless_sample > sample.json
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sena_stf::keyless::{self, aptos_sample};
use sena_wallet::keyless::KeylessSession;
use serde_json::json;

fn main() {
    let blinder = [7u8; 31];
    let session = KeylessSession::from_parts(
        aptos_sample::ephemeral_secret_key(),
        aptos_sample::EXP_DATE_SECS,
        blinder,
    );
    let claims = json!({
        "iss": aptos_sample::ISS,
        "aud": aptos_sample::AUD,
        "sub": aptos_sample::UID_VAL,
        "nonce": session.nonce(),
        "family_name": "Straka",
    });
    let jwt = format!(
        "{}.{}.c2ln",
        URL_SAFE_NO_PAD.encode(aptos_sample::JWT_HEADER_JSON),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let p = aptos_sample::PROOF;
    let pih = keyless::public_inputs_hash(&aptos_sample::signature()).unwrap();
    let pih = format!("0x{}", hex::encode(keyless::fr_to_bytes(&pih)));
    let out = json!({
        "jwt": jwt,
        "random": hex::encode([&aptos_sample::ephemeral_secret_key()[..], &blinder[..]].concat()),
        "exp_date_secs": aptos_sample::EXP_DATE_SECS,
        "exp_horizon_secs": aptos_sample::EXP_HORIZON_SECS,
        "pepper": hex::encode(aptos_sample::pepper()),
        "jwk": { "iss": aptos_sample::ISS, "kid": "test-rsa", "n": aptos_sample::JWK_N },
        "extra_field": aptos_sample::EXTRA_FIELD,
        "prover_response": {
            "proof": { "a": &p[..64], "b": &p[64..192], "c": &p[192..] },
            "public_inputs_hash": pih,
        },
        "address": aptos_sample::signature().address().to_string(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
