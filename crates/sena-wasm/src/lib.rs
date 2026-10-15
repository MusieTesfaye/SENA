//! SENA wallet logic for browsers.
//!
//! Thin bindings over [`sena_wallet`]: values cross as strings — hex for
//! bytes, decimal for `u128` amounts, JSON for structures — and errors as
//! thrown strings. Randomness comes from the caller (`crypto.getRandomValues`)
//! so nothing here needs a source of its own.
//!
//! Build: `scripts/build-wasm.sh`.

use sena_primitives::{AssetId, L2Address};
use sena_stf::keyless::limits;
use sena_stf::{KeylessSignature, Transaction};
use sena_wallet::keyless::{self, Jwt, KeylessSession, SignIn};
use sena_wallet::FeeQuote;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

/// The claim a keyless account is keyed by.
const UID_KEY: &str = "sub";

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn bytes<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], JsError> {
    hex::decode(hex_str.trim().trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err(format!("{what} must be {N} bytes of hex")))
}

fn amount(s: &str, what: &str) -> Result<u128, JsError> {
    s.trim()
        .parse()
        .map_err(|_| err(format!("{what} is not a whole number: {s:?}")))
}

fn address(s: &str) -> Result<L2Address, JsError> {
    L2Address::from_hex(s.trim()).map_err(|e| err(format!("bad address {s:?}: {e}")))
}

fn json_of<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn session_from(json_str: &str) -> Result<KeylessSession, JsError> {
    let v: Value = serde_json::from_str(json_str).map_err(err)?;
    let field = |k: &str| {
        v[k].as_str()
            .ok_or_else(|| err(format!("session has no {k}")))
    };
    Ok(KeylessSession::from_parts(
        bytes(field("secret")?, "session secret")?,
        v["exp_date_secs"]
            .as_u64()
            .ok_or_else(|| err("session has no exp_date_secs"))?,
        bytes(field("blinder")?, "session blinder")?,
    ))
}

fn session_json(s: &KeylessSession) -> String {
    json!({
        "secret": hex::encode(s.secret_key()),
        "blinder": hex::encode(s.blinder),
        "exp_date_secs": s.exp_date_secs,
        "public_key": hex::encode(s.public_key()),
        "nonce": s.nonce(),
    })
    .to_string()
}

/// A new ephemeral session expiring at `exp_date_secs`, from 63 random bytes
/// (32 for the key, 31 for the blinder). Returns its JSON, which the wallet
/// stores; `nonce` goes in the OAuth request.
#[wasm_bindgen(js_name = newSession)]
pub fn new_session(exp_date_secs: u64, random: &[u8]) -> Result<String, JsError> {
    if random.len() != 32 + limits::BYTES_PER_SCALAR {
        return Err(err("newSession needs 63 random bytes"));
    }
    let secret: [u8; 32] = random[..32].try_into().map_err(err)?;
    let blinder: [u8; limits::BYTES_PER_SCALAR] = random[32..].try_into().map_err(err)?;
    Ok(session_json(&KeylessSession::from_parts(
        secret,
        exp_date_secs,
        blinder,
    )))
}

/// The JWT's header and claims as JSON: `{header: {...}, claims: {...}}`.
#[wasm_bindgen(js_name = decodeJwt)]
pub fn decode_jwt(jwt: &str) -> Result<String, JsError> {
    let parsed = Jwt::parse(jwt).map_err(err)?;
    let header: Value = serde_json::from_str(&parsed.header_json).map_err(err)?;
    Ok(json!({ "header": header, "claims": parsed.claims }).to_string())
}

/// The body to POST to the pepper service's `/v0/fetch`.
#[wasm_bindgen(js_name = pepperRequest)]
pub fn pepper_request(jwt: &str, session: &str) -> Result<String, JsError> {
    Ok(keyless::pepper_request(jwt, &session_from(session)?, UID_KEY).to_string())
}

/// The pepper, as hex, from the pepper service's response JSON.
#[wasm_bindgen(js_name = parsePepper)]
pub fn parse_pepper(response: &str) -> Result<String, JsError> {
    let v: Value = serde_json::from_str(response).map_err(err)?;
    Ok(hex::encode(
        keyless::parse_pepper_response(&v).map_err(err)?,
    ))
}

/// The keyless address a sign-in controls.
#[wasm_bindgen(js_name = keylessAddress)]
pub fn keyless_address(jwt: &str, pepper: &str) -> Result<String, JsError> {
    let parsed = Jwt::parse(jwt).map_err(err)?;
    let pepper = bytes::<{ limits::PEPPER_BYTES }>(pepper, "pepper")?;
    Ok(keyless::address_of(&parsed, &pepper, UID_KEY)
        .map_err(err)?
        .to_string())
}

fn sign_in<'a>(
    session: &'a KeylessSession,
    pepper: &str,
    exp_horizon_secs: u64,
    jwk_n: &'a str,
    extra_field: &'a str,
) -> Result<SignIn<'a>, JsError> {
    Ok(SignIn {
        session,
        pepper: bytes(pepper, "pepper")?,
        uid_key: UID_KEY,
        extra_field: Some(extra_field).filter(|f| !f.is_empty()),
        exp_horizon_secs,
        jwk_n,
    })
}

/// The body to POST to the proving service's `/v0/prove`. `extra_field` is a
/// JWT field to reveal, as `"name":"value",`, or empty for none.
#[wasm_bindgen(js_name = proverRequest)]
pub fn prover_request(
    jwt: &str,
    session: &str,
    pepper: &str,
    exp_horizon_secs: u64,
    extra_field: &str,
) -> Result<String, JsError> {
    let s = session_from(session)?;
    let sign_in = sign_in(&s, pepper, exp_horizon_secs, "", extra_field)?;
    Ok(keyless::prover_request(jwt, &sign_in).to_string())
}

/// The keyless signature, as JSON, for a sign-in and the proving service's
/// response. `jwk_n` is the modulus of the JWK whose `kid` the JWT header
/// names, and `extra_field` as for [`prover_request`]. Refuses a proof for
/// other public inputs than this sign-in's.
#[wasm_bindgen(js_name = assembleSignature)]
pub fn assemble_signature(
    jwt: &str,
    session: &str,
    pepper: &str,
    exp_horizon_secs: u64,
    jwk_n: &str,
    extra_field: &str,
    prover_response: &str,
) -> Result<String, JsError> {
    let s = session_from(session)?;
    let v: Value = serde_json::from_str(prover_response).map_err(err)?;
    let proved = keyless::parse_prover_response(&v).map_err(err)?;
    let parsed = Jwt::parse(jwt).map_err(err)?;
    let sig = keyless::assemble(
        &parsed,
        &sign_in(&s, pepper, exp_horizon_secs, jwk_n, extra_field)?,
        proved.proof,
        Some(proved.public_inputs_hash),
    )
    .map_err(err)?;
    Ok(json_of(&sig))
}

/// The address a keyless signature's account has.
#[wasm_bindgen(js_name = signatureAddress)]
pub fn signature_address(signature: &str) -> Result<String, JsError> {
    let sig: KeylessSignature = serde_json::from_str(signature).map_err(err)?;
    Ok(sig.address().to_string())
}

/// An unsigned transfer, as JSON, metered to exactly the gas it uses.
/// Amounts and prices are decimal strings; `max_fee_per_gas` and `tip` are in
/// `PRICE_SCALE`ths of the fee asset's smallest unit.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = buildTransfer)]
pub fn build_transfer(
    sender: &str,
    nonce: u64,
    to: &str,
    asset: u32,
    amount_units: &str,
    fee_asset: u32,
    fee_rate: &str,
    fee_intrinsic_gas: u64,
    max_fee_per_gas: &str,
    tip: &str,
) -> Result<String, JsError> {
    let fee = FeeQuote {
        asset: AssetId(fee_asset),
        rate: amount(fee_rate, "fee rate")?,
        intrinsic_gas: fee_intrinsic_gas,
        max_fee_per_gas: amount(max_fee_per_gas, "max fee per gas")?,
        max_priority_fee_per_gas: amount(tip, "tip")?,
    };
    let tx = sena_wallet::transfer(
        address(sender)?,
        nonce,
        address(to)?,
        AssetId(asset),
        amount(amount_units, "amount")?,
        &fee,
    )
    .map_err(err)?;
    Ok(json_of(&tx))
}

fn tx_from(json_str: &str) -> Result<Transaction, JsError> {
    serde_json::from_str(json_str).map_err(|e| err(format!("bad transaction: {e}")))
}

/// Signs a transaction with a keyless session and signature, raising its gas
/// limit by what keyless verification costs. Returns the signed JSON.
#[wasm_bindgen(js_name = signKeyless)]
pub fn sign_keyless(tx: &str, session: &str, signature: &str) -> Result<String, JsError> {
    let sig: KeylessSignature = serde_json::from_str(signature).map_err(err)?;
    Ok(json_of(&keyless::sign(
        tx_from(tx)?,
        &session_from(session)?,
        sig,
    )))
}

/// Signs a transaction with an Ed25519 secret key. Returns the signed JSON.
#[wasm_bindgen(js_name = signEd25519)]
pub fn sign_ed25519(tx: &str, secret: &str) -> Result<String, JsError> {
    Ok(json_of(&sena_wallet::sign_ed25519(
        tx_from(tx)?,
        &bytes(secret, "secret key")?,
    )))
}

/// The address an Ed25519 secret key controls.
#[wasm_bindgen(js_name = ed25519Address)]
pub fn ed25519_address(secret: &str) -> Result<String, JsError> {
    Ok(sena_wallet::ed25519_address(&bytes(secret, "secret key")?).to_string())
}

/// A transaction's hash, as the node reports it.
#[wasm_bindgen(js_name = transactionHash)]
pub fn transaction_hash(tx: &str) -> Result<String, JsError> {
    Ok(tx_from(tx)?.hash().to_string())
}

/// The `sena_submitTransaction` request body for a signed transaction.
#[wasm_bindgen(js_name = submitRequest)]
pub fn submit_request(tx: &str) -> Result<String, JsError> {
    let v: Value = serde_json::from_str(tx).map_err(err)?;
    tx_from(tx)?;
    Ok(json!({ "method": "sena_submitTransaction", "params": v }).to_string())
}
