//! The wallet side of keyless accounts, without I/O: the requests a wallet
//! sends to the pepper and proving services are built here, and sent by
//! whoever embeds this (`sena_node::keyless_client` natively, `sena-wasm` in a
//! browser).
//!
//! A keyless transaction is authorised by an `OpenID` Connect sign-in rather
//! than a long-lived key. The flow, with the services Aptos runs for its own
//! keyless accounts:
//!
//! 1. The wallet creates a [`KeylessSession`]: a fresh ephemeral Ed25519 key,
//!    its expiry and a blinder. [`KeylessSession::nonce`] commits to all three.
//! 2. The user signs in with the identity provider, which embeds that nonce
//!    in the JWT it issues.
//! 3. The wallet fetches the user's pepper ([`PepperClient`]) and a Groth16
//!    proof that the JWT is validly signed and commits to the session
//!    ([`ProverClient`]). The proof is for the Aptos Keyless circuit SENA
//!    verifies against.
//! 4. [`assemble`] turns the JWT, pepper and proof into a
//!    [`KeylessSignature`], recomputing every public value itself and refusing
//!    a proof whose public-inputs hash is not the one it computed.
//! 5. Each transaction is signed by the ephemeral key ([`sign`]) until the
//!    session expires.
//!
//! Nothing here is trusted by the chain: a wrong pepper derives a different
//! address, and a wrong proof fails verification. The checks exist so a
//! wallet finds out at sign-in, not when its first transaction is refused.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sena_primitives::L2Address;
use sena_stf::keyless::{self, limits, KeylessError, KeylessSignature};
use sena_stf::{Authenticator, Transaction};
use serde_json::{json, Value};

/// Why a keyless sign-in could not be completed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ClientError {
    /// The JWT is not three base64url parts with JSON header and payload.
    #[error("malformed JWT: {0}")]
    MalformedJwt(String),
    /// A claim the circuit needs is missing or not a string.
    #[error("the JWT has no string claim {0:?}")]
    MissingClaim(String),
    /// The JWT's nonce does not commit to this session.
    #[error("the JWT nonce does not commit to this session's ephemeral key")]
    WrongNonce,
    /// An input violates a circuit limit.
    #[error(transparent)]
    Keyless(#[from] KeylessError),
    /// The proof's public-inputs hash is not the one the inputs give.
    #[error("the prover proved different public inputs than this sign-in's")]
    PublicInputsMismatch,
    /// A service could not be reached or answered with an error.
    #[error("{service}: {message}")]
    Service {
        /// Which service.
        service: &'static str,
        /// What went wrong.
        message: String,
    },
}

/// An ephemeral key and what the OAuth nonce commits to.
#[derive(Clone)]
pub struct KeylessSession {
    key: SigningKey,
    /// When the ephemeral key stops being usable (Unix seconds).
    pub exp_date_secs: u64,
    /// Blinds the nonce so it reveals nothing about the key.
    pub blinder: [u8; limits::BYTES_PER_SCALAR],
}

impl std::fmt::Debug for KeylessSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessSession")
            .field("ephemeral_public_key", &hex::encode(self.public_key()))
            .field("exp_date_secs", &self.exp_date_secs)
            .finish_non_exhaustive()
    }
}

impl KeylessSession {
    /// A fresh session expiring at `exp_date_secs`, from a cryptographic
    /// random source.
    #[must_use]
    pub fn generate<R: rand_core::CryptoRngCore>(exp_date_secs: u64, rng: &mut R) -> Self {
        let mut blinder = [0u8; limits::BYTES_PER_SCALAR];
        rng.fill_bytes(&mut blinder);
        Self {
            key: SigningKey::generate(rng),
            exp_date_secs,
            blinder,
        }
    }

    /// A session from saved parts.
    #[must_use]
    pub fn from_parts(
        secret: [u8; 32],
        exp_date_secs: u64,
        blinder: [u8; limits::BYTES_PER_SCALAR],
    ) -> Self {
        Self {
            key: SigningKey::from_bytes(&secret),
            exp_date_secs,
            blinder,
        }
    }

    /// The ephemeral public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The ephemeral secret key, for the wallet to store.
    #[must_use]
    pub fn secret_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// The nonce to request the JWT with.
    #[must_use]
    pub fn nonce(&self) -> String {
        keyless::oauth_nonce(&self.public_key(), self.exp_date_secs, &self.blinder)
    }

    /// The ephemeral key in the form Aptos services expect: its BCS encoding
    /// (`0x00` Ed25519 tag, `0x20` length, key), hex without `0x`.
    #[must_use]
    pub fn epk_bcs_hex(&self) -> String {
        let mut b = vec![0x00, 0x20];
        b.extend_from_slice(&self.public_key());
        hex::encode(b)
    }
}

/// The parts of a JWT a keyless signature commits to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Jwt {
    /// The decoded header JSON, exactly as issued.
    pub header_json: String,
    /// The decoded payload.
    pub claims: Value,
}

impl Jwt {
    /// Splits and decodes a compact JWT. The signature is not checked: the
    /// proof attests to it, against a JWK the chain accepts.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::MalformedJwt`] if it does not decode.
    pub fn parse(jwt: &str) -> Result<Self, ClientError> {
        let bad = |m: &str| ClientError::MalformedJwt(m.to_owned());
        let mut parts = jwt.split('.');
        let (Some(h), Some(p), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("expected three parts"));
        };
        let header = URL_SAFE_NO_PAD
            .decode(h)
            .map_err(|_| bad("header is not base64url"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(p)
            .map_err(|_| bad("payload is not base64url"))?;
        let header_json = String::from_utf8(header).map_err(|_| bad("header is not UTF-8"))?;
        serde_json::from_str::<Value>(&header_json).map_err(|_| bad("header is not JSON"))?;
        let claims = serde_json::from_slice(&payload).map_err(|_| bad("payload is not JSON"))?;
        Ok(Self {
            header_json,
            claims,
        })
    }

    /// A string claim.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::MissingClaim`] if absent or not a string.
    pub fn claim(&self, name: &str) -> Result<&str, ClientError> {
        self.claims[name]
            .as_str()
            .ok_or_else(|| ClientError::MissingClaim(name.to_owned()))
    }
}

/// What a sign-in produces besides the JWT.
#[derive(Clone, Debug)]
pub struct SignIn<'a> {
    /// The session the JWT was requested for.
    pub session: &'a KeylessSession,
    /// The user's pepper.
    pub pepper: [u8; limits::PEPPER_BYTES],
    /// The claim identifying the user, normally `"sub"`.
    pub uid_key: &'a str,
    /// A payload field revealed in the clear, e.g. `"family_name":"Straka",`.
    pub extra_field: Option<&'a str>,
    /// The expiry horizon the proof was made for.
    pub exp_horizon_secs: u64,
    /// The modulus (`n`, base64url) of the JWK that signed the JWT.
    pub jwk_n: &'a str,
}

/// Builds the keyless authenticator for a sign-in, with the ephemeral
/// signature left zero (see [`sign`]).
///
/// `public_inputs_hash`, if the prover returned one, must be the hash this
/// function computes; otherwise the proof is for other inputs and would be
/// refused on chain.
///
/// # Errors
///
/// Returns [`ClientError`] if the JWT does not match the session, a claim is
/// missing or too long, or the prover's hash disagrees.
pub fn assemble(
    jwt: &Jwt,
    sign_in: &SignIn<'_>,
    proof: [u8; 128],
    public_inputs_hash: Option<[u8; 32]>,
) -> Result<KeylessSignature, ClientError> {
    if jwt.claim("nonce")? != sign_in.session.nonce() {
        return Err(ClientError::WrongNonce);
    }
    let iss = jwt.claim("iss")?;
    let aud = jwt.claim("aud")?;
    let uid_val = jwt.claim(sign_in.uid_key)?;
    let sig = KeylessSignature {
        iss_hash: keyless::iss_hash(iss)?,
        idc: keyless::id_commitment(&sign_in.pepper, aud, sign_in.uid_key, uid_val)?,
        ephemeral_public_key: sign_in.session.public_key(),
        ephemeral_signature: [0; 64],
        exp_date_secs: sign_in.session.exp_date_secs,
        exp_horizon_secs: sign_in.exp_horizon_secs,
        jwt_header_hash: keyless::jwt_header_hash(&jwt.header_json)?,
        jwk_hash: keyless::rsa_jwk_hash_b64(sign_in.jwk_n)?,
        extra_field_hash: sign_in
            .extra_field
            .map(keyless::extra_field_hash)
            .transpose()?,
        proof,
    };
    keyless::parse_proof(&sig.proof)?;
    if let Some(expected) = public_inputs_hash {
        if keyless::fr_to_bytes(&keyless::public_inputs_hash(&sig)?) != expected {
            return Err(ClientError::PublicInputsMismatch);
        }
    }
    Ok(sig)
}

/// Signs `tx` with the session's ephemeral key under `signature`, setting
/// the sender to the keyless address.
///
/// Keyless verification costs gas of its own, so the gas limit is raised to
/// what the keyless transaction needs if it is below it; the price caps are
/// left as they are.
#[must_use]
pub fn sign(
    mut tx: Transaction,
    session: &KeylessSession,
    mut signature: KeylessSignature,
) -> Transaction {
    tx.sender = signature.address();
    signature.ephemeral_signature = [0; 64];
    tx.authenticator = Authenticator::Keyless(Box::new(signature.clone()));
    if let Ok(required) = sena_stf::gas_required(&tx) {
        tx.gas_limit = tx.gas_limit.max(required);
    }
    signature.ephemeral_signature = session.key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Keyless(Box::new(signature));
    tx
}

/// The keyless address a sign-in controls.
///
/// # Errors
///
/// Returns [`ClientError`] if a claim is missing or too long.
pub fn address_of(
    jwt: &Jwt,
    pepper: &[u8; limits::PEPPER_BYTES],
    uid_key: &str,
) -> Result<L2Address, ClientError> {
    Ok(keyless::derive_address(
        jwt.claim("iss")?,
        pepper,
        jwt.claim("aud")?,
        uid_key,
        jwt.claim(uid_key)?,
    )?)
}

// --- Services --------------------------------------------------------------------

fn hex_field<const N: usize>(
    service: &'static str,
    v: &Value,
    name: &str,
) -> Result<[u8; N], ClientError> {
    let s = v[name].as_str().ok_or_else(|| ClientError::Service {
        service,
        message: format!("no {name}"),
    })?;
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ClientError::Service {
            service,
            message: format!("{name} is not {N} bytes of hex"),
        })
}

/// The request the pepper service (`POST <pepper>/v0/fetch`) takes, for a JWT
/// and session. Both Aptos services take this shape; the prover more besides
/// ([`prover_request`]).
#[must_use]
pub fn pepper_request(jwt: &str, session: &KeylessSession, uid_key: &str) -> Value {
    json!({
        "jwt_b64": jwt,
        "epk": session.epk_bcs_hex(),
        "epk_blinder": hex::encode(session.blinder),
        "exp_date_secs": session.exp_date_secs,
        "uid_key": uid_key,
    })
}

/// Reads the pepper service's answer, `{"pepper": "<hex>"}`. The pepper
/// must stay the same across sign-ins or the address changes, so a wallet
/// should use one service consistently.
///
/// # Errors
///
/// Returns [`ClientError::Service`] on an error or an unexpected shape.
pub fn parse_pepper_response(v: &Value) -> Result<[u8; limits::PEPPER_BYTES], ClientError> {
    if let Some(m) = v["message"].as_str().filter(|_| v.get("pepper").is_none()) {
        return Err(ClientError::Service {
            service: "pepper service",
            message: m.to_owned(),
        });
    }
    hex_field("pepper service", v, "pepper")
}

/// A proof and the public-inputs hash it is for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProverResponse {
    /// A ‖ B ‖ C, compressed.
    pub proof: [u8; 128],
    /// The public-inputs hash, 32 little-endian bytes.
    pub public_inputs_hash: [u8; 32],
}

/// The request the proving service (`POST <prover>/v0/prove`) takes, which
/// proves a JWT against the Aptos Keyless circuit.
#[must_use]
pub fn prover_request(jwt: &str, sign_in: &SignIn<'_>) -> Value {
    let mut body = pepper_request(jwt, sign_in.session, sign_in.uid_key);
    body["exp_horizon_secs"] = json!(sign_in.exp_horizon_secs);
    body["pepper"] = json!(hex::encode(sign_in.pepper));
    body["extra_field"] = sign_in
        .extra_field
        .map_or(Value::Null, |f| json!(field_name(f)));
    body
}

/// The name of a revealed field (`family_name` in `"family_name":"Straka",`),
/// which is how the prover asks for it.
fn field_name(extra_field: &str) -> &str {
    extra_field
        .trim_start_matches('"')
        .split('"')
        .next()
        .unwrap_or(extra_field)
}

/// Parses the prover's answer: `{proof: {a, b, c}, public_inputs_hash, ...}`
/// with points as hex and the hash as a decimal or hex field element.
///
/// # Errors
///
/// Returns [`ClientError::Service`] on an unexpected shape.
#[allow(clippy::many_single_char_names)]
pub fn parse_prover_response(v: &Value) -> Result<ProverResponse, ClientError> {
    const S: &str = "prover";
    let bad = |m: &str| ClientError::Service {
        service: S,
        message: m.to_owned(),
    };
    if let Some(m) = v["message"].as_str().filter(|_| v.get("proof").is_none()) {
        return Err(bad(m));
    }
    let p = &v["proof"];
    let a: [u8; 32] = hex_field(S, p, "a")?;
    let b: [u8; 64] = hex_field(S, p, "b")?;
    let c: [u8; 32] = hex_field(S, p, "c")?;
    let mut proof = [0u8; 128];
    proof[..32].copy_from_slice(&a);
    proof[32..96].copy_from_slice(&b);
    proof[96..].copy_from_slice(&c);
    let h = v["public_inputs_hash"]
        .as_str()
        .ok_or_else(|| bad("no public_inputs_hash"))?;
    let public_inputs_hash = if let Some(hx) = h.strip_prefix("0x") {
        hex::decode(hx)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("bad public_inputs_hash"))?
    } else {
        keyless::fr_to_bytes(&h.parse().map_err(|()| bad("bad public_inputs_hash"))?)
    };
    Ok(ProverResponse {
        proof,
        public_inputs_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sena_stf::keyless::{aptos_sample, KeylessConfig, KeylessContext};
    use sena_stf::Payload;

    fn session() -> KeylessSession {
        KeylessSession::from_parts(
            aptos_sample::ephemeral_secret_key(),
            aptos_sample::EXP_DATE_SECS,
            [7; 31],
        )
    }

    /// A JWT carrying the Aptos sample's claims and a nonce for `session`.
    fn jwt(session: &KeylessSession) -> String {
        let claims = json!({
            "iss": aptos_sample::ISS,
            "aud": aptos_sample::AUD,
            "sub": aptos_sample::UID_VAL,
            "nonce": session.nonce(),
            "family_name": "Straka",
        });
        format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(aptos_sample::JWT_HEADER_JSON),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn sign_in(session: &KeylessSession) -> SignIn<'_> {
        SignIn {
            session,
            pepper: aptos_sample::pepper(),
            uid_key: aptos_sample::UID_KEY,
            extra_field: Some(aptos_sample::EXTRA_FIELD),
            exp_horizon_secs: aptos_sample::EXP_HORIZON_SECS,
            jwk_n: aptos_sample::JWK_N,
        }
    }

    fn proof() -> [u8; 128] {
        hex::decode(aptos_sample::PROOF)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn a_sign_in_assembles_the_sample_authenticator_which_verifies() {
        let s = session();
        let parsed = Jwt::parse(&jwt(&s)).unwrap();
        let expected = aptos_sample::signature();
        let pih = keyless::fr_to_bytes(&keyless::public_inputs_hash(&expected).unwrap());
        let sig = assemble(&parsed, &sign_in(&s), proof(), Some(pih)).unwrap();
        assert_eq!(sig, expected);
        assert_eq!(
            address_of(&parsed, &aptos_sample::pepper(), "sub").unwrap(),
            expected.address()
        );

        let tx = Transaction {
            sender: L2Address::from_bytes([0; 32]),
            nonce: 0,
            fee_asset: sena_primitives::AssetId(1),
            fee_rate: 0,
            fee_intrinsic_gas: 0,
            gas_limit: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            payload: Payload::Transfer {
                to: L2Address::from_bytes([9; 32]),
                asset: sena_primitives::AssetId(1),
                amount: 1,
            },
            authenticator: Authenticator::Ed25519 {
                public_key: [0; 32],
                signature: [0; 64],
            },
        };
        let mut tx = tx;
        sena_stf::gas::fill_default_fees(&mut tx);
        let tx = sign(tx, &s, sig);
        let config = KeylessConfig::aptos_devnet_insecure();
        let ctx = KeylessContext {
            config: Some(&config),
            now: aptos_sample::EXP_DATE_SECS - 1,
        };
        tx.authenticate(&ctx)
            .expect("the assembled, signed transaction verifies");
    }

    #[test]
    fn a_jwt_for_another_session_is_refused() {
        let s = session();
        let other = KeylessSession::from_parts(
            aptos_sample::ephemeral_secret_key(),
            aptos_sample::EXP_DATE_SECS,
            [8; 31],
        );
        let parsed = Jwt::parse(&jwt(&other)).unwrap();
        assert_eq!(
            assemble(&parsed, &sign_in(&s), proof(), None),
            Err(ClientError::WrongNonce)
        );
    }

    #[test]
    fn a_proof_for_other_inputs_is_refused() {
        let s = session();
        let parsed = Jwt::parse(&jwt(&s)).unwrap();
        let mut wrong = sign_in(&s);
        wrong.pepper[0] = 77;
        let pih =
            keyless::fr_to_bytes(&keyless::public_inputs_hash(&aptos_sample::signature()).unwrap());
        assert_eq!(
            assemble(&parsed, &wrong, proof(), Some(pih)),
            Err(ClientError::PublicInputsMismatch)
        );
    }

    #[test]
    fn prover_responses_parse() {
        let p = aptos_sample::PROOF;
        let v = json!({
            "proof": {"a": &p[..64], "b": &p[64..192], "c": &p[192..]},
            "public_inputs_hash": "12345",
            "training_wheels_signature": "00",
        });
        let r = parse_prover_response(&v).unwrap();
        assert_eq!(r.proof, proof());
        assert_eq!(r.public_inputs_hash[0], 0x39); // 12345 = 0x3039, little-endian
        assert!(parse_prover_response(&json!({"message": "rate limited"})).is_err());
        assert_eq!(field_name(aptos_sample::EXTRA_FIELD), "family_name");
    }

    #[test]
    fn malformed_jwts_are_refused() {
        assert!(Jwt::parse("a.b").is_err());
        assert!(Jwt::parse("!!.e30.x").is_err());
    }
}
