//! The wallet side of keyless accounts, with the HTTP calls to the pepper and
//! proving services. The logic itself is [`sena_wallet::keyless`], re-exported
//! here; this module only sends its requests.

use std::time::Duration;

pub use sena_wallet::keyless::*;
use serde_json::Value;

fn post(service: &'static str, url: &str, body: &Value) -> Result<Value, ClientError> {
    let err = |message: String| ClientError::Service { service, message };
    match ureq::post(url)
        .timeout(Duration::from_secs(60))
        .send_json(body)
    {
        Ok(r) => r.into_json().map_err(|e| err(e.to_string())),
        Err(ureq::Error::Status(code, r)) => Err(err(format!(
            "HTTP {code}: {}",
            r.into_string().unwrap_or_default()
        ))),
        Err(e) => Err(err(e.to_string())),
    }
}

/// The pepper service (`POST /v0/fetch`), which derives a user's pepper from
/// their JWT.
#[derive(Clone, Debug)]
pub struct PepperClient {
    /// Base URL, e.g. `https://api.mainnet.aptoslabs.com/keyless/pepper`.
    pub url: String,
}

impl PepperClient {
    /// Fetches the pepper for a signed-in user.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Service`] if the service fails.
    pub fn fetch(
        &self,
        jwt: &str,
        session: &KeylessSession,
        uid_key: &str,
    ) -> Result<[u8; sena_stf::keyless::limits::PEPPER_BYTES], ClientError> {
        let url = format!("{}/v0/fetch", self.url.trim_end_matches('/'));
        parse_pepper_response(&post(
            "pepper service",
            &url,
            &pepper_request(jwt, session, uid_key),
        )?)
    }
}

/// The proving service (`POST /v0/prove`), which proves a JWT against the
/// Aptos Keyless circuit.
#[derive(Clone, Debug)]
pub struct ProverClient {
    /// Base URL, e.g. `https://api.mainnet.aptoslabs.com/keyless/prover`.
    pub url: String,
}

impl ProverClient {
    /// Proves a sign-in.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Service`] if the service fails.
    pub fn prove(&self, jwt: &str, sign_in: &SignIn<'_>) -> Result<ProverResponse, ClientError> {
        let url = format!("{}/v0/prove", self.url.trim_end_matches('/'));
        parse_prover_response(&post("prover", &url, &prover_request(jwt, sign_in))?)
    }
}
