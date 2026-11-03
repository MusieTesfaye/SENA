//! Keeps a chain's accepted keyless JWKs in step with an identity provider.
//!
//! Providers rotate the keys they sign ID tokens with every few weeks. A
//! keyless proof is over one particular key, and the chain accepts only the
//! keys its council has approved (`GovernanceUpdate::SetJwk`), so without
//! this, sign-ins start failing the day the provider rotates.
//!
//! Each round fetches the provider's JWKS, and for every RSA key the chain
//! does not yet accept, submits a council-signed `SetJwk { active: true }`.
//! Keys this process has seen accepted and the provider has since withdrawn
//! are retired with `active: false`. The signing key must be a council member
//! and the council's threshold must be one: this is an operator's tool for a
//! test network, where a single key is an acceptable council. A network with
//! a real council collects signatures out of band instead.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use sena_primitives::{AssetId, L2Address};
use sena_stf::{Authenticator, CouncilSignature, GovernanceUpdate, Payload, Transaction};

/// Where and how to sync.
#[derive(Clone, Debug)]
pub struct JwkSyncConfig {
    /// The node's RPC endpoint.
    pub rpc: String,
    /// The provider's issuer (`iss`), e.g. `https://accounts.google.com`.
    pub iss: String,
    /// Its JWKS endpoint.
    pub jwks_url: String,
    /// The council member's key; it also sends and pays for the transactions.
    pub key: SigningKey,
    /// The asset fees are paid in.
    pub fee_asset: u32,
    /// Where the keys seen accepted are remembered, for retiring them later.
    pub state: PathBuf,
}

/// What one round did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Key ids newly accepted.
    pub accepted: Vec<String>,
    /// Key ids retired.
    pub retired: Vec<String>,
}

fn call(rpc: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    ureq::post(rpc)
        .timeout(Duration::from_secs(15))
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("request to {rpc} failed: {e}"))?
        .into_json()
        .map_err(|e| format!("response was not JSON: {e}"))
}

fn num(v: &serde_json::Value, k: &str) -> Result<u128, String> {
    v[k].as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v[k].as_u64().map(u128::from))
        .ok_or_else(|| format!("missing {k} in {v}"))
}

/// The provider's RSA keys, by key id.
///
/// # Errors
///
/// If the JWKS cannot be fetched or parsed.
pub fn fetch_jwks(url: &str) -> Result<BTreeMap<String, String>, String> {
    let body: serde_json::Value = ureq::get(url)
        .timeout(Duration::from_secs(15))
        .call()
        .map_err(|e| format!("fetching {url}: {e}"))?
        .into_json()
        .map_err(|e| format!("{url} did not return JSON: {e}"))?;
    let keys = body["keys"]
        .as_array()
        .ok_or_else(|| format!("{url} has no keys"))?;
    Ok(keys
        .iter()
        .filter(|k| k["kty"] == "RSA" && k["alg"].as_str().unwrap_or("RS256") == "RS256")
        .filter_map(|k| Some((k["kid"].as_str()?.to_owned(), k["n"].as_str()?.to_owned())))
        .collect())
}

impl JwkSyncConfig {
    fn is_active(&self, n: &str) -> Result<bool, String> {
        let r = call(
            &self.rpc,
            &serde_json::json!({ "method": "sena_getJwk", "params": { "iss": self.iss, "n": n } }),
        )?;
        if r["result"] == "error" {
            return Err(format!("sena_getJwk: {}", r["message"]));
        }
        Ok(r["active"] == true)
    }

    /// Signs `update` as the council and submits it; waits for its block.
    fn govern(&self, update: GovernanceUpdate) -> Result<(), String> {
        let me = hex::encode(self.key.verifying_key().to_bytes());
        let council = call(
            &self.rpc,
            &serde_json::json!({ "method": "sena_getCouncil" }),
        )?;
        let members = council["members"]
            .as_array()
            .ok_or_else(|| format!("sena_getCouncil: {council}"))?;
        let index = members
            .iter()
            .position(|m| m.as_str() == Some(me.as_str()))
            .ok_or("this key is not a council member")?;
        if council["threshold"] != 1 {
            return Err(format!(
                "the council needs {} signatures; jwk-sync signs alone",
                council["threshold"]
            ));
        }
        let epoch = council["epoch"].as_u64().ok_or("no council epoch")?;

        let info = call(
            &self.rpc,
            &serde_json::json!({ "method": "sena_getChainInfo" }),
        )?;
        let chain_id = info["transaction_chain_id"]
            .as_u64()
            .ok_or_else(|| format!("no chain id: {info}"))?;
        let quote = call(
            &self.rpc,
            &serde_json::json!({ "method": "sena_gasPrice", "params": { "asset": self.fee_asset } }),
        )?;
        let sender = L2Address::from_bytes(self.key.verifying_key().to_bytes());
        let account = call(
            &self.rpc,
            &serde_json::json!({ "method": "sena_getAccount", "params": { "address": sender.to_string() } }),
        )?;

        let digest = update.signing_digest(chain_id, epoch);
        let signature = CouncilSignature {
            index: u32::try_from(index).map_err(|e| e.to_string())?,
            signature: self.key.sign(digest.as_bytes()).to_bytes(),
        };
        let mut tx = Transaction {
            chain_id,
            sender,
            nonce: account["nonce"]
                .as_u64()
                .ok_or_else(|| format!("no nonce: {account}"))?,
            fee_asset: AssetId(self.fee_asset),
            fee_rate: num(&quote, "rate")?,
            fee_intrinsic_gas: u64::try_from(num(&quote, "intrinsic_gas")?)
                .map_err(|e| e.to_string())?,
            gas_limit: 0,
            max_fee_per_gas: num(&quote, "suggested_max_fee_per_gas")?,
            max_priority_fee_per_gas: 0,
            payload: Payload::Governance {
                epoch,
                update,
                signatures: vec![signature],
            },
            authenticator: Authenticator::Ed25519 {
                public_key: self.key.verifying_key().to_bytes(),
                signature: [0; 64],
            },
        };
        tx.gas_limit = sena_stf::gas_required(&tx).map_err(|e| e.to_string())?;
        tx.authenticator = Authenticator::Ed25519 {
            public_key: self.key.verifying_key().to_bytes(),
            signature: self.key.sign(tx.signing_digest().as_bytes()).to_bytes(),
        };
        let hash = tx.hash();
        let body = serde_json::to_value(crate::Request::SubmitTransaction(Box::new(tx)))
            .map_err(|e| e.to_string())?;
        let r = call(&self.rpc, &body)?;
        if r["result"] != "submitted" {
            return Err(format!("the node refused the update: {r}"));
        }
        for _ in 0..120 {
            let c = call(
                &self.rpc,
                &serde_json::json!({ "method": "sena_getConfirmation", "params": { "hash": hash.to_string() } }),
            )?;
            match c["status"].as_str() {
                Some("soft_confirmed" | "finalized") => return Ok(()),
                _ => std::thread::sleep(Duration::from_millis(500)),
            }
        }
        Err(format!(
            "transaction {hash} was not included within a minute"
        ))
    }

    fn set(&self, n: &str, active: bool) -> Result<(), String> {
        let bad = |e: sena_stf::KeylessError| e.to_string();
        self.govern(GovernanceUpdate::SetJwk {
            iss_hash: sena_stf::keyless::iss_hash(&self.iss).map_err(bad)?,
            jwk_hash: sena_stf::keyless::rsa_jwk_hash_b64(n).map_err(bad)?,
            active,
        })?;
        // Included is not applied: a batch step can fail. Read it back.
        if self.is_active(n)? == active {
            Ok(())
        } else {
            Err(format!(
                "the chain did not apply SetJwk(active: {active}); check the council and fees"
            ))
        }
    }

    fn load(&self) -> BTreeMap<String, String> {
        std::fs::read(&self.state)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, seen: &BTreeMap<String, String>) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(seen).map_err(|e| e.to_string())?;
        std::fs::write(&self.state, json)
            .map_err(|e| format!("writing {}: {e}", self.state.display()))
    }

    /// One round: accept the provider's new keys, retire withdrawn ones.
    ///
    /// # Errors
    ///
    /// If the provider or the node cannot be reached, or the node refuses an
    /// update. Progress made before the error is kept.
    pub fn round(&self) -> Result<SyncReport, String> {
        let published = fetch_jwks(&self.jwks_url)?;
        if published.is_empty() {
            // An empty or broken JWKS is never a reason to retire everything.
            return Err(format!("{} lists no RSA keys", self.jwks_url));
        }
        let mut seen = self.load();
        let mut report = SyncReport::default();
        for (kid, n) in &published {
            if !self.is_active(n)? {
                self.set(n, true)?;
                report.accepted.push(kid.clone());
            }
            seen.insert(kid.clone(), n.clone());
            self.save(&seen)?;
        }
        let withdrawn: Vec<(String, String)> = seen
            .iter()
            .filter(|(kid, _)| !published.contains_key(*kid))
            .map(|(k, n)| (k.clone(), n.clone()))
            .collect();
        for (kid, n) in withdrawn {
            if self.is_active(&n)? {
                self.set(&n, false)?;
                report.retired.push(kid.clone());
            }
            seen.remove(&kid);
            self.save(&seen)?;
        }
        Ok(report)
    }
}
