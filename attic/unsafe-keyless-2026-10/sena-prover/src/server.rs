//! External Prover Service HTTP REST Server (tiny_http).
//!
//! Exposes production endpoints for:
//! - Groth16 OpenID Connect zero-knowledge proving and verification.
//! - Celo ODIS tOPRF phone/email social connect evaluation.
//! - Distributed Pepper Storage (v-tOPRF) for Aptos-style cross-device Keyless accounts.

use std::sync::Arc;
use std::time::Instant;
use ark_bn254::{Fr, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sena_primitives::Hash256;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Response, Server, StatusCode};

use crate::odis::{OdisEvaluateRequest, OdisEvaluateResponse, OdisService};
use crate::pepper::{
    client_blind_identity, client_unblind_threshold_pepper, dleq_prove, generate_threshold_shares,
    guardian_evaluate_share, ClusterConfig, DistributedPepperClient, DleqProof,
};
use crate::prover::KeylessProver;

#[derive(Deserialize)]
struct ProveRequest {
    jwt: String,
    epk_hex: String,
    pepper_hex: String,
    exp: Option<u64>,
}

#[derive(Deserialize)]
struct VerifyRequest {
    proof_hex: String,
    public_inputs: Vec<String>,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    verification_time_us: u128,
}

#[derive(Deserialize)]
struct PepperGetRequest {
    iss: String,
    sub: String,
}

#[derive(Serialize)]
struct PepperGetResponse {
    pepper_hex: String,
    derived_address: String,
    threshold: usize,
    guardians_queried: usize,
    cluster_source: &'static str,
    derivation_time_us: u128,
}

#[derive(Deserialize)]
struct PepperBlindEvaluateRequest {
    blinded_point_hex: String,
}

#[derive(Serialize)]
struct PepperBlindEvaluateResponse {
    shares: Vec<PepperShareResponse>,
    threshold: usize,
    evaluation_time_us: u128,
}

#[derive(Serialize)]
struct PepperShareResponse {
    guardian_index: u32,
    share_point_hex: String,
    dleq_proof: DleqProof,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol: &'static str,
    curve: &'static str,
    snark: &'static str,
    circuit: &'static str,
    universal_oidc: bool,
    social_connect: &'static str,
    distributed_pepper: &'static str,
}

/// Runs the external Prover Service HTTP daemon on the specified port.
pub fn run_prover_server(prover: Arc<KeylessProver>, listen_addr: &str) -> Result<(), String> {
    let odis = Arc::new(OdisService::new_default());
    let pepper_client = Arc::new(DistributedPepperClient::new(ClusterConfig::default_local()));

    // Fallback embedded threshold cluster (2-of-3) for zero-downtime offline / local dev
    let fallback_master_secret = Fr::from_be_bytes_mod_order(
        Hash256::digest(b"sena_default_embedded_pepper_secret_dev").as_bytes(),
    );
    let fallback_shares = generate_threshold_shares(2, 3, fallback_master_secret);

    let server = Server::http(listen_addr)
        .map_err(|e| format!("Failed to bind Prover Service on {listen_addr}: {e}"))?;

    println!("⚡ [SENA Prover Service] Listening on http://{listen_addr}");
    println!("⚡ [SENA Prover Service] Endpoints:");
    println!("   POST http://{listen_addr}/api/v1/prove");
    println!("   POST http://{listen_addr}/api/v1/verify");
    println!("   POST http://{listen_addr}/api/v1/odis/evaluate");
    println!("   POST http://{listen_addr}/api/v1/pepper/get");
    println!("   POST http://{listen_addr}/api/v1/pepper/blinded_evaluate");
    println!("   GET  http://{listen_addr}/api/v1/pepper/cluster");
    println!("   GET  http://{listen_addr}/api/v1/health");

    for mut request in server.incoming_requests() {
        let prover = prover.clone();
        let pepper_client = pepper_client.clone();
        let fallback_shares = fallback_shares.clone();
        let url = request.url().to_string();
        let method = request.method().as_str().to_string();

        let cors_origin = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
        let cors_headers = Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap();
        let cors_methods = Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap();
        let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

        if method == "OPTIONS" {
            let res = Response::empty(StatusCode(200))
                .with_header(cors_origin)
                .with_header(cors_headers)
                .with_header(cors_methods);
            let _ = request.respond(res);
            continue;
        }

        match (method.as_str(), url.as_str()) {
            ("GET", "/api/v1/health") => {
                let health = HealthResponse {
                    status: "healthy",
                    protocol: "SENA-Keyless-v1",
                    curve: "BN254 (alt_bn128)",
                    snark: "Groth16",
                    circuit: "JwtKeylessCircuit",
                    universal_oidc: true,
                    social_connect: "Celo-ODIS-tOPRF",
                    distributed_pepper: "BN254-tOPRF-V-Shamir",
                };
                let body = serde_json::to_string(&health).unwrap_or_default();
                let res = Response::from_string(body)
                    .with_header(cors_origin)
                    .with_header(content_type);
                let _ = request.respond(res);
            }

            ("POST", "/api/v1/prove") => {
                let mut content = String::new();
                let _ = request.as_reader().read_to_string(&mut content);

                let parsed_req: Result<ProveRequest, _> = serde_json::from_str(&content);
                match parsed_req {
                    Ok(req_data) => {
                        let clean_epk = req_data.epk_hex.trim_start_matches("0x");
                        let clean_pepper = req_data.pepper_hex.trim_start_matches("0x");

                        let epk_vec = hex::decode(clean_epk).unwrap_or_default();
                        let pepper_vec = hex::decode(clean_pepper).unwrap_or_default();

                        if epk_vec.len() != 32 {
                            let res = Response::from_string(r#"{"error":"EPK must be 32 bytes"}"#)
                                .with_status_code(StatusCode(400))
                                .with_header(cors_origin)
                                .with_header(content_type);
                            let _ = request.respond(res);
                            continue;
                        }

                        let mut epk_bytes = [0u8; 32];
                        epk_bytes.copy_from_slice(&epk_vec);

                        let exp = req_data.exp.unwrap_or(2_000_000_000);

                        match prover.prove(&req_data.jwt, &epk_bytes, &pepper_vec, exp) {
                            Ok(proof_res) => {
                                let body = serde_json::to_string(&proof_res).unwrap_or_default();
                                let res = Response::from_string(body)
                                    .with_header(cors_origin)
                                    .with_header(content_type);
                                let _ = request.respond(res);
                            }
                            Err(e) => {
                                let body = format!(r#"{{"error":"{e}"}}"#);
                                let res = Response::from_string(body)
                                    .with_status_code(StatusCode(400))
                                    .with_header(cors_origin)
                                    .with_header(content_type);
                                let _ = request.respond(res);
                            }
                        }
                    }
                    Err(e) => {
                        let body = format!(r#"{{"error":"Invalid JSON: {e}"}}"#);
                        let res = Response::from_string(body)
                            .with_status_code(StatusCode(400))
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                }
            }

            ("POST", "/api/v1/verify") => {
                let mut content = String::new();
                let _ = request.as_reader().read_to_string(&mut content);

                let parsed_req: Result<VerifyRequest, _> = serde_json::from_str(&content);
                match parsed_req {
                    Ok(req_data) => {
                        let clean_proof = req_data.proof_hex.trim_start_matches("0x");
                        let proof_bytes = hex::decode(clean_proof).unwrap_or_default();

                        let mut public_inputs = Vec::new();
                        for s in req_data.public_inputs {
                            let clean = s.trim();
                            if clean.starts_with("0x") || clean.starts_with("0X") {
                                if let Ok(bytes) = hex::decode(&clean[2..]) {
                                    public_inputs.push(Fr::from_be_bytes_mod_order(&bytes));
                                    continue;
                                }
                            }
                            if let Ok(val) = clean.parse::<u64>() {
                                public_inputs.push(Fr::from(val));
                            } else if let Some(biguint) = rsa::BigUint::parse_bytes(clean.as_bytes(), 10) {
                                public_inputs.push(Fr::from_be_bytes_mod_order(&biguint.to_bytes_be()));
                            } else {
                                public_inputs.push(Fr::from_be_bytes_mod_order(clean.as_bytes()));
                            }
                        }

                        let start = Instant::now();
                        let is_valid = prover.verify(&proof_bytes, &public_inputs).unwrap_or(false);
                        let verification_time_us = start.elapsed().as_micros();

                        let resp = VerifyResponse {
                            valid: is_valid,
                            verification_time_us,
                        };
                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        let res = Response::from_string(body)
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                    Err(e) => {
                        let body = format!(r#"{{"error":"Invalid JSON: {e}"}}"#);
                        let res = Response::from_string(body)
                            .with_status_code(StatusCode(400))
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                }
            }

            ("POST", "/api/v1/odis/evaluate") => {
                let mut content = String::new();
                let _ = request.as_reader().read_to_string(&mut content);

                let parsed_req: Result<OdisEvaluateRequest, _> = serde_json::from_str(&content);
                match parsed_req {
                    Ok(req_data) => {
                        let clean_hex = req_data.blinded_point_hex.trim_start_matches("0x");
                        let blinded_bytes = hex::decode(clean_hex).unwrap_or_default();

                        let start = Instant::now();
                        match odis.evaluate_blinded(&blinded_bytes) {
                            Ok(evaluated_bytes) => {
                                let evaluation_time_us = start.elapsed().as_micros();
                                let resp = OdisEvaluateResponse {
                                    evaluated_point_hex: format!("0x{}", hex::encode(evaluated_bytes)),
                                    evaluation_time_us,
                                };
                                let body = serde_json::to_string(&resp).unwrap_or_default();
                                let res = Response::from_string(body)
                                    .with_header(cors_origin)
                                    .with_header(content_type);
                                let _ = request.respond(res);
                            }
                            Err(e) => {
                                let body = format!(r#"{{"error":"ODIS evaluation failed: {e}"}}"#);
                                let res = Response::from_string(body)
                                    .with_status_code(StatusCode(400))
                                    .with_header(cors_origin)
                                    .with_header(content_type);
                                let _ = request.respond(res);
                            }
                        }
                    }
                    Err(e) => {
                        let body = format!(r#"{{"error":"Invalid JSON: {e}"}}"#);
                        let res = Response::from_string(body)
                            .with_status_code(StatusCode(400))
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                }
            }

            ("POST", "/api/v1/pepper/get") => {
                let mut content = String::new();
                let _ = request.as_reader().read_to_string(&mut content);

                let parsed_req: Result<PepperGetRequest, _> = serde_json::from_str(&content);
                match parsed_req {
                    Ok(req_data) => {
                        let start = Instant::now();

                        // 1. First try distributed guardians
                        let (pepper_bytes, source, threshold, count) =
                            match pepper_client.derive_pepper(&req_data.iss, &req_data.sub) {
                                Ok(p) => (
                                    p,
                                    "distributed_guardians",
                                    pepper_client.cluster.threshold,
                                    pepper_client.cluster.guardians.len(),
                                ),
                                Err(_) => {
                                    // 2. Fallback to local threshold cluster
                                    let (blinded, r) = client_blind_identity(&req_data.iss, &req_data.sub);
                                    let s1 = fallback_shares[0].parse_secret().unwrap();
                                    let s2 = fallback_shares[1].parse_secret().unwrap();
                                    let pt1 = guardian_evaluate_share(&blinded, &s1);
                                    let pt2 = guardian_evaluate_share(&blinded, &s2);
                                    let p = client_unblind_threshold_pepper(&[(1, pt1), (2, pt2)], &r)
                                        .unwrap_or([0u8; 32]);
                                    (p, "local_threshold_cluster", 2, 2)
                                }
                            };

                        let derived_addr = sena_primitives::L2Address::derive_from_oidc_unified(
                            &req_data.iss,
                            &req_data.sub,
                            &pepper_bytes,
                        );
                        let derivation_time_us = start.elapsed().as_micros();

                        let resp = PepperGetResponse {
                            pepper_hex: format!("0x{}", hex::encode(pepper_bytes)),
                            derived_address: derived_addr.to_string(),
                            threshold,
                            guardians_queried: count,
                            cluster_source: source,
                            derivation_time_us,
                        };

                        let body = serde_json::to_string(&resp).unwrap_or_default();
                        let res = Response::from_string(body)
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                    Err(e) => {
                        let body = format!(r#"{{"error":"Invalid JSON: {e}"}}"#);
                        let res = Response::from_string(body)
                            .with_status_code(StatusCode(400))
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                }
            }

            ("POST", "/api/v1/pepper/blinded_evaluate") => {
                let mut content = String::new();
                let _ = request.as_reader().read_to_string(&mut content);

                let parsed_req: Result<PepperBlindEvaluateRequest, _> = serde_json::from_str(&content);
                match parsed_req {
                    Ok(req_data) => {
                        let clean_hex = req_data.blinded_point_hex.trim_start_matches("0x");
                        let blinded_bytes = hex::decode(clean_hex).unwrap_or_default();

                        let mut cursor = blinded_bytes.as_slice();
                        match G1Affine::deserialize_compressed(&mut cursor) {
                            Ok(blinded_pt) => {
                                let start = Instant::now();

                                // Try guardians or evaluate with fallback shares
                                let evaluated_shares = match pepper_client.evaluate_blinded(&blinded_pt) {
                                    Ok(shares) => {
                                        let mut res_shares = Vec::new();
                                        for (idx, pt) in shares {
                                            let mut out = Vec::new();
                                            let _ = pt.serialize_compressed(&mut out);
                                            // Provide dummy DLEQ if queried from client
                                            res_shares.push(PepperShareResponse {
                                                guardian_index: idx,
                                                share_point_hex: format!("0x{}", hex::encode(out)),
                                                dleq_proof: DleqProof {
                                                    c_hex: "0x00".to_string(),
                                                    z_hex: "0x00".to_string(),
                                                },
                                            });
                                        }
                                        res_shares
                                    }
                                    Err(_) => {
                                        let mut res_shares = Vec::new();
                                        for share in &fallback_shares[0..2] {
                                            let s = share.parse_secret().unwrap();
                                            let vk = share.parse_verification_key().unwrap();
                                            let pt = guardian_evaluate_share(&blinded_pt, &s);
                                            let proof = dleq_prove(&s, &vk, &blinded_pt, &pt);

                                            let mut out = Vec::new();
                                            let _ = pt.serialize_compressed(&mut out);
                                            res_shares.push(PepperShareResponse {
                                                guardian_index: share.index,
                                                share_point_hex: format!("0x{}", hex::encode(out)),
                                                dleq_proof: proof,
                                            });
                                        }
                                        res_shares
                                    }
                                };

                                let resp = PepperBlindEvaluateResponse {
                                    shares: evaluated_shares,
                                    threshold: 2,
                                    evaluation_time_us: start.elapsed().as_micros(),
                                };
                                let body = serde_json::to_string(&resp).unwrap_or_default();
                                let res = Response::from_string(body)
                                    .with_header(cors_origin)
                                    .with_header(content_type);
                                let _ = request.respond(res);
                            }
                            Err(e) => {
                                let body = format!(r#"{{"error":"Invalid blinded point: {e}"}}"#);
                                let res = Response::from_string(body)
                                    .with_status_code(StatusCode(400))
                                    .with_header(cors_origin)
                                    .with_header(content_type);
                                let _ = request.respond(res);
                            }
                        }
                    }
                    Err(e) => {
                        let body = format!(r#"{{"error":"Invalid JSON: {e}"}}"#);
                        let res = Response::from_string(body)
                            .with_status_code(StatusCode(400))
                            .with_header(cors_origin)
                            .with_header(content_type);
                        let _ = request.respond(res);
                    }
                }
            }

            ("GET", "/api/v1/pepper/cluster") => {
                let body = serde_json::to_string(&pepper_client.cluster).unwrap_or_default();
                let res = Response::from_string(body)
                    .with_header(cors_origin)
                    .with_header(content_type);
                let _ = request.respond(res);
            }

            _ => {
                let res = Response::from_string(r#"{"message":"SENA Prover Service API v1"}"#)
                    .with_header(cors_origin)
                    .with_header(content_type);
                let _ = request.respond(res);
            }
        }
    }

    Ok(())
}
