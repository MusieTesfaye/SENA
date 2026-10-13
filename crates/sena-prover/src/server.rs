//! External Prover Service HTTP REST Server (tiny_http).
//!
//! Exposes production endpoints for generating and verifying Groth16 proofs.

use std::sync::Arc;
use std::time::Instant;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Response, Server, StatusCode};

use crate::odis::{OdisEvaluateRequest, OdisEvaluateResponse, OdisService};
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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol: &'static str,
    curve: &'static str,
    snark: &'static str,
    circuit: &'static str,
    universal_oidc: bool,
    social_connect: &'static str,
}

/// Runs the external Prover Service HTTP daemon on the specified port.
pub fn run_prover_server(prover: Arc<KeylessProver>, listen_addr: &str) -> Result<(), String> {
    let odis = Arc::new(OdisService::new_default());
    let server = Server::http(listen_addr)
        .map_err(|e| format!("Failed to bind Prover Service on {listen_addr}: {e}"))?;

    println!("⚡ [SENA Prover Service] Listening on http://{listen_addr}");
    println!("⚡ [SENA Prover Service] Endpoints:");
    println!("   POST http://{listen_addr}/api/v1/prove");
    println!("   POST http://{listen_addr}/api/v1/verify");
    println!("   POST http://{listen_addr}/api/v1/odis/evaluate");
    println!("   GET  http://{listen_addr}/api/v1/health");

    for mut request in server.incoming_requests() {
        let prover = prover.clone();
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
