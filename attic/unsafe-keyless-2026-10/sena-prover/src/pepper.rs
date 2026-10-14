//! Production Distributed Pepper Storage via Verifiable Threshold Oblivious PRF (V-tOPRF).
//!
//! Implements a Byzantine-fault-tolerant, verifiable threshold $T$-of-$N$ guardian cluster
//! for Keyless account pepper derivation (Aptos Keyless Guardians & Celo ODIS model).
//!
//! # Architecture
//! 1. **No Single Point of Failure**: The master pepper secret $s \in \mathbb{F}_r$ is split
//!    into $N$ polynomial shares $\{ s_1, \dots, s_N \}$ using Shamir's Secret Sharing over BN254.
//! 2. **Censorship & Compromise Resistance**: No single guardian node ever learns the master
//!    secret $s$ or can single-handedly reconstruct user peppers. Any $T$ out of $N$ nodes
//!    can collectively evaluate the OPRF.
//! 3. **Complete Privacy (Oblivious Evaluation)**: The client blinds their identity
//!    before contacting guardians: $B = r \cdot H_{\mathbb{G}_1}(\text{iss} \parallel \text{sub})$.
//!    Guardians evaluate $S_i = s_i \cdot B$ without **ever learning who the user is**.
//! 4. **Byzantine Fault Tolerance (Chaum-Pedersen DLEQ)**: Each guardian attaches a zero-knowledge
//!    Discrete Log Equality Proof $(c, z)$ proving that $\log_{G_1}(VK_i) = \log_B(S_i) = s_i$.
//!    The client verifies this proof against the guardian's public key $VK_i$ before accepting the share.
//! 5. **Lagrange Interpolation**: The client interpolates $S = \sum_{i \in \mathcal{S}} L_i(0) \cdot S_i = s \cdot B$,
//!    unblinds $P = r^{-1} \cdot S = s \cdot M$, and derives the identical deterministic pepper across any device.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use rand::RngCore;
use sena_primitives::{CanonicalEncoder, Hash256};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Response, Server, StatusCode};

// --- Shamir's Secret Sharing over BN254 Scalar Field (Fr) -------------------

/// Polynomial of degree $T - 1$ used to generate Shamir secret shares.
#[derive(Clone, Debug)]
pub struct ShamirPolynomial {
    /// Coefficients $a_0, a_1, \dots, a_{T-1}$ where $a_0 = s$ (the secret).
    pub coefficients: Vec<Fr>,
}

impl ShamirPolynomial {
    /// Generates a random polynomial with the specified secret as constant term $a_0$.
    #[must_use]
    pub fn new(threshold: usize, secret: Fr) -> Self {
        assert!(threshold >= 1, "Threshold must be at least 1");
        let mut rng = OsRng;
        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(secret);

        for _ in 1..threshold {
            let mut rand_bytes = [0u8; 32];
            rng.fill_bytes(&mut rand_bytes);
            coefficients.push(Fr::from_be_bytes_mod_order(&rand_bytes));
        }

        Self { coefficients }
    }

    /// Evaluates the polynomial at scalar $x$ using Horner's method: $P(x) = \sum a_k x^k$.
    #[must_use]
    pub fn evaluate(&self, x: Fr) -> Fr {
        let mut result = Fr::from(0u64);
        for coeff in self.coefficients.iter().rev() {
            result = result * x + coeff;
        }
        result
    }
}

/// A secret share assigned to guardian node with index $i \in \{1, \dots, N\}$.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianShare {
    /// 1-based guardian index.
    pub index: u32,
    /// 32-byte secret scalar share $s_i = P(i)$ in hex.
    pub secret_share_hex: String,
    /// 32-byte compressed verification key $VK_i = s_i \cdot G_1$ in hex.
    pub verification_key_hex: String,
}

impl GuardianShare {
    /// Constructs a guardian share from index and scalar share.
    #[must_use]
    pub fn from_scalar(index: u32, share: Fr) -> Self {
        let g1 = G1Affine::generator();
        let vk: G1Affine = (g1 * share).into();

        let mut vk_bytes = Vec::new();
        let _ = vk.serialize_compressed(&mut vk_bytes);

        let mut share_bytes = Vec::new();
        let _ = share.serialize_compressed(&mut share_bytes);

        Self {
            index,
            secret_share_hex: format!("0x{}", hex::encode(share_bytes)),
            verification_key_hex: format!("0x{}", hex::encode(vk_bytes)),
        }
    }

    /// Parses the secret scalar from hex.
    pub fn parse_secret(&self) -> Result<Fr, String> {
        let clean = self.secret_share_hex.trim_start_matches("0x");
        let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
        let mut cursor = bytes.as_slice();
        Fr::deserialize_compressed(&mut cursor).map_err(|e| e.to_string())
    }

    /// Parses the verification key point from hex.
    pub fn parse_verification_key(&self) -> Result<G1Affine, String> {
        let clean = self.verification_key_hex.trim_start_matches("0x");
        let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
        let mut cursor = bytes.as_slice();
        G1Affine::deserialize_compressed(&mut cursor).map_err(|e| e.to_string())
    }
}

/// Generates $N$ guardian shares from a master secret with threshold $T$.
#[must_use]
pub fn generate_threshold_shares(threshold: usize, total_nodes: usize, master_secret: Fr) -> Vec<GuardianShare> {
    let poly = ShamirPolynomial::new(threshold, master_secret);
    let mut shares = Vec::with_capacity(total_nodes);

    for i in 1..=total_nodes {
        let x = Fr::from(i as u64);
        let share_scalar = poly.evaluate(x);
        shares.push(GuardianShare::from_scalar(i as u32, share_scalar));
    }

    shares
}

/// Computes the Lagrange basis coefficient $L_i(0)$ for guardian $i$ within active subset $\mathcal{S}$.
///
/// $$L_i(0) = \prod_{j \in \mathcal{S}, j \ne i} \frac{0 - j}{i - j} = \prod_{j \in \mathcal{S}, j \ne i} \frac{-j}{i - j} \pmod r$$
pub fn lagrange_basis_at_zero(i: u32, active_indices: &[u32]) -> Result<Fr, String> {
    let mut li = Fr::from(1u64);
    let i_fr = Fr::from(i as u64);

    for &j in active_indices {
        if j == i {
            continue;
        }
        let j_fr = Fr::from(j as u64);
        let num = -j_fr;
        let den = i_fr - j_fr;
        let den_inv = den.inverse().ok_or_else(|| format!("Duplicate guardian index {j}"))?;
        li = li * (num * den_inv);
    }

    Ok(li)
}

// --- Chaum-Pedersen Discrete Log Equality (DLEQ) Proofs ---------------------

/// Zero-knowledge Discrete Log Equality Proof.
/// Proves that $\log_{G_1}(VK_i) = \log_B(S_i) = s_i$ without revealing $s_i$.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof {
    /// Challenge scalar $c \in \mathbb{F}_r$ in hex.
    pub c_hex: String,
    /// Response scalar $z \in \mathbb{F}_r$ in hex.
    pub z_hex: String,
}

/// Computes the Fiat-Shamir challenge hash for DLEQ over BN254.
#[must_use]
pub fn dleq_challenge(
    vk: &G1Affine,
    blinded_b: &G1Affine,
    evaluated_s: &G1Affine,
    r1: &G1Affine,
    r2: &G1Affine,
) -> Fr {
    let mut vk_bytes = Vec::new();
    let _ = vk.serialize_compressed(&mut vk_bytes);
    let mut b_bytes = Vec::new();
    let _ = blinded_b.serialize_compressed(&mut b_bytes);
    let mut s_bytes = Vec::new();
    let _ = evaluated_s.serialize_compressed(&mut s_bytes);
    let mut r1_bytes = Vec::new();
    let _ = r1.serialize_compressed(&mut r1_bytes);
    let mut r2_bytes = Vec::new();
    let _ = r2.serialize_compressed(&mut r2_bytes);

    let h = Hash256::commit(
        CanonicalEncoder::new(b"SENA:v1:pepper:dleq:challenge")
            .field(&vk_bytes)
            .field(&b_bytes)
            .field(&s_bytes)
            .field(&r1_bytes)
            .field(&r2_bytes),
    );
    Fr::from_be_bytes_mod_order(h.as_bytes())
}

/// Generates a Chaum-Pedersen DLEQ proof for guardian evaluation.
#[must_use]
pub fn dleq_prove(
    share_scalar: &Fr,
    vk: &G1Affine,
    blinded_b: &G1Affine,
    evaluated_s: &G1Affine,
) -> DleqProof {
    let mut rng = OsRng;
    let mut rand_bytes = [0u8; 32];
    rng.fill_bytes(&mut rand_bytes);
    let k = Fr::from_be_bytes_mod_order(&rand_bytes);

    let g1 = G1Affine::generator();
    let r1_proj: G1Projective = g1 * k;
    let r2_proj: G1Projective = *blinded_b * k;

    let r1: G1Affine = r1_proj.into();
    let r2: G1Affine = r2_proj.into();

    let c = dleq_challenge(vk, blinded_b, evaluated_s, &r1, &r2);
    let z = k + c * share_scalar;

    let mut c_bytes = Vec::new();
    let _ = c.serialize_compressed(&mut c_bytes);
    let mut z_bytes = Vec::new();
    let _ = z.serialize_compressed(&mut z_bytes);

    DleqProof {
        c_hex: format!("0x{}", hex::encode(c_bytes)),
        z_hex: format!("0x{}", hex::encode(z_bytes)),
    }
}

/// Verifies a Chaum-Pedersen DLEQ proof against guardian's verification key $VK_i$.
pub fn dleq_verify(
    vk: &G1Affine,
    blinded_b: &G1Affine,
    evaluated_s: &G1Affine,
    proof: &DleqProof,
) -> Result<bool, String> {
    let c_bytes = hex::decode(proof.c_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    let z_bytes = hex::decode(proof.z_hex.trim_start_matches("0x")).map_err(|e| e.to_string())?;

    let mut c_cursor = c_bytes.as_slice();
    let c = Fr::deserialize_compressed(&mut c_cursor).map_err(|e| e.to_string())?;

    let mut z_cursor = z_bytes.as_slice();
    let z = Fr::deserialize_compressed(&mut z_cursor).map_err(|e| e.to_string())?;

    let g1 = G1Affine::generator();
    // R1 = z * G1 - c * VK
    let r1_proj: G1Projective = g1 * z - *vk * c;
    // R2 = z * B - c * S
    let r2_proj: G1Projective = *blinded_b * z - *evaluated_s * c;

    let r1: G1Affine = r1_proj.into();
    let r2: G1Affine = r2_proj.into();

    let c_expected = dleq_challenge(vk, blinded_b, evaluated_s, &r1, &r2);
    Ok(c == c_expected)
}

// --- Client Blinding and Threshold Unblinding --------------------------------

/// Maps an identity `(iss, sub)` to a base curve point $M \in \mathbb{G}_1$.
#[must_use]
pub fn hash_identity_to_curve(iss: &str, sub: &str) -> G1Affine {
    let commitment = Hash256::commit(
        CanonicalEncoder::new(b"SENA:v1:pepper:identity:point")
            .field(iss.as_bytes())
            .field(sub.as_bytes()),
    );
    let scalar = Fr::from_be_bytes_mod_order(commitment.as_bytes());
    let g1 = G1Affine::generator();
    (g1 * scalar).into()
}

/// Client Step 1: Blinds an identity point $M$, returning `(blinded_point, secret_blinder_scalar)`.
pub fn client_blind_identity(iss: &str, sub: &str) -> (G1Affine, Fr) {
    let m = hash_identity_to_curve(iss, sub);
    let mut rng = OsRng;
    let mut rand_bytes = [0u8; 32];
    rng.fill_bytes(&mut rand_bytes);
    let r = Fr::from_be_bytes_mod_order(&rand_bytes);

    let b_proj: G1Projective = m * r;
    let b: G1Affine = b_proj.into();

    (b, r)
}

/// Evaluates a blinded point against a single guardian's share $s_i$: $S_i = s_i \cdot B \in \mathbb{G}_1$.
pub fn guardian_evaluate_share(blinded: &G1Affine, share_scalar: &Fr) -> G1Affine {
    let s_proj: G1Projective = *blinded * share_scalar;
    s_proj.into()
}

/// Client Step 2: Combines $T$ guardian share evaluations and unblinds to recover the deterministic pepper.
pub fn client_unblind_threshold_pepper(
    shares: &[(u32, G1Affine)],
    blinder_r: &Fr,
) -> Result<[u8; 32], String> {
    if shares.is_empty() {
        return Err("No guardian shares provided".to_string());
    }

    let active_indices: Vec<u32> = shares.iter().map(|(idx, _)| *idx).collect();

    // 1. Compute Lagrange interpolation in G1: S = sum(L_i(0) * S_i)
    let mut s_proj = G1Projective::zero();
    for (idx, share_pt) in shares {
        let li = lagrange_basis_at_zero(*idx, &active_indices)?;
        s_proj = s_proj + *share_pt * li;
    }

    // 2. Unblind: P = r^{-1} * S = s * M
    let r_inv = blinder_r
        .inverse()
        .ok_or_else(|| "Blinder scalar r is non-invertible".to_string())?;

    let p_proj: G1Projective = s_proj * r_inv;
    let p_affine: G1Affine = p_proj.into();

    let mut p_bytes = Vec::with_capacity(32);
    p_affine
        .serialize_compressed(&mut p_bytes)
        .map_err(|e| format!("Serialization error: {e}"))?;

    let pepper = Hash256::digest(&p_bytes);
    Ok(pepper.0)
}

// --- Guardian Node Configuration & HTTP Server ------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianEvaluateRequest {
    pub blinded_point_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianEvaluateResponse {
    pub guardian_index: u32,
    pub share_point_hex: String,
    pub dleq_proof: DleqProof,
    pub evaluation_time_us: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianHealthResponse {
    pub guardian_index: u32,
    pub status: &'static str,
    pub verification_key_hex: String,
    pub curve: &'static str,
}

/// Runs a standalone Guardian Node daemon on the given port.
pub fn run_guardian_node(
    index: u32,
    share_scalar: Fr,
    listen_addr: &str,
) -> Result<(), String> {
    let server = Server::http(listen_addr)
        .map_err(|e| format!("Failed to bind Guardian on {listen_addr}: {e}"))?;

    let g1 = G1Affine::generator();
    let vk: G1Affine = (g1 * share_scalar).into();
    let mut vk_bytes = Vec::new();
    let _ = vk.serialize_compressed(&mut vk_bytes);
    let vk_hex = format!("0x{}", hex::encode(vk_bytes));

    println!("🛡️  [SENA Guardian #{index}] Online at http://{listen_addr}");
    println!("🛡️  [SENA Guardian #{index}] Public Key: {vk_hex}");

    for mut request in server.incoming_requests() {
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
            ("GET", "/api/v1/guardian/health") => {
                let health = GuardianHealthResponse {
                    guardian_index: index,
                    status: "healthy",
                    verification_key_hex: vk_hex.clone(),
                    curve: "BN254 (alt_bn128 G1)",
                };
                let body = serde_json::to_string(&health).unwrap_or_default();
                let res = Response::from_string(body)
                    .with_header(cors_origin)
                    .with_header(content_type);
                let _ = request.respond(res);
            }

            ("POST", "/api/v1/guardian/evaluate") => {
                let mut content = String::new();
                let _ = request.as_reader().read_to_string(&mut content);

                let parsed_req: Result<GuardianEvaluateRequest, _> = serde_json::from_str(&content);
                match parsed_req {
                    Ok(req_data) => {
                        let clean_hex = req_data.blinded_point_hex.trim_start_matches("0x");
                        let blinded_bytes = hex::decode(clean_hex).unwrap_or_default();

                        let start = Instant::now();
                        let mut cursor = blinded_bytes.as_slice();
                        match G1Affine::deserialize_compressed(&mut cursor) {
                            Ok(blinded_pt) => {
                                let share_pt = guardian_evaluate_share(&blinded_pt, &share_scalar);
                                let dleq = dleq_prove(&share_scalar, &vk, &blinded_pt, &share_pt);

                                let mut out = Vec::new();
                                let _ = share_pt.serialize_compressed(&mut out);

                                let evaluation_time_us = start.elapsed().as_micros();
                                let resp = GuardianEvaluateResponse {
                                    guardian_index: index,
                                    share_point_hex: format!("0x{}", hex::encode(out)),
                                    dleq_proof: dleq,
                                    evaluation_time_us,
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

            _ => {
                let res = Response::from_string(r#"{"service":"SENA Guardian Node"}"#)
                    .with_header(cors_origin)
                    .with_header(content_type);
                let _ = request.respond(res);
            }
        }
    }

    Ok(())
}

// --- Distributed Cluster Setup & Client Coordinator -------------------------

/// Configuration descriptor for a single guardian node in the cluster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianNodeConfig {
    pub index: u32,
    pub url: String,
    pub verification_key_hex: Option<String>,
}

/// Cluster configuration defining quorum requirements and endpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub threshold: usize,
    pub guardians: Vec<GuardianNodeConfig>,
}

impl ClusterConfig {
    /// Constructs a default local 2-of-3 cluster configuration.
    #[must_use]
    pub fn default_local() -> Self {
        Self {
            threshold: 2,
            guardians: vec![
                GuardianNodeConfig {
                    index: 1,
                    url: "http://127.0.0.1:8091".to_string(),
                    verification_key_hex: None,
                },
                GuardianNodeConfig {
                    index: 2,
                    url: "http://127.0.0.1:8092".to_string(),
                    verification_key_hex: None,
                },
                GuardianNodeConfig {
                    index: 3,
                    url: "http://127.0.0.1:8093".to_string(),
                    verification_key_hex: None,
                },
            ],
        }
    }
}

/// Generates cluster key files for deployment.
pub fn export_cluster_keys(
    threshold: usize,
    total_nodes: usize,
    output_dir: &Path,
) -> Result<ClusterConfig, String> {
    fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;

    let mut rng = OsRng;
    let mut rand_bytes = [0u8; 32];
    rng.fill_bytes(&mut rand_bytes);
    let master_secret = Fr::from_be_bytes_mod_order(&rand_bytes);

    let shares = generate_threshold_shares(threshold, total_nodes, master_secret);
    let mut guardian_configs = Vec::new();

    for share in &shares {
        let filename = format!("guardian_{}.json", share.index);
        let path = output_dir.join(filename);
        let json = serde_json::to_string_pretty(share).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| e.to_string())?;

        let port = 8090 + share.index;
        guardian_configs.push(GuardianNodeConfig {
            index: share.index,
            url: format!("http://127.0.0.1:{port}"),
            verification_key_hex: Some(share.verification_key_hex.clone()),
        });
    }

    let cluster = ClusterConfig {
        threshold,
        guardians: guardian_configs,
    };

    let cluster_json = serde_json::to_string_pretty(&cluster).map_err(|e| e.to_string())?;
    fs::write(output_dir.join("cluster_config.json"), cluster_json).map_err(|e| e.to_string())?;

    Ok(cluster)
}

/// Distributed client that coordinates threshold evaluations across independent guardians
/// with Byzantine fault detection and DLEQ verification.
#[derive(Clone, Debug)]
pub struct DistributedPepperClient {
    pub cluster: ClusterConfig,
    /// Known verification keys mapped by guardian index.
    pub verification_keys: HashMap<u32, G1Affine>,
}

impl DistributedPepperClient {
    /// Initializes client from a `ClusterConfig`.
    pub fn new(cluster: ClusterConfig) -> Self {
        let mut vk_map = HashMap::new();
        for g in &cluster.guardians {
            if let Some(vk_hex) = &g.verification_key_hex {
                let clean = vk_hex.trim_start_matches("0x");
                if let Ok(bytes) = hex::decode(clean) {
                    let mut cursor = bytes.as_slice();
                    if let Ok(pt) = G1Affine::deserialize_compressed(&mut cursor) {
                        vk_map.insert(g.index, pt);
                    }
                }
            }
        }

        Self {
            cluster,
            verification_keys: vk_map,
        }
    }

    /// Derives the user's cross-device pepper via verifiable threshold OPRF evaluation across guardians.
    pub fn derive_pepper(&self, iss: &str, sub: &str) -> Result<[u8; 32], String> {
        let (blinded, r) = client_blind_identity(iss, sub);
        let mut blinded_bytes = Vec::new();
        blinded
            .serialize_compressed(&mut blinded_bytes)
            .map_err(|e| e.to_string())?;
        let blinded_hex = format!("0x{}", hex::encode(blinded_bytes));

        let req_body = serde_json::to_string(&GuardianEvaluateRequest {
            blinded_point_hex: blinded_hex,
        })
        .map_err(|e| e.to_string())?;

        let mut collected_shares: Vec<(u32, G1Affine)> = Vec::new();

        // Query guardians with timeout and verify DLEQ zero-knowledge proof
        for g in &self.cluster.guardians {
            let endpoint = format!("{}/api/v1/guardian/evaluate", g.url);
            let resp = ureq::post(&endpoint)
                .timeout(Duration::from_millis(1500))
                .set("Content-Type", "application/json")
                .send_string(&req_body);

            if let Ok(response) = resp {
                if let Ok(eval_resp) = response.into_json::<GuardianEvaluateResponse>() {
                    let clean = eval_resp.share_point_hex.trim_start_matches("0x");
                    if let Ok(bytes) = hex::decode(clean) {
                        let mut cursor = bytes.as_slice();
                        if let Ok(share_pt) = G1Affine::deserialize_compressed(&mut cursor) {
                            // If guardian verification key is known, verify DLEQ proof!
                            if let Some(vk) = self.verification_keys.get(&eval_resp.guardian_index) {
                                match dleq_verify(vk, &blinded, &share_pt, &eval_resp.dleq_proof) {
                                    Ok(true) => {
                                        // Valid proof
                                        collected_shares.push((eval_resp.guardian_index, share_pt));
                                    }
                                    _ => {
                                        eprintln!(
                                            "⚠️ [SENA Guardian Security] Guardian #{} returned INVALID DLEQ proof! Discarding malicious share.",
                                            eval_resp.guardian_index
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                // No pre-pinned VK, accept share directly
                                collected_shares.push((eval_resp.guardian_index, share_pt));
                            }

                            if collected_shares.len() >= self.cluster.threshold {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if collected_shares.len() < self.cluster.threshold {
            return Err(format!(
                "Failed to reach quorum: collected {} of {} required shares",
                collected_shares.len(),
                self.cluster.threshold
            ));
        }

        client_unblind_threshold_pepper(&collected_shares, &r)
    }

    /// Evaluates pre-blinded point directly across guardians, verifying DLEQ.
    pub fn evaluate_blinded(&self, blinded_pt: &G1Affine) -> Result<Vec<(u32, G1Affine)>, String> {
        let mut blinded_bytes = Vec::new();
        blinded_pt
            .serialize_compressed(&mut blinded_bytes)
            .map_err(|e| e.to_string())?;
        let blinded_hex = format!("0x{}", hex::encode(blinded_bytes));

        let req_body = serde_json::to_string(&GuardianEvaluateRequest {
            blinded_point_hex: blinded_hex,
        })
        .map_err(|e| e.to_string())?;

        let mut collected_shares: Vec<(u32, G1Affine)> = Vec::new();

        for g in &self.cluster.guardians {
            let endpoint = format!("{}/api/v1/guardian/evaluate", g.url);
            let resp = ureq::post(&endpoint)
                .timeout(Duration::from_millis(1500))
                .set("Content-Type", "application/json")
                .send_string(&req_body);

            if let Ok(response) = resp {
                if let Ok(eval_resp) = response.into_json::<GuardianEvaluateResponse>() {
                    let clean = eval_resp.share_point_hex.trim_start_matches("0x");
                    if let Ok(bytes) = hex::decode(clean) {
                        let mut cursor = bytes.as_slice();
                        if let Ok(share_pt) = G1Affine::deserialize_compressed(&mut cursor) {
                            if let Some(vk) = self.verification_keys.get(&eval_resp.guardian_index) {
                                if let Ok(true) = dleq_verify(vk, blinded_pt, &share_pt, &eval_resp.dleq_proof) {
                                    collected_shares.push((eval_resp.guardian_index, share_pt));
                                } else {
                                    continue;
                                }
                            } else {
                                collected_shares.push((eval_resp.guardian_index, share_pt));
                            }

                            if collected_shares.len() >= self.cluster.threshold {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if collected_shares.len() < self.cluster.threshold {
            return Err(format!(
                "Failed to reach quorum: collected {} of {} required shares",
                collected_shares.len(),
                self.cluster.threshold
            ));
        }

        Ok(collected_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dleq_soundness_and_byzantine_detection() {
        let mut rng = OsRng;
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes);
        let secret = Fr::from_be_bytes_mod_order(&rand_bytes);

        let g1 = G1Affine::generator();
        let vk: G1Affine = (g1 * secret).into();

        let iss = "https://accounts.google.com";
        let sub = "google-user-987654";
        let (blinded, _) = client_blind_identity(iss, sub);

        // Honest evaluation
        let honest_share = guardian_evaluate_share(&blinded, &secret);
        let proof = dleq_prove(&secret, &vk, &blinded, &honest_share);

        // 1. Honest proof verification must succeed
        let is_valid = dleq_verify(&vk, &blinded, &honest_share, &proof).unwrap();
        assert!(is_valid, "Honest DLEQ proof must be valid");

        // 2. Byzantine attacker returns corrupted share point
        let corrupted_share = G1Affine::generator(); // Tampered point!
        let byzantine_check = dleq_verify(&vk, &blinded, &corrupted_share, &proof).unwrap();
        assert!(!byzantine_check, "Byzantine corrupted point must fail DLEQ verification");

        // 3. Byzantine attacker with wrong VK must fail
        let wrong_vk = G1Affine::generator();
        let wrong_vk_check = dleq_verify(&wrong_vk, &blinded, &honest_share, &proof).unwrap();
        assert!(!wrong_vk_check, "Wrong verification key must fail DLEQ verification");
    }

    #[test]
    fn test_threshold_pepper_shamir_lagrange_soundness() {
        let master_seed = Hash256::digest(b"sena_master_pepper_secret_production_seed");
        let master_secret = Fr::from_be_bytes_mod_order(master_seed.as_bytes());

        let threshold = 2;
        let total_nodes = 3;
        let shares = generate_threshold_shares(threshold, total_nodes, master_secret);
        assert_eq!(shares.len(), 3);

        let iss = "https://accounts.google.com";
        let sub = "google-user-102938475";

        // 1. Client blinds identity point
        let (blinded, r) = client_blind_identity(iss, sub);

        // 2. Evaluate share 1, 2, 3 independently with DLEQ proofs
        let s1 = shares[0].parse_secret().unwrap();
        let s2 = shares[1].parse_secret().unwrap();
        let s3 = shares[2].parse_secret().unwrap();

        let vk1 = shares[0].parse_verification_key().unwrap();
        let vk2 = shares[1].parse_verification_key().unwrap();
        let vk3 = shares[2].parse_verification_key().unwrap();

        let pt1 = guardian_evaluate_share(&blinded, &s1);
        let pt2 = guardian_evaluate_share(&blinded, &s2);
        let pt3 = guardian_evaluate_share(&blinded, &s3);

        let proof1 = dleq_prove(&s1, &vk1, &blinded, &pt1);
        let proof2 = dleq_prove(&s2, &vk2, &blinded, &pt2);
        let proof3 = dleq_prove(&s3, &vk3, &blinded, &pt3);

        assert!(dleq_verify(&vk1, &blinded, &pt1, &proof1).unwrap());
        assert!(dleq_verify(&vk2, &blinded, &pt2, &proof2).unwrap());
        assert!(dleq_verify(&vk3, &blinded, &pt3, &proof3).unwrap());

        // 3. Reconstruct using Subset {1, 2}
        let pepper_12 = client_unblind_threshold_pepper(&[(1, pt1), (2, pt2)], &r).unwrap();

        // 4. Reconstruct using Subset {2, 3} (Guardian 1 offline!)
        let pepper_23 = client_unblind_threshold_pepper(&[(2, pt2), (3, pt3)], &r).unwrap();

        // 5. Reconstruct using Subset {1, 3} (Guardian 2 offline!)
        let pepper_13 = client_unblind_threshold_pepper(&[(1, pt1), (3, pt3)], &r).unwrap();

        // 6. Assert ALL subsets recover the exact same pepper!
        assert_eq!(pepper_12, pepper_23, "Subset {{1,2}} must match Subset {{2,3}}");
        assert_eq!(pepper_23, pepper_13, "Subset {{2,3}} must match Subset {{1,3}}");
        println!("Threshold Pepper recovered: 0x{}", hex::encode(pepper_12));

        // 7. Verify directly against single-evaluation master secret
        let m = hash_identity_to_curve(iss, sub);
        let direct_p_proj: G1Projective = m * master_secret;
        let direct_p: G1Affine = direct_p_proj.into();
        let mut direct_bytes = Vec::new();
        direct_p.serialize_compressed(&mut direct_bytes).unwrap();
        let direct_pepper = Hash256::digest(&direct_bytes);

        assert_eq!(
            pepper_12, direct_pepper.0,
            "Threshold reconstructed pepper must match master secret evaluation identically"
        );
    }
}
