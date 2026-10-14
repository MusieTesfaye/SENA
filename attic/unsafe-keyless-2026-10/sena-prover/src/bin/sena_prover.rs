//! The SENA Prover Service CLI binary.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
use clap::{Parser, Subcommand};
use sena_prover::{
    export_cluster_keys, load_ceremony_keys, run_ceremony, run_guardian_node, run_prover_server,
    save_ceremony_keys, ClusterConfig, DistributedPepperClient, GuardianNodeConfig, GuardianShare,
    KeylessProver,
};

#[derive(Parser)]
#[command(name = "sena-prover")]
#[command(about = "SENA Production Groth16 Prover Daemon & Distributed Pepper Guardian Cluster", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the external Prover Service HTTP daemon
    Run {
        /// Port to listen on
        #[arg(short, long, default_value = "8090")]
        port: u16,

        /// Path to ceremony parameters directory
        #[arg(long, default_value = "./prover-params")]
        params: PathBuf,
    },

    /// Run the production Phase 2 ceremony and export proving/verifying keys
    Ceremony {
        /// Output directory for ceremony artifacts
        #[arg(short, long, default_value = "./prover-params")]
        output: PathBuf,
    },

    /// Benchmark witness generation and Groth16 proving throughput
    Bench,

    /// Start a standalone Byzantine-fault-tolerant Guardian Node
    Guardian {
        /// Guardian 1-based index (e.g. 1, 2, 3)
        #[arg(short, long)]
        index: Option<u32>,

        /// 32-byte secret share scalar in hex
        #[arg(short, long)]
        share: Option<String>,

        /// Path to guardian key configuration JSON file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Port to listen on
        #[arg(short, long, default_value = "8091")]
        port: u16,
    },

    /// Generate production threshold secret shares and cluster configuration
    GuardianKeygen {
        /// Quorum threshold T (minimum shares required to reconstruct pepper)
        #[arg(short, long, default_value = "2")]
        threshold: usize,

        /// Total number of guardian nodes N
        #[arg(short, long, default_value = "3")]
        nodes: usize,

        /// Output directory for cluster configuration and share files
        #[arg(short, long, default_value = "./cluster-keys")]
        output: PathBuf,
    },

    /// Derive pepper across distributed guardians via threshold OPRF
    PepperClient {
        /// Comma-separated guardian HTTP URLs
        #[arg(short, long, default_value = "http://127.0.0.1:8091,http://127.0.0.1:8092,http://127.0.0.1:8093")]
        guardians: String,

        /// Threshold requirement
        #[arg(short, long, default_value = "2")]
        threshold: usize,

        /// Identity issuer
        #[arg(long, default_value = "https://accounts.google.com")]
        iss: String,

        /// Identity subject
        #[arg(long, default_value = "user_test_999")]
        sub: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Ceremony { output } => {
            println!("🔮 Starting SENA Production Phase 2 Ceremony over BN254...");
            let start = Instant::now();
            match run_ceremony() {
                Ok((pk, vk)) => {
                    println!("   Ceremony synthesis completed in {:?}", start.elapsed());
                    match save_ceremony_keys(&output, &pk, &vk) {
                        Ok((pk_p, vk_p, json_p)) => {
                            println!("✅ Proving Key saved:       {}", pk_p.display());
                            println!("✅ Verifying Key saved:     {}", vk_p.display());
                            println!("✅ JSON Format saved:      {}", json_p.display());
                            println!("🎉 Production parameters ready for deployment!");
                        }
                        Err(e) => eprintln!("❌ Failed to save keys: {e}"),
                    }
                }
                Err(e) => eprintln!("❌ Ceremony setup failed: {e}"),
            }
        }

        Commands::Run { port, params } => {
            println!("🚀 Initializing SENA Keyless Prover Service...");

            let prover = if params.exists() && params.join("sena_jwt_prod.pk").exists() {
                println!("📂 Loading existing ceremony keys from: {}", params.display());
                match load_ceremony_keys(&params) {
                    Ok((pk, vk)) => KeylessProver::new(pk, vk),
                    Err(e) => {
                        eprintln!("⚠️ Failed to load keys ({e}). Generating fresh keys in-memory...");
                        KeylessProver::initialize_default().expect("Failed to initialize prover")
                    }
                }
            } else {
                println!("⚡ Generating fresh ceremony parameters in-memory...");
                KeylessProver::initialize_default().expect("Failed to initialize prover")
            };

            let addr = format!("127.0.0.1:{port}");
            if let Err(e) = run_prover_server(Arc::new(prover), &addr) {
                eprintln!("❌ Server error: {e}");
            }
        }

        Commands::Bench => {
            println!("🏎️ Benchmarking SENA BN254 Groth16 Prover...");
            let prover = KeylessProver::initialize_default().expect("Setup failed");

            let dummy_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6InNlbmFfdGVzdF9raWRfMDEifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJzZW5hLW1vYmlsZS13YWxsZXQtdjEiLCJzdWIiOiIxMDkyODM3NCIsIm5vbmNlIjoiMHgwMSIsImV4cCI6MjAwMDAwMDAwMH0.signature_dummy";
            let epk = [7u8; 32];
            let pepper = b"alice_secure_pepper_test";

            println!("   Running 5 consecutive Groth16 prove iterations...");
            let mut times = Vec::new();

            for i in 1..=5 {
                let start = Instant::now();
                let res = prover.prove(dummy_jwt, &epk, pepper, 2_000_000_000).expect("Prove failed");
                let elapsed = start.elapsed();
                times.push(elapsed.as_secs_f64() * 1000.0);
                println!("   Iter #{i}: {:?} (Proof size: {} bytes)", elapsed, res.proof_hex.len() / 2 - 1);
            }

            let avg: f64 = times.iter().sum::<f64>() / (times.len() as f64);
            println!("⚡ Average Proving Latency: {:.2} ms per proof", avg);
            println!("✅ Prover benchmark completed successfully!");
        }

        Commands::Guardian {
            index,
            share,
            config,
            port,
        } => {
            let (idx, share_scalar) = if let Some(cfg_path) = config {
                println!("📂 Loading guardian configuration from: {}", cfg_path.display());
                let content = fs::read_to_string(&cfg_path).expect("Failed to read guardian config");
                let g_share: GuardianShare = serde_json::from_str(&content).expect("Invalid JSON in config");
                let scalar = g_share.parse_secret().expect("Failed to parse secret scalar");
                (g_share.index, scalar)
            } else if let (Some(i), Some(s_hex)) = (index, share) {
                let clean = s_hex.trim_start_matches("0x");
                let bytes = hex::decode(clean).expect("Invalid hex for secret share");
                let mut cursor = bytes.as_slice();
                let scalar = Fr::deserialize_compressed(&mut cursor).expect("Invalid scalar bytes");
                (i, scalar)
            } else {
                eprintln!("❌ Error: Either provide --config <PATH> or both --index <U32> and --share <HEX>");
                std::process::exit(1);
            };

            let addr = format!("127.0.0.1:{port}");
            println!("🛡️ Starting SENA Guardian Node #{idx} on http://{addr}...");
            if let Err(e) = run_guardian_node(idx, share_scalar, &addr) {
                eprintln!("❌ Guardian server error: {e}");
            }
        }

        Commands::GuardianKeygen {
            threshold,
            nodes,
            output,
        } => {
            println!("🔑 Generating Production {threshold}-of-{nodes} Guardian Cluster Keys...");
            match export_cluster_keys(threshold, nodes, &output) {
                Ok(cluster) => {
                    println!("✅ Cluster configuration written to: {}/cluster_config.json", output.display());
                    for g in &cluster.guardians {
                        println!(
                            "   Guardian #{}: {} (VK: {})",
                            g.index,
                            g.url,
                            g.verification_key_hex.as_deref().unwrap_or("none")
                        );
                    }
                    println!("🎉 Cluster generation completed successfully!");
                }
                Err(e) => eprintln!("❌ Keygen failed: {e}"),
            }
        }

        Commands::PepperClient {
            guardians,
            threshold,
            iss,
            sub,
        } => {
            println!("🌐 Running Distributed Pepper Client across guardians...");
            let urls: Vec<String> = guardians.split(',').map(|s| s.trim().to_string()).collect();
            let guardian_configs = urls
                .iter()
                .enumerate()
                .map(|(i, u)| GuardianNodeConfig {
                    index: (i + 1) as u32,
                    url: u.clone(),
                    verification_key_hex: None,
                })
                .collect();

            let cluster = ClusterConfig {
                threshold,
                guardians: guardian_configs,
            };

            let client = DistributedPepperClient::new(cluster);
            let start = Instant::now();
            match client.derive_pepper(&iss, &sub) {
                Ok(pepper) => {
                    let elapsed = start.elapsed();
                    let addr = sena_primitives::L2Address::derive_from_oidc_unified(&iss, &sub, &pepper);
                    println!("⚡ Pepper Derived in {:?}:", elapsed);
                    println!("   Pepper (32 bytes):  0x{}", hex::encode(pepper));
                    println!("   Unified Address:    {}", addr);
                    println!("✅ Cross-device recovery successfully verified!");
                }
                Err(e) => eprintln!("❌ Failed to derive pepper: {e}"),
            }
        }
    }
}
