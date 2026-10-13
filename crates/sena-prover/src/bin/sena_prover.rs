//! The SENA Prover Service CLI binary.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use clap::{Parser, Subcommand};
use sena_prover::{
    load_ceremony_keys, run_ceremony, run_prover_server, save_ceremony_keys, KeylessProver,
};

#[derive(Parser)]
#[command(name = "sena-prover")]
#[command(about = "SENA Production Groth16 Prover Daemon & Ceremony Manager", long_about = None)]
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
    }
}
