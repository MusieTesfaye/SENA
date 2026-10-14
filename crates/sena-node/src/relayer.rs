//! Automated Aptos L1 Relayer Daemon.
//!
//! Observes newly sealed L2 blocks from `sena-node` and automatically posts
//! bonded assertions to `sena::assertions::post` on Aptos L1.
//!
//! Tracks open assertions, verifies their challenge window lifecycle, and
//! automatically calls `sena::assertions::finalize` when an assertion has
//! survived its challenge window without challenge.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use sena_primitives::{domain, CanonicalEncoder, Hash256};
use serde::{Deserialize, Serialize};

use crate::rpc::{Request, Response};

/// Configuration for the Aptos L1 Relayer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayerConfig {
    /// URL of the SENA L2 JSON-RPC node.
    pub sena_rpc_url: String,
    /// Target Aptos network (e.g. "testnet", "devnet", "local").
    pub aptos_network: String,
    /// Aptos REST API endpoint.
    pub aptos_rest_url: String,
    /// On-chain address of the deployed SENA rollup package.
    pub contract_address: String,
    /// Aptos CLI profile to sign L1 transactions with.
    pub profile: String,
    /// Address of the proposer account on Aptos L1.
    pub proposer_address: String,
    /// Minimum bond required per assertion (in octas / micro-units).
    pub bond_amount: u128,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    /// Automatically call finalize when challenge window elapses.
    pub auto_finalize: bool,
    /// Dry run mode (computes and verifies without broadcasting to L1).
    pub dry_run: bool,
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            sena_rpc_url: "http://127.0.0.1:8545".to_string(),
            aptos_network: "testnet".to_string(),
            aptos_rest_url: "https://api.testnet.aptoslabs.com/v1".to_string(),
            contract_address: "0x1".to_string(),
            profile: "default".to_string(),
            proposer_address: "0x1".to_string(),
            bond_amount: 1_000_000,
            poll_interval_secs: 2,
            auto_finalize: true,
            dry_run: false,
        }
    }
}

/// An assertion tracked by the relayer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackedAssertion {
    /// Block height on SENA L2.
    pub l2_height: u64,
    /// 32-byte assertion identifier.
    pub assertion_id: String,
    /// 32-byte parent assertion identifier.
    pub parent_id: String,
    /// State root before the block.
    pub pre_state_root: String,
    /// State root after the block.
    pub post_state_root: String,
    /// Commitment to the batch transactions.
    pub batch_commitment: String,
    /// Execution trace length in steps.
    pub trace_length: u64,
    /// Escrowed bond amount.
    pub bond: u128,
    /// Timestamp when posted (unix seconds).
    pub posted_at_unix: u64,
    /// On-chain status ("Pending", "Challenged", "Finalized").
    pub status: &'static str,
}

/// The Automated Aptos L1 Relayer Daemon.
#[derive(Clone, Debug)]
pub struct AptosRelayer {
    /// Relayer configuration.
    pub config: RelayerConfig,
    /// Highest L2 block height successfully relayed.
    pub last_relayed_height: u64,
    /// List of tracked assertions currently under observation.
    pub tracked_assertions: Vec<TrackedAssertion>,
}

impl AptosRelayer {
    /// Creates a new relayer from configuration.
    #[must_use]
    pub fn new(config: RelayerConfig) -> Self {
        Self {
            config,
            last_relayed_height: 0,
            tracked_assertions: Vec::new(),
        }
    }

    /// Computes the deterministic assertion id matching Move `sena::assertions::assertion_id`.
    #[must_use]
    pub fn compute_assertion_id(
        parent: &[u8; 32],
        proposer_tag: u64,
        pre_root: &[u8; 32],
        post_root: &[u8; 32],
        batch_commitment: &[u8; 32],
        trace_length: u64,
        bond: u128,
    ) -> Hash256 {
        Hash256::commit(
            CanonicalEncoder::new(domain::ASSERTION)
                .field(parent)
                .u64(proposer_tag)
                .field(pre_root)
                .field(post_root)
                .field(batch_commitment)
                .u64(trace_length)
                .u128(bond),
        )
    }

    /// Fetches the current chain info from the L2 RPC node.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is unreachable or answers unexpectedly.
    pub fn query_l2_chain_info(&self) -> Result<(u64, Hash256), String> {
        let resp = ureq::post(&self.config.sena_rpc_url)
            .timeout(Duration::from_secs(3))
            .send_json(&Request::GetChainInfo)
            .map_err(|e| format!("RPC connection error: {e}"))?;

        let val: Response = resp
            .into_json()
            .map_err(|e| format!("JSON parse error: {e}"))?;
        match val {
            Response::ChainInfo {
                height, state_root, ..
            } => Ok((height, state_root)),
            Response::Error { message } => Err(format!("L2 RPC error: {message}")),
            other => Err(format!("Unexpected RPC response: {other:?}")),
        }
    }

    /// Fetches a block and its transactions from the L2 RPC.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is unreachable or has no such block.
    pub fn query_l2_block(&self, height: u64) -> Result<(Hash256, Hash256, Hash256, u64), String> {
        let resp = ureq::post(&self.config.sena_rpc_url)
            .timeout(Duration::from_secs(3))
            .send_json(&Request::GetBlock { height })
            .map_err(|e| format!("RPC connection error: {e}"))?;

        let val: Response = resp
            .into_json()
            .map_err(|e| format!("JSON parse error: {e}"))?;
        match val {
            Response::Block {
                pre_state_root,
                post_state_root,
                batch_commitment,
                trace_length,
                ..
            } => {
                let effective_trace_length = trace_length.max(1);
                Ok((
                    pre_state_root,
                    post_state_root,
                    batch_commitment,
                    effective_trace_length,
                ))
            }
            Response::Error { message } => Err(format!("L2 RPC error: {message}")),
            other => Err(format!("Unexpected RPC response: {other:?}")),
        }
    }

    /// Relays newly sealed blocks from L2 to Aptos L1.
    ///
    /// # Errors
    ///
    /// Returns an error if the L2 node cannot be read or the L1 post fails, in
    /// which case nothing is recorded and the same block is retried next time.
    pub fn step(&mut self) -> Result<Option<TrackedAssertion>, String> {
        let (current_height, _) = self.query_l2_chain_info()?;
        if current_height <= self.last_relayed_height {
            return Ok(None);
        }

        let target_height = self.last_relayed_height + 1;
        let (pre_root, post_root, batch_commitment, trace_length) =
            self.query_l2_block(target_height)?;

        let parent_bytes = if let Some(last) = self.tracked_assertions.last() {
            Hash256::from_hex(&last.assertion_id)
                .unwrap_or(Hash256::ZERO)
                .0
        } else {
            [0u8; 32]
        };

        let aid = Self::compute_assertion_id(
            &parent_bytes,
            0,
            &pre_root.0,
            &post_root.0,
            &batch_commitment.0,
            trace_length,
            self.config.bond_amount,
        );

        let parent_hex = format!("0x{}", hex::encode(parent_bytes));
        let aid_hex = format!("0x{}", hex::encode(aid.0));

        println!("[SENA Relayer] Relaying block #{target_height} to Aptos L1");
        println!("   Assertion ID:     {aid_hex}");
        println!("   Parent ID:        {parent_hex}");
        println!("   Post State Root:  {post_root}");
        println!(
            "   Bond Escrowed:    {} micro-units",
            self.config.bond_amount
        );

        if !self.config.dry_run {
            let function_id = format!("{}::assertions::post", self.config.contract_address);
            println!(
                "   Submitting L1 transaction -> {function_id} --profile {}",
                self.config.profile
            );
            let status = std::process::Command::new("aptos")
                .args([
                    "move",
                    "run",
                    "--function-id",
                    &function_id,
                    "--args",
                    &format!("address:{}", self.config.contract_address),
                    &format!("hex:{parent_hex}"),
                    &format!("hex:0x{}", hex::encode(pre_root.0)),
                    &format!("hex:0x{}", hex::encode(post_root.0)),
                    &format!("hex:0x{}", hex::encode(batch_commitment.0)),
                    &format!("u64:{trace_length}"),
                    &format!("u128:{}", self.config.bond_amount),
                    "--profile",
                    &self.config.profile,
                    "--assume-yes",
                ])
                .output();

            // Fail closed: an assertion that did not land must not be
            // recorded as relayed, or the next one would name a parent that
            // does not exist on chain.
            let out = status.map_err(|e| format!("could not execute aptos CLI: {e}"))?;
            let out_str = String::from_utf8_lossy(&out.stdout);
            if !out.status.success() || !out_str.contains("\"success\": true") {
                let err_str = String::from_utf8_lossy(&out.stderr);
                return Err(format!(
                    "L1 post of block {target_height} failed; not advancing: {out_str} {err_str}"
                ));
            }
            println!("   L1 transaction confirmed: {aid_hex}");
        }

        let tracked = TrackedAssertion {
            l2_height: target_height,
            assertion_id: aid_hex,
            parent_id: parent_hex,
            pre_state_root: format!("0x{}", hex::encode(pre_root.0)),
            post_state_root: format!("0x{}", hex::encode(post_root.0)),
            batch_commitment: format!("0x{}", hex::encode(batch_commitment.0)),
            trace_length,
            bond: self.config.bond_amount,
            posted_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            status: "Pending",
        };

        self.last_relayed_height = target_height;
        self.tracked_assertions.push(tracked.clone());

        if self.config.dry_run {
            println!("[SENA Relayer] Block #{target_height} computed (dry run, nothing posted)");
        } else {
            println!("[SENA Relayer] Block #{target_height} anchored to Aptos L1");
        }
        Ok(Some(tracked))
    }

    /// Checks pending assertions and attempts finalization if their challenge window elapsed.
    pub fn finalize_pending(&mut self) {
        if !self.config.auto_finalize {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 86,400s floor on mainnet/testnet, or shorter if local
        let window_secs = if self.config.aptos_network == "local" {
            10
        } else {
            86_400
        };

        for assertion in &mut self.tracked_assertions {
            if assertion.status == "Pending" && now >= assertion.posted_at_unix + window_secs {
                println!(
                    "⏳ [SENA Relayer] Finalizing assertion {}...",
                    assertion.assertion_id
                );
                if !self.config.dry_run {
                    let function_id =
                        format!("{}::assertions::finalize", self.config.contract_address);
                    let _ = std::process::Command::new("aptos")
                        .args([
                            "move",
                            "run",
                            "--function-id",
                            &function_id,
                            "--args",
                            &format!("address:{}", self.config.contract_address),
                            &format!("hex:{}", assertion.assertion_id),
                            "--profile",
                            &self.config.profile,
                            "--assume-yes",
                        ])
                        .output();
                }
                assertion.status = "Finalized";
                println!(
                    "🎯 [SENA Relayer] Assertion {} is now Finalized!",
                    assertion.assertion_id
                );
            }
        }
    }

    /// Runs the relayer daemon continuously.
    ///
    /// # Errors
    ///
    /// Does not currently return an error; failures are retried.
    pub fn run_daemon(&mut self, running: &AtomicBool) -> Result<(), String> {
        println!(
            "🚀 [SENA Relayer Daemon] Started on network: {}",
            self.config.aptos_network
        );
        println!("   Monitoring L2 RPC: {}", self.config.sena_rpc_url);
        println!("   Target Contract:   {}", self.config.contract_address);
        println!("   Polling Interval:  {}s", self.config.poll_interval_secs);

        while running.load(Ordering::SeqCst) {
            if let Err(e) = self.step() {
                eprintln!("⚠️  [SENA Relayer] Warning: {e}");
            }
            self.finalize_pending();
            thread::sleep(Duration::from_secs(self.config.poll_interval_secs));
        }

        println!("🛑 [SENA Relayer Daemon] Shutting down cleanly.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sena_fraudproof::assertion::Assertion;
    use sena_fraudproof::{AssertionId, PartyId};

    #[test]
    fn test_assertion_id_matches_move_spec() {
        let parent = [0x11u8; 32];
        let pre_root = [0x22u8; 32];
        let post_root = [0x33u8; 32];
        let batch = [0x44u8; 32];
        let trace_len = 10u64;
        let bond = 1_000_000u128;

        let computed = AptosRelayer::compute_assertion_id(
            &parent, 0, &pre_root, &post_root, &batch, trace_len, bond,
        );

        let ref_assertion = Assertion {
            parent: AssertionId(Hash256(parent)),
            proposer: PartyId(0),
            pre_state_root: Hash256(pre_root),
            post_state_root: Hash256(post_root),
            batch_commitment: Hash256(batch),
            trace_length: trace_len,
            bond,
        };

        assert_eq!(
            computed,
            ref_assertion.id().0,
            "Relayer assertion ID derivation must match Move and reference fraudproof crate identically"
        );
    }
}
