//! Talking to the SENA contracts on Aptos L1.
//!
//! Everything the relayer and the watcher do on L1 goes through the [`L1`]
//! trait: submit an entry function, call a view, read the clock, and read the
//! batch data an assertion published. [`AptosCli`] implements it with the
//! Aptos CLI (for signing and submitting, so keys stay in the operator's
//! Aptos profile) and the fullnode REST API (for reading events). Tests use an
//! in-memory implementation.

use std::process::Command;
use std::time::Duration;

use sena_fraudproof::{Assertion, AssertionId, PartyId};
use sena_primitives::Hash256;
use serde_json::{json, Value};

/// One argument to an entry or view function.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Arg {
    /// An account address, `0x`-prefixed hex.
    Address(String),
    /// `vector<u8>`.
    Bytes(Vec<u8>),
    /// `vector<vector<u8>>`.
    BytesList(Vec<Vec<u8>>),
    /// `u8`.
    U8(u8),
    /// `u64`.
    U64(u64),
    /// `vector<u64>`.
    U64List(Vec<u64>),
    /// `u128`.
    U128(u128),
    /// `bool`.
    Bool(bool),
}

impl Arg {
    /// The argument in the Aptos CLI's `--json-file` format.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
        match self {
            Self::Address(a) => json!({"type": "address", "value": a}),
            Self::Bytes(b) => json!({"type": "hex", "value": hx(b)}),
            Self::BytesList(l) => {
                json!({"type": "hex", "value": l.iter().map(|b| hx(b)).collect::<Vec<_>>()})
            }
            Self::U8(v) => json!({"type": "u8", "value": v}),
            Self::U64(v) => json!({"type": "u64", "value": v.to_string()}),
            Self::U64List(l) => {
                json!({"type": "u64", "value": l.iter().map(u64::to_string).collect::<Vec<_>>()})
            }
            Self::U128(v) => json!({"type": "u128", "value": v.to_string()}),
            Self::Bool(v) => json!({"type": "bool", "value": v}),
        }
    }
}

/// Why an L1 interaction failed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum L1Error {
    /// The transport or the CLI failed before L1 answered.
    #[error("could not reach L1: {0}")]
    Transport(String),
    /// The transaction executed and aborted, or failed validation.
    #[error("L1 rejected {function}: {status}")]
    Rejected {
        /// The entry function.
        function: String,
        /// The VM status Aptos reported.
        status: String,
    },
    /// L1 answered with something this client does not understand.
    #[error("unexpected L1 response: {0}")]
    Malformed(String),
}

impl L1Error {
    /// Whether the failure is a Move abort with code `code`. The CLI reports
    /// aborts as `Move abort in <module>: <NAME>(0x<code>): ...`.
    #[must_use]
    pub fn is_abort(&self, code: u64) -> bool {
        matches!(self, Self::Rejected { status, .. } if status.contains(&format!("(0x{code:x})")))
    }
}

/// The batch data an assertion published on L1.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublishedBatch {
    /// The assertion it belongs to.
    pub assertion: Vec<u8>,
    /// The batch timestamp.
    pub timestamp: u64,
    /// The transactions, canonically encoded.
    pub tx_bytes: Vec<Vec<u8>>,
    /// Each transaction's start position in the trace.
    pub tx_starts: Vec<u64>,
}

/// An assertion as `sena::assertions::record` reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// Its parent's id.
    pub parent: Vec<u8>,
    /// Its proposer.
    pub proposer: String,
    /// State root before.
    pub pre_state_root: Hash256,
    /// Claimed state root after.
    pub post_state_root: Hash256,
    /// Batch timestamp.
    pub timestamp: u64,
    /// Number of transactions.
    pub tx_count: u64,
    /// Batch root.
    pub tx_root: Hash256,
    /// Claimed trace length.
    pub trace_length: u64,
    /// Bond posted.
    pub bond: u128,
    /// L1 time it was posted.
    pub posted_at: u64,
    /// 0 pending, 1 challenged, 2 finalized, 3 rejected.
    pub status: u8,
}

/// Assertion statuses, as `sena::assertions` numbers them.
pub mod status {
    /// Open to challenge.
    pub const PENDING: u8 = 0;
    /// Under challenge.
    pub const CHALLENGED: u8 = 1;
    /// Final.
    pub const FINALIZED: u8 = 2;
    /// Overturned.
    pub const REJECTED: u8 = 3;
}

/// A dispute as `sena::disputes::dispute_state` reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DisputeState {
    /// Whether it exists.
    pub exists: bool,
    /// 0 bisecting, 1 one-step, 2 resolved.
    pub stage: u8,
    /// 0 defender, 1 challenger.
    pub turn: u8,
    /// Interval start.
    pub lo: u64,
    /// Interval end.
    pub hi: u64,
    /// Whether the defender's dissection is waiting for a selection.
    pub has_offer: bool,
    /// The dissection on offer.
    pub offered: Vec<Hash256>,
    /// When the party to move must move by.
    pub deadline: u64,
}

/// What the relayer and watcher need from L1.
pub trait L1 {
    /// Submits an entry function, e.g. `"assertions::post"`, signed by the
    /// client's own account. Returns the gas used.
    ///
    /// # Errors
    ///
    /// Returns [`L1Error`] if it does not execute successfully.
    fn submit(&self, function: &str, args: &[Arg]) -> Result<u64, L1Error>;

    /// Calls a view function, returning its results.
    ///
    /// # Errors
    ///
    /// Returns [`L1Error`] if the call fails.
    fn view(&self, function: &str, args: &[Arg]) -> Result<Vec<Value>, L1Error>;

    /// L1's current time, in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`L1Error`] if L1 cannot be reached.
    fn now(&self) -> Result<u64, L1Error>;

    /// The batch data published for `assertion`, found among `proposer`'s
    /// transactions.
    ///
    /// # Errors
    ///
    /// Returns [`L1Error`] if L1 cannot be read; `Ok(None)` if not found.
    fn published_batch(
        &self,
        proposer: &str,
        assertion: &[u8],
    ) -> Result<Option<PublishedBatch>, L1Error>;

    /// This client's own account address.
    fn address(&self) -> String;

    /// The address the SENA contracts (and their resources) live at.
    fn contract(&self) -> String;
}

// --- Decoding view results -----------------------------------------------------

fn as_str(v: &Value) -> Result<&str, L1Error> {
    v.as_str().ok_or_else(|| L1Error::Malformed(v.to_string()))
}

/// Parses a `0x`-hex view result.
///
/// # Errors
///
/// Returns [`L1Error::Malformed`] if it is not hex.
pub fn bytes_of(v: &Value) -> Result<Vec<u8>, L1Error> {
    let s = as_str(v)?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| L1Error::Malformed(e.to_string()))
}

fn hash_of(v: &Value) -> Result<Hash256, L1Error> {
    let b = bytes_of(v)?;
    b.try_into()
        .map(Hash256)
        .map_err(|_| L1Error::Malformed("expected 32 bytes".into()))
}

/// Parses a numeric view result (Aptos encodes u64/u128 as strings).
///
/// # Errors
///
/// Returns [`L1Error::Malformed`] if it is not a number.
pub fn u128_of(v: &Value) -> Result<u128, L1Error> {
    match v {
        Value::String(s) => s.parse().map_err(|_| L1Error::Malformed(s.clone())),
        Value::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| L1Error::Malformed(n.to_string())),
        other => Err(L1Error::Malformed(other.to_string())),
    }
}

fn u64_of(v: &Value) -> Result<u64, L1Error> {
    u64::try_from(u128_of(v)?).map_err(|_| L1Error::Malformed(v.to_string()))
}

fn bool_of(v: &Value) -> Result<bool, L1Error> {
    v.as_bool().ok_or_else(|| L1Error::Malformed(v.to_string()))
}

/// Parses `sena::assertions::record`.
///
/// # Errors
///
/// Returns [`L1Error::Malformed`] on an unexpected shape.
pub fn parse_record(v: &[Value]) -> Result<Record, L1Error> {
    if v.len() != 11 {
        return Err(L1Error::Malformed(format!("record has {} fields", v.len())));
    }
    Ok(Record {
        parent: bytes_of(&v[0])?,
        proposer: as_str(&v[1])?.to_owned(),
        pre_state_root: hash_of(&v[2])?,
        post_state_root: hash_of(&v[3])?,
        timestamp: u64_of(&v[4])?,
        tx_count: u64_of(&v[5])?,
        tx_root: hash_of(&v[6])?,
        trace_length: u64_of(&v[7])?,
        bond: u128_of(&v[8])?,
        posted_at: u64_of(&v[9])?,
        status: u8::try_from(u64_of(&v[10])?).map_err(|_| L1Error::Malformed("status".into()))?,
    })
}

/// Parses `sena::disputes::dispute_state`.
///
/// # Errors
///
/// Returns [`L1Error::Malformed`] on an unexpected shape.
pub fn parse_dispute(v: &[Value]) -> Result<DisputeState, L1Error> {
    if v.len() != 8 {
        return Err(L1Error::Malformed(format!(
            "dispute state has {} fields",
            v.len()
        )));
    }
    let offered = v[6]
        .as_array()
        .ok_or_else(|| L1Error::Malformed(v[6].to_string()))?
        .iter()
        .map(hash_of)
        .collect::<Result<_, _>>()?;
    Ok(DisputeState {
        exists: bool_of(&v[0])?,
        stage: u8::try_from(u64_of(&v[1])?).map_err(|_| L1Error::Malformed("stage".into()))?,
        turn: u8::try_from(u64_of(&v[2])?).map_err(|_| L1Error::Malformed("turn".into()))?,
        lo: u64_of(&v[3])?,
        hi: u64_of(&v[4])?,
        has_offer: bool_of(&v[5])?,
        offered,
        deadline: u64_of(&v[7])?,
    })
}

/// Parses a `BatchPublished` event's data.
///
/// # Errors
///
/// Returns [`L1Error::Malformed`] on an unexpected shape.
pub fn parse_batch_event(data: &Value) -> Result<PublishedBatch, L1Error> {
    let list = |k: &str| -> Result<&Vec<Value>, L1Error> {
        data[k]
            .as_array()
            .ok_or_else(|| L1Error::Malformed(format!("event field {k}")))
    };
    Ok(PublishedBatch {
        assertion: bytes_of(&data["assertion"])?,
        timestamp: u64_of(&data["timestamp"])?,
        tx_bytes: list("tx_bytes")?
            .iter()
            .map(bytes_of)
            .collect::<Result<_, _>>()?,
        tx_starts: list("tx_starts")?
            .iter()
            .map(u64_of)
            .collect::<Result<_, _>>()?,
    })
}

/// The id of the `index`th assertion posted (`sena::assertions::assertion_at`);
/// index 0 is genesis.
///
/// # Errors
///
/// Returns [`L1Error`] if the view fails.
pub fn assertion_at<C: L1 + ?Sized>(l1: &C, index: u64) -> Result<Vec<u8>, L1Error> {
    let v = l1.view(
        "assertions::assertion_at",
        &[Arg::Address(l1.contract()), Arg::U64(index)],
    )?;
    bytes_of(
        v.first()
            .ok_or_else(|| L1Error::Malformed("assertion_at".into()))?,
    )
}

// --- Identifiers shared with Move -------------------------------------------------

/// An assertion's id exactly as `sena::assertions::assertion_id` computes it
/// (the proposer tag is always zero on L1).
#[must_use]
pub fn assertion_id(
    parent: &[u8; 32],
    pre: Hash256,
    post: Hash256,
    batch_commitment: Hash256,
    trace_length: u64,
    bond: u128,
) -> [u8; 32] {
    Assertion {
        parent: AssertionId(Hash256(*parent)),
        proposer: PartyId(0),
        pre_state_root: pre,
        post_state_root: post,
        batch_commitment,
        trace_length,
        bond,
    }
    .id()
    .0
     .0
}

/// The id `sena::assertions::initialize` gives the genesis assertion.
#[must_use]
pub fn genesis_id(genesis_root: Hash256) -> [u8; 32] {
    assertion_id(&[0; 32], Hash256::ZERO, genesis_root, Hash256::ZERO, 0, 0)
}

/// A dispute's id, as `sena::disputes::dispute_id` computes it.
///
/// # Panics
///
/// Panics if `challenger` is not hex.
#[must_use]
pub fn dispute_id(assertion: &[u8], challenger: &str) -> Vec<u8> {
    let hexed = challenger.trim_start_matches("0x");
    let mut addr = hex::decode(format!("{hexed:0>64}")).expect("an account address");
    let mut id = assertion.to_vec();
    id.append(&mut addr);
    id
}

// --- The Aptos CLI implementation ------------------------------------------------

/// [`L1`] over the Aptos CLI and a fullnode's REST API.
#[derive(Clone, Debug)]
pub struct AptosCli {
    /// Path to the `aptos` binary.
    pub binary: String,
    /// The Aptos CLI profile that signs (must exist in `.aptos/config.yaml`).
    pub profile: String,
    /// The fullnode REST endpoint, e.g. `https://api.testnet.aptoslabs.com/v1`.
    pub rest_url: String,
    /// The address the SENA package is published at.
    pub contract: String,
    /// The profile's account address.
    pub account: String,
    /// The most gas units a single transaction may use.
    pub max_gas: u64,
}

impl AptosCli {
    fn json_file(function: &str, args: &[Arg]) -> Result<tempfile_path::TempJson, L1Error> {
        let body = json!({
            "function_id": function,
            "type_args": [],
            "args": args.iter().map(Arg::to_json).collect::<Vec<_>>(),
        });
        tempfile_path::TempJson::write(&body).map_err(|e| L1Error::Transport(e.to_string()))
    }

    fn get(&self, path: &str) -> Result<Value, L1Error> {
        let url = format!("{}{path}", self.rest_url.trim_end_matches('/'));
        ureq::get(&url)
            .timeout(Duration::from_secs(20))
            .call()
            .map_err(|e| L1Error::Transport(e.to_string()))?
            .into_json()
            .map_err(|e| L1Error::Malformed(e.to_string()))
    }
}

impl L1 for AptosCli {
    fn submit(&self, function: &str, args: &[Arg]) -> Result<u64, L1Error> {
        let full = format!("{}::{function}", self.contract);
        let file = Self::json_file(&full, args)?;
        let out = Command::new(&self.binary)
            .args([
                "move",
                "run",
                "--json-file",
                file.path(),
                "--profile",
                &self.profile,
                "--assume-yes",
            ])
            .args([
                "--max-gas",
                &self.max_gas.to_string(),
                "--url",
                &self.rest_url,
            ])
            .output()
            .map_err(|e| L1Error::Transport(format!("cannot run {}: {e}", self.binary)))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let parsed: Value = serde_json::from_str(&stdout).map_err(|_| {
            L1Error::Transport(format!("{stdout} {}", String::from_utf8_lossy(&out.stderr)))
        })?;
        let result = &parsed["Result"];
        if result["success"].as_bool() == Some(true) {
            return u64_of(&result["gas_used"]);
        }
        let status = result["vm_status"]
            .as_str()
            .map_or_else(|| parsed["Error"].to_string(), str::to_owned);
        Err(L1Error::Rejected {
            function: function.to_owned(),
            status,
        })
    }

    fn view(&self, function: &str, args: &[Arg]) -> Result<Vec<Value>, L1Error> {
        let full = format!("{}::{function}", self.contract);
        let file = Self::json_file(&full, args)?;
        let out = Command::new(&self.binary)
            .args([
                "move",
                "view",
                "--json-file",
                file.path(),
                "--url",
                &self.rest_url,
            ])
            .output()
            .map_err(|e| L1Error::Transport(e.to_string()))?;
        let parsed: Value = serde_json::from_slice(&out.stdout)
            .map_err(|_| L1Error::Transport(String::from_utf8_lossy(&out.stderr).into_owned()))?;
        parsed["Result"]
            .as_array()
            .cloned()
            .ok_or_else(|| L1Error::Rejected {
                function: function.to_owned(),
                status: parsed["Error"].to_string(),
            })
    }

    fn now(&self) -> Result<u64, L1Error> {
        let info = self.get("")?;
        Ok(u64_of(&info["ledger_timestamp"])? / 1_000_000)
    }

    fn published_batch(
        &self,
        proposer: &str,
        assertion: &[u8],
    ) -> Result<Option<PublishedBatch>, L1Error> {
        let event_type = format!("{}::assertions::BatchPublished", self.contract);
        let mut start = 0u64;
        loop {
            let page = self.get(&format!(
                "/accounts/{proposer}/transactions?start={start}&limit=100"
            ))?;
            let txs = page
                .as_array()
                .ok_or_else(|| L1Error::Malformed(page.to_string()))?;
            if txs.is_empty() {
                return Ok(None);
            }
            for tx in txs {
                for event in tx["events"].as_array().into_iter().flatten() {
                    if event["type"]
                        .as_str()
                        .is_some_and(|t| same_type(t, &event_type))
                    {
                        let batch = parse_batch_event(&event["data"])?;
                        if batch.assertion == assertion {
                            return Ok(Some(batch));
                        }
                    }
                }
            }
            start += txs.len() as u64;
        }
    }

    fn address(&self) -> String {
        self.account.clone()
    }

    fn contract(&self) -> String {
        self.contract.clone()
    }
}

/// Compares Move type names, tolerating leading zeros in the address.
fn same_type(a: &str, b: &str) -> bool {
    let norm = |t: &str| {
        let (addr, rest) = t.split_once("::").unwrap_or((t, ""));
        format!(
            "{}::{rest}",
            addr.trim_start_matches("0x").trim_start_matches('0')
        )
    };
    norm(a) == norm(b)
}

/// A JSON file that removes itself when dropped.
mod tempfile_path {
    use std::path::PathBuf;

    use std::io::Write as _;

    pub struct TempJson(PathBuf);

    impl TempJson {
        pub fn write(value: &serde_json::Value) -> std::io::Result<Self> {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sena-l1-{}-{n}.json", std::process::id()));
            let mut f = std::fs::File::create(&path)?;
            f.write_all(value.to_string().as_bytes())?;
            Ok(Self(path))
        }

        pub fn path(&self) -> &str {
            self.0.to_str().unwrap_or_default()
        }
    }

    impl Drop for TempJson {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_compare_across_address_padding() {
        assert!(same_type(
            "0x0cafe::assertions::BatchPublished",
            "0xcafe::assertions::BatchPublished"
        ));
        assert!(!same_type(
            "0xcafe::assertions::Other",
            "0xcafe::assertions::BatchPublished"
        ));
    }

    #[test]
    fn dispute_ids_pad_the_address() {
        let id = dispute_id(&[1; 32], "0xb0b");
        assert_eq!(id.len(), 64);
        assert_eq!(&id[62..], &[0x0b, 0x0b]);
    }

    #[test]
    fn records_parse() {
        let v: Vec<Value> = serde_json::from_str(&format!(
            r#"["0x{p}", "0xa11ce", "0x{r}", "0x{r}", "5", "1", "0x{r}", "6", "100", "7", 1]"#,
            p = "00".repeat(32),
            r = "11".repeat(32)
        ))
        .unwrap();
        let rec = parse_record(&v).unwrap();
        assert_eq!(rec.trace_length, 6);
        assert_eq!(rec.status, status::CHALLENGED);
    }
}
