//! Reading the L1 deposit log (`sena::deposits`) into the sequencer.
//!
//! The sequencer credits a deposit only after reading it here, from Aptos
//! itself. Nothing reaches it over RPC: a deposit the sequencer was told about
//! rather than read would be one it might credit wrongly, and a wrong credit is
//! fraud its bond pays for.
//!
//! Reading needs no key, only the fullnode's REST `/view` endpoint.

use std::time::Duration;

use serde_json::{json, Value};

use sena_stf::DepositRecord;

use crate::l1::{self, Arg, L1Error, PublishedBatch, L1};
use crate::sequencer::Sequencer;

/// The most deposits read from L1 per poll.
pub const MAX_READ_PER_POLL: u64 = 64;

/// A read-only view of an Aptos fullnode, over REST.
#[derive(Clone, Debug)]
pub struct RestReader {
    /// Fullnode REST endpoint, e.g. `https://api.testnet.aptoslabs.com/v1`.
    pub rest_url: String,
    /// The address the SENA package and its chain live at.
    pub contract: String,
}

impl RestReader {
    fn arg_json(arg: &Arg) -> Value {
        match arg {
            Arg::Address(a) => json!(a),
            Arg::U64(v) => json!(v.to_string()),
            Arg::U128(v) => json!(v.to_string()),
            Arg::U8(v) => json!(v),
            Arg::Bool(v) => json!(v),
            Arg::Bytes(b) => json!(format!("0x{}", hex::encode(b))),
            Arg::U64List(v) => json!(v.iter().map(u64::to_string).collect::<Vec<_>>()),
            Arg::BytesList(v) => json!(v
                .iter()
                .map(|b| format!("0x{}", hex::encode(b)))
                .collect::<Vec<_>>()),
        }
    }
}

impl L1 for RestReader {
    fn submit(&self, function: &str, _: &[Arg]) -> Result<u64, L1Error> {
        Err(L1Error::Rejected {
            function: function.to_owned(),
            status: "a REST reader cannot sign".to_owned(),
        })
    }

    fn view(&self, function: &str, args: &[Arg]) -> Result<Vec<Value>, L1Error> {
        let url = format!("{}/view", self.rest_url.trim_end_matches('/'));
        let body = json!({
            "function": format!("{}::{function}", self.contract),
            "type_arguments": [],
            "arguments": args.iter().map(Self::arg_json).collect::<Vec<_>>(),
        });
        let response = crate::l1::with_api_key(ureq::post(&url))
            .timeout(Duration::from_secs(10))
            .send_json(body)
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => L1Error::Rejected {
                    function: function.to_owned(),
                    status: format!("HTTP {code}: {}", r.into_string().unwrap_or_default()),
                },
                other @ ureq::Error::Transport(_) => L1Error::Transport(other.to_string()),
            })?;
        response
            .into_json::<Vec<Value>>()
            .map_err(|e| L1Error::Malformed(e.to_string()))
    }

    fn now(&self) -> Result<u64, L1Error> {
        Err(L1Error::Transport("not needed to read deposits".into()))
    }

    fn published_batch(&self, _: &str, _: &[u8]) -> Result<Option<PublishedBatch>, L1Error> {
        Ok(None)
    }

    fn address(&self) -> String {
        String::new()
    }

    fn contract(&self) -> String {
        self.contract.clone()
    }
}

/// Reads deposits from `next` on, stopping at the first id L1 has not
/// recorded, or after `max`.
///
/// # Errors
///
/// Returns [`L1Error`] if L1 cannot be read; nothing is returned then, so a
/// gap is never mistaken for the end of the log.
pub fn read_from<C: L1 + ?Sized>(
    l1: &C,
    next: u64,
    max: u64,
) -> Result<Vec<(u64, DepositRecord)>, L1Error> {
    let mut out = Vec::new();
    let mut id = next;
    while (out.len() as u64) < max {
        match l1::deposit_record(l1, id)? {
            Some(record) => out.push((id, record)),
            None => break,
        }
        id += 1;
    }
    Ok(out)
}

/// Reads any new deposits from L1 into `sequencer`. Returns how many.
///
/// # Errors
///
/// Returns a description if L1 cannot be read or contradicts what the
/// sequencer already read.
pub fn poll<C: L1 + ?Sized>(sequencer: &mut Sequencer, l1: &C) -> Result<usize, String> {
    let read = read_from(l1, sequencer.next_deposit_to_read(), MAX_READ_PER_POLL)
        .map_err(|e| e.to_string())?;
    for (id, record) in &read {
        sequencer
            .record_deposit(*id, *record)
            .map_err(|e| e.to_string())?;
    }
    Ok(read.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// An L1 whose only state is a deposit log.
    #[derive(Default)]
    struct Log {
        records: BTreeMap<u64, DepositRecord>,
        fail: bool,
        calls: RefCell<u32>,
    }

    impl L1 for Log {
        fn submit(&self, f: &str, _: &[Arg]) -> Result<u64, L1Error> {
            Err(L1Error::Malformed(f.into()))
        }
        fn view(&self, function: &str, args: &[Arg]) -> Result<Vec<Value>, L1Error> {
            *self.calls.borrow_mut() += 1;
            assert_eq!(function, "deposits::record");
            if self.fail {
                return Err(L1Error::Transport("down".into()));
            }
            let Arg::U64(id) = args[1] else { panic!() };
            Ok(match self.records.get(&id) {
                Some(r) => vec![
                    json!(true),
                    json!(format!("0x{}", hex::encode(r.recipient.as_bytes()))),
                    json!(r.asset.get()),
                    json!(r.amount.to_string()),
                ],
                None => vec![json!(false), json!("0x"), json!(0), json!("0")],
            })
        }
        fn now(&self) -> Result<u64, L1Error> {
            Ok(0)
        }
        fn published_batch(&self, _: &str, _: &[u8]) -> Result<Option<PublishedBatch>, L1Error> {
            Ok(None)
        }
        fn address(&self) -> String {
            String::new()
        }
        fn contract(&self) -> String {
            "0xC4A1".into()
        }
    }

    fn record(n: u8) -> DepositRecord {
        DepositRecord {
            recipient: sena_primitives::L2Address::from_bytes([n; 32]),
            asset: sena_primitives::AssetId(1),
            amount: u128::from(n) * 100,
        }
    }

    #[test]
    fn reads_up_to_the_first_unrecorded_id() {
        let l1 = Log {
            records: [(1, record(1)), (2, record(2)), (4, record(4))].into(),
            ..Log::default()
        };
        let read = read_from(&l1, 1, 10).unwrap();
        assert_eq!(read, vec![(1, record(1)), (2, record(2))]);
        assert_eq!(read_from(&l1, 3, 10).unwrap(), vec![]);
    }

    #[test]
    fn a_failed_read_is_an_error_not_an_empty_log() {
        let l1 = Log {
            records: [(1, record(1))].into(),
            fail: true,
            ..Log::default()
        };
        assert!(read_from(&l1, 1, 10).is_err());
    }

    #[test]
    fn reads_stop_at_the_limit() {
        let l1 = Log {
            records: (1..=10u8).map(|i| (u64::from(i), record(i))).collect(),
            ..Log::default()
        };
        assert_eq!(read_from(&l1, 1, 3).unwrap().len(), 3);
        assert_eq!(*l1.calls.borrow(), 3);
    }
}
