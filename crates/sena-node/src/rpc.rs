//! The JSON-RPC surface (SDD §6.1).
//!
//! Transport-agnostic: [`handle`] maps a request to a response and does no I/O,
//! so the same surface can sit behind HTTP, a websocket, or an in-process call,
//! and can be tested without a socket. Wiring it to HTTP is the remaining piece
//! of this layer.
//!
//! # Finality is a first-class field
//!
//! Every method that reports on a transaction returns a [`Confirmation`] that
//! distinguishes soft confirmation from L1 finality, and `sena_getAssertion`
//! reports an assertion's status and the time left in its window
//! (REQ-FRAUD-027, REQ-CORE-005). An integrator should not have to go looking
//! for whether a payment can still be reverted.

use sena_primitives::{Hash256, HashedIdentifier, L2Address};
use sena_stf::{keys, Account, SocialBinding, Transaction};
use serde::{Deserialize, Serialize};

use sena_fraudproof::{AssertionId, Status};

use crate::sequencer::{Confirmation, Sequencer};

/// A request to the node.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "method", content = "params")]
pub enum Request {
    /// Submit a transaction for inclusion.
    #[serde(rename = "sena_submitTransaction")]
    SubmitTransaction(Box<Transaction>),
    /// Read an account's nonce and balances.
    #[serde(rename = "sena_getAccount")]
    GetAccount {
        /// The account to read.
        address: L2Address,
    },
    /// Resolve a hashed social identifier to an address (REQ-SOCIAL-004).
    #[serde(rename = "sena_resolveIdentifier")]
    ResolveIdentifier {
        /// The hashed identifier to resolve.
        identifier: HashedIdentifier,
    },
    /// Report a transaction's confirmation status.
    #[serde(rename = "sena_getConfirmation")]
    GetConfirmation {
        /// The transaction's hash.
        hash: Hash256,
    },
    /// Report on an assertion (REQ-FRAUD-027).
    #[serde(rename = "sena_getAssertion")]
    GetAssertion {
        /// The assertion to report on.
        id: AssertionId,
    },
    /// Report the highest block whose assertion has finalized.
    #[serde(rename = "sena_getFinalizedHeight")]
    GetFinalizedHeight,
    /// Report the current L2 state root.
    #[serde(rename = "sena_getStateRoot")]
    GetStateRoot,
}

/// A response from the node.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "result")]
pub enum Response {
    /// The transaction was queued.
    Submitted {
        /// Its hash, for later status queries.
        hash: Hash256,
        /// Its status, which is always pending at this point. Returned anyway,
        /// so a caller never has to infer that submission is not confirmation.
        confirmation: Confirmation,
    },
    /// An account's state.
    Account {
        /// The account's nonce.
        nonce: u64,
        /// Balances, as `(asset id, amount)` pairs in asset order.
        balances: Vec<(u32, u128)>,
    },
    /// An identifier resolution.
    Resolved {
        /// The address, or `None` if the identifier is unbound or released.
        address: Option<L2Address>,
    },
    /// A transaction's confirmation status.
    Confirmation(Confirmation),
    /// An assertion's status.
    AssertionStatus {
        /// Where the assertion stands.
        status: Status,
        /// Seconds remaining in its challenge window; zero once elapsed.
        window_remaining: u64,
        /// Whether a withdrawal may be made against its post-state root.
        withdrawable: bool,
    },
    /// The highest finalized block height.
    FinalizedHeight {
        /// The height, or zero if nothing has finalized yet.
        height: u64,
    },
    /// The current L2 state root.
    StateRoot {
        /// The root.
        root: Hash256,
        /// Whether this root is withdrawable against on L1 — which it is not
        /// until its assertion finalizes.
        withdrawable: bool,
    },
    /// The request could not be served.
    Error {
        /// A human-readable explanation.
        message: String,
    },
}

/// Serves one request against the node.
pub fn handle(sequencer: &mut Sequencer, request: Request) -> Response {
    match request {
        Request::SubmitTransaction(transaction) => {
            match sequencer.mempool.submit(&sequencer.state, *transaction) {
                Ok(hash) => Response::Submitted {
                    hash,
                    confirmation: Confirmation::Pending,
                },
                Err(reason) => Response::Error {
                    message: reason.to_string(),
                },
            }
        }

        Request::GetAccount { address } => {
            let account = sequencer
                .state
                .get(&keys::account(&address))
                .map_or_else(|| Ok(Account::new()), Account::decode);
            match account {
                Ok(account) => Response::Account {
                    nonce: account.nonce,
                    balances: account
                        .balances
                        .iter()
                        .map(|(a, v)| (a.get(), *v))
                        .collect(),
                },
                Err(error) => Response::Error {
                    message: error.to_string(),
                },
            }
        }

        Request::ResolveIdentifier { identifier } => {
            let address = sequencer
                .state
                .get(&keys::social_by_identifier(&identifier))
                .and_then(|bytes| SocialBinding::decode(bytes).ok())
                .and_then(|binding| binding.address());
            Response::Resolved { address }
        }

        Request::GetConfirmation { hash } => Response::Confirmation(sequencer.confirmation(&hash)),

        Request::GetAssertion { id } => match sequencer.chain.get(&id) {
            None => Response::Error {
                message: "no such assertion".to_owned(),
            },
            Some(record) => {
                let elapsed = sequencer.chain.now().saturating_sub(record.posted_at);
                Response::AssertionStatus {
                    status: record.status,
                    window_remaining: sequencer.chain.challenge_window().saturating_sub(elapsed),
                    withdrawable: record.status == Status::Finalized,
                }
            }
        },

        Request::GetFinalizedHeight => Response::FinalizedHeight {
            height: sequencer.finalized_height(),
        },

        Request::GetStateRoot => {
            let root = sequencer.state.root();
            Response::StateRoot {
                root,
                withdrawable: sequencer.chain.is_withdrawable(&root),
            }
        }
    }
}
