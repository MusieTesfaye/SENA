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

use sena_primitives::serde_hex::balances;
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
    /// Fetch a block's published batch data (REQ-FRAUD-007).
    ///
    /// This is what makes independent verification possible: without it a
    /// verifier could not re-execute the chain, and an assertion could not be
    /// checked by anyone but the party that made it.
    #[serde(rename = "sena_getBlock")]
    GetBlock {
        /// Block height, counting from one.
        height: u64,
    },
    /// Report chain-level status.
    #[serde(rename = "sena_getChainInfo")]
    GetChainInfo,
    /// Produce everything needed to withdraw on Aptos (REQ-CORE-004).
    ///
    /// The proof is made against the most recent **finalized** assertion, not
    /// the current root, because that is what the L1 bridge checks against. A
    /// proof against the current root would be rejected on chain.
    #[serde(rename = "sena_getWithdrawalProof")]
    GetWithdrawalProof {
        /// The account to prove a balance for.
        address: L2Address,
    },
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
        /// Balances in asset order, with amounts as decimal strings so that
        /// clients whose JSON numbers are doubles do not silently round them.
        #[serde(with = "balances")]
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
    /// A block's published batch data.
    Block {
        /// Its height.
        height: u64,
        /// State root before the block.
        pre_state_root: Hash256,
        /// State root after it.
        post_state_root: Hash256,
        /// The transactions, in execution order.
        transactions: Vec<Transaction>,
        /// The assertion covering it, if one has been posted.
        assertion: Option<AssertionId>,
        /// Number of execution steps, which bisection searches over.
        trace_length: u64,
    },
    /// Chain-level status.
    ChainInfo {
        /// The chain this node belongs to.
        chain_id: String,
        /// Highest block produced.
        height: u64,
        /// Highest block whose assertion has finalized.
        finalized_height: u64,
        /// The configured challenge window, in seconds.
        challenge_window_secs: u64,
        /// Current L2 state root.
        state_root: Hash256,
        /// How many transactions are waiting.
        mempool_size: usize,
    },
    /// Everything the L1 bridge needs to release custody.
    ///
    /// Encoded as hex because these go straight into `aptos move run` arguments.
    WithdrawalProof {
        /// The assertion the proof is against. Must be finalized on L1.
        assertion_height: u64,
        /// Root the proof reconstructs to.
        state_root: Hash256,
        /// The account's stored bytes.
        account_value: String,
        /// Sibling hashes, root-first.
        siblings: Vec<String>,
        /// Whether the path ends in a leaf.
        terminal_is_leaf: bool,
        /// The key at the terminal, if it is a leaf.
        terminal_key: String,
        /// The value digest at the terminal, if it is a leaf.
        terminal_value_hash: String,
        /// Whether the covering assertion has finalized. A withdrawal submitted
        /// while this is false will be refused on chain.
        finalized: bool,
    },
    /// The request could not be served.
    Error {
        /// A human-readable explanation.
        message: String,
    },
}

/// Builds the proof the L1 bridge needs to release custody.
///
/// Made against the most recent **finalized** assertion rather than the current
/// root. A proof against an unfinalized root is one the bridge refuses, and
/// handing one out would let the user discover that as a failed transaction.
fn withdrawal_proof(sequencer: &Sequencer, address: L2Address) -> Response {
    let height = sequencer.finalized_height();
    if height == 0 {
        return Response::Error {
            message: "no assertion has finalized yet; nothing is withdrawable".to_owned(),
        };
    }

    let Some(block) = usize::try_from(height - 1)
        .ok()
        .and_then(|i| sequencer.blocks.get(i))
    else {
        return Response::Error {
            message: format!("no block at finalized height {height}"),
        };
    };

    let root = block.post_state_root;
    let slot = keys::account(&address);
    let proof = sequencer.state.prove_at(root, &slot);
    let value = sequencer
        .state
        .get(&slot)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();

    let (terminal_is_leaf, terminal_key, terminal_value_hash) = match &proof.terminal {
        sena_state::Terminal::Leaf { key, value_hash } => (true, key.to_hex(), value_hash.to_hex()),
        sena_state::Terminal::Empty => (false, String::new(), String::new()),
    };

    Response::WithdrawalProof {
        assertion_height: height,
        state_root: root,
        account_value: hex::encode(value),
        siblings: proof.siblings.iter().map(Hash256::to_hex).collect(),
        terminal_is_leaf,
        terminal_key,
        terminal_value_hash,
        finalized: true,
    }
}

/// Serves one request against the node.
///
/// `chain_id` is reported back so a client can tell at a glance whether it is
/// talking to the network it thinks it is.
pub fn handle(sequencer: &mut Sequencer, chain_id: &str, request: Request) -> Response {
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

        Request::GetBlock { height } => {
            match usize::try_from(height.saturating_sub(1))
                .ok()
                .and_then(|i| sequencer.blocks.get(i))
            {
                None => Response::Error {
                    message: format!("no block at height {height}"),
                },
                Some(block) => Response::Block {
                    height: block.height,
                    pre_state_root: block.pre_state_root,
                    post_state_root: block.post_state_root,
                    transactions: block.transactions.clone(),
                    assertion: sequencer.assertion_for(block.height),
                    trace_length: block.trace.len() as u64,
                },
            }
        }

        Request::GetWithdrawalProof { address } => withdrawal_proof(sequencer, address),

        Request::GetChainInfo => Response::ChainInfo {
            chain_id: chain_id.to_owned(),
            height: sequencer.blocks.len() as u64,
            finalized_height: sequencer.finalized_height(),
            challenge_window_secs: sequencer.chain.challenge_window(),
            state_root: sequencer.state.root(),
            mempool_size: sequencer.mempool.len(),
        },
    }
}
