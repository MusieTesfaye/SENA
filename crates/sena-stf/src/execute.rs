//! Execution: applying instructions, and verifying one in isolation.
//!
//! Two callers need to execute instructions, and they must never disagree.
//!
//! - The sequencer and verifier nodes run [`apply`] against a full state trie.
//! - Aptos L1 runs [`verify_step`] during dispute resolution, holding no state
//!   at all — only a pre-state root and a Merkle proof of the slot involved.
//!
//! If those two implementations could drift apart, a dishonest sequencer could
//! produce a trace that L1 would wrongly endorse, or an honest one could be
//! wrongly slashed. They are therefore not two implementations: both call
//! [`transition`], which holds the entire semantics of the instruction set as a
//! pure function from the slot's current bytes to its new bytes (NFR-MAINT-004).

use sena_primitives::{AssetId, Hash256, L2Address};
use sena_state::{hash_value, MerkleProof, MerkleTrie, ProofError};
use serde::{Deserialize, Serialize};

use crate::account::{Account, BalanceError};
use crate::gas::{self, GasError, WhitelistedAsset};
use crate::governance::{self, Council, GovernanceError, GovernanceUpdate};
use crate::instruction::{Instruction, MachineState};
use crate::social::SocialBinding;
use crate::transaction::{AuthError, Payload, Transaction};

/// The system-controlled vault that collects fees (REQ-GAS-007).
///
/// A fixed, unspendable-by-key address: it is not derived from any OIDC identity
/// and no signing key maps to it, so the fees it accumulates can only be moved
/// by a protocol rule, never by whoever holds a private key.
pub const FEE_VAULT: L2Address = L2Address::from_bytes([0xFE; 32]);

/// The base cost of a transaction, in native units.
///
/// Re-exported from [`crate::gas`], where the conversion into a whitelisted
/// asset is defined. Pricing by the work a transaction actually performs needs
/// per-instruction metering and is tracked as follow-up work.
pub use crate::gas::BASE_GAS_NATIVE;

/// Why a single step failed.
///
/// A step failing means the trace is invalid, which means whoever asserted it
/// was wrong. These are therefore not user-facing errors in the ordinary sense —
/// they are the conditions a fraud proof establishes.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum StepError {
    /// The account's nonce did not match the transaction's.
    #[error("nonce mismatch: account is at {actual}, transaction claimed {expected}")]
    NonceMismatch {
        /// The nonce the account holds.
        actual: u64,
        /// The nonce the transaction supplied.
        expected: u64,
    },
    /// An account's balance could not support the operation.
    #[error("balance error: {0}")]
    Balance(#[from] BalanceError),
    /// Stored bytes could not be decoded as the expected type.
    #[error("state slot holds malformed data")]
    MalformedSlot,
    /// The identifier is already bound to a different address.
    #[error("identifier is already bound to another address")]
    IdentifierTaken,
    /// The identifier is not bound to the address trying to release it.
    #[error("identifier is not held by the address attempting to release it")]
    IdentifierNotHeld,
    /// The witness did not describe the slot the instruction touches.
    #[error("witness is for slot {provided}, but the instruction touches {expected}")]
    WitnessSlotMismatch {
        /// The slot the witness described.
        provided: Hash256,
        /// The slot the instruction actually touches.
        expected: Hash256,
    },
    /// A Merkle proof in the witness did not verify.
    #[error("witness proof invalid: {0}")]
    BadWitnessProof(#[from] ProofError),
    /// The fee asset is not on the whitelist.
    #[error("asset is not whitelisted for fees")]
    AssetNotWhitelisted,
    /// The fee asset is whitelisted but currently disabled.
    #[error("asset is whitelisted but disabled for fees")]
    AssetDisabled,
    /// The transaction declared a rate the whitelist does not hold.
    #[error("declared gas rate {declared} does not match the on-chain rate {on_chain}")]
    GasRateMismatch {
        /// The rate the transaction claimed.
        declared: u128,
        /// The rate actually recorded.
        on_chain: u128,
    },
    /// A gas computation failed.
    #[error("gas error: {0}")]
    Gas(#[from] GasError),
    /// A governance check failed.
    #[error("governance error: {0}")]
    Governance(#[from] GovernanceError),
}

/// The complete semantics of the instruction set.
///
/// Given the current contents of the instruction's slot — `None` if the slot is
/// empty — returns what the slot should contain afterwards. Pure: no trie, no
/// clock, no I/O. Everything that can make execution diverge between two honest
/// nodes would have to enter through here, and nothing can.
///
/// # Errors
///
/// Returns [`StepError`] if the instruction is not applicable to the current
/// contents, which means the trace containing it is invalid.
pub fn transition(instruction: &Instruction, current: Option<&[u8]>) -> Result<Vec<u8>, StepError> {
    match instruction {
        Instruction::ConsumeNonce { expected, .. } => {
            let mut account = decode_account(current)?;
            if account.nonce != *expected {
                return Err(StepError::NonceMismatch {
                    actual: account.nonce,
                    expected: *expected,
                });
            }
            // Incrementing cannot overflow in practice: it would take 2^64
            // transactions from one account. Checked anyway, because a wrap
            // would silently re-enable every previously used nonce.
            account.nonce = account.nonce.checked_add(1).ok_or(BalanceError::Overflow)?;
            Ok(account.encode())
        }
        Instruction::Debit { asset, amount, .. } => {
            let mut account = decode_account(current)?;
            account.debit(*asset, *amount)?;
            Ok(account.encode())
        }
        Instruction::Credit { asset, amount, .. } => {
            let mut account = decode_account(current)?;
            account.credit(*asset, *amount)?;
            Ok(account.encode())
        }
        Instruction::BindIdentifier { address, .. } => {
            match current {
                None => {}
                Some(bytes) => match SocialBinding::decode(bytes) {
                    Err(_) => return Err(StepError::MalformedSlot),
                    Ok(SocialBinding::Vacant) => {}
                    Ok(SocialBinding::Bound { address: holder }) => {
                        // Re-binding to the same address is idempotent; binding
                        // over someone else's identifier is not permitted.
                        if holder != *address {
                            return Err(StepError::IdentifierTaken);
                        }
                    }
                },
            }
            Ok(SocialBinding::Bound { address: *address }.encode())
        }
        Instruction::UnbindIdentifier { expected_owner, .. } => {
            let bytes = current.ok_or(StepError::IdentifierNotHeld)?;
            let binding = SocialBinding::decode(bytes).map_err(|_| StepError::MalformedSlot)?;
            match binding.address() {
                Some(holder) if holder == *expected_owner => Ok(SocialBinding::Vacant.encode()),
                _ => Err(StepError::IdentifierNotHeld),
            }
        }
        Instruction::VerifyGasAsset { rate, .. } => {
            let bytes = current.ok_or(StepError::AssetNotWhitelisted)?;
            let record = WhitelistedAsset::decode(bytes).map_err(|_| StepError::MalformedSlot)?;
            if !record.enabled {
                return Err(StepError::AssetDisabled);
            }
            if record.rate != *rate {
                return Err(StepError::GasRateMismatch {
                    declared: *rate,
                    on_chain: record.rate,
                });
            }
            // A read-only step: the slot is written back byte-identical, so the
            // state root is unchanged and the step is still a single-slot write
            // like every other.
            Ok(bytes.to_vec())
        }
        Instruction::VerifyCouncil { digest, signatures } => {
            let bytes = current.ok_or(GovernanceError::MalformedCouncil)?;
            let council = Council::decode(bytes)?;
            governance::verify_council_signatures(&council, digest, signatures)?;
            Ok(bytes.to_vec())
        }
        Instruction::SetGasAsset { record } => {
            GovernanceUpdate::SetGasAsset {
                record: record.clone(),
            }
            .check_permitted()?;
            Ok(record.encode())
        }
        Instruction::SetParameter { name, value } => {
            // Re-checked here and not only at compile time: the L1 verifier
            // adjudicates this instruction from the batch data alone, so the
            // allowlist has to be enforced by the step itself (REQ-GOV-007).
            GovernanceUpdate::SetParameter {
                name: name.clone(),
                value: *value,
            }
            .check_permitted()?;
            Ok(value.to_be_bytes().to_vec())
        }
    }
}

fn decode_account(current: Option<&[u8]>) -> Result<Account, StepError> {
    match current {
        // An account that has never been touched is an account with a zero
        // nonce and no balances, not an error. Crediting a fresh address is how
        // every account comes into existence.
        None => Ok(Account::new()),
        Some(bytes) => Account::decode(bytes).map_err(|_| StepError::MalformedSlot),
    }
}

/// Applies one instruction to a full state trie, returning the new state root.
///
/// # Errors
///
/// Returns [`StepError`] if the instruction is not applicable.
pub fn apply(trie: &mut MerkleTrie, instruction: &Instruction) -> Result<Hash256, StepError> {
    let slot = instruction.slot();
    let updated = transition(instruction, trie.get(&slot))?;
    Ok(trie.insert(slot, updated))
}

/// Everything Aptos L1 needs to check a single step without holding state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StepWitness {
    /// The slot the instruction touches.
    pub slot: Hash256,
    /// The slot's contents before the step, or `None` if it was empty.
    pub value: Option<Vec<u8>>,
    /// Proof of `value` against the pre-state root.
    pub proof: MerkleProof,
}

/// Verifies one step in isolation, the way the L1 dispute contract does.
///
/// This is the function `sena::osp` reimplements in Move. It takes a pre-state
/// commitment, an instruction, and a witness, and derives the post-state that
/// honest execution must produce. Comparing that against what a party claimed is
/// what settles a dispute (REQ-FRAUD-017).
///
/// The witness is checked before it is trusted: the slot must be the one the
/// instruction actually touches, and the claimed contents must prove against the
/// pre-state root. A prover supplying a witness for some other slot, or
/// misreporting what the slot held, is rejected here.
///
/// # Errors
///
/// Returns [`StepError`] if the witness is for the wrong slot, if its proof does
/// not verify against `pre.state_root`, or if the instruction is not applicable
/// to the proven contents.
pub fn verify_step(
    pre: &MachineState,
    instruction: &Instruction,
    witness: &StepWitness,
) -> Result<MachineState, StepError> {
    let expected_slot = instruction.slot();
    if witness.slot != expected_slot {
        return Err(StepError::WitnessSlotMismatch {
            provided: witness.slot,
            expected: expected_slot,
        });
    }

    match &witness.value {
        Some(bytes) => {
            witness
                .proof
                .verify_inclusion(&pre.state_root, &witness.slot, bytes)?;
        }
        None => {
            witness
                .proof
                .verify_non_inclusion(&pre.state_root, &witness.slot)?;
        }
    }

    let updated = transition(instruction, witness.value.as_deref())?;
    let post_root = witness
        .proof
        .compute_updated_root(&witness.slot, &hash_value(&updated))?;

    Ok(MachineState {
        state_root: post_root,
        // Saturating rather than wrapping: a trace long enough to overflow a u64
        // program counter cannot be produced, and wrapping would alias two
        // distinct trace positions.
        pc: pre.pc.saturating_add(1),
    })
}

/// Why a transaction could not be turned into instructions.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum CompileError {
    /// The transaction is not authorised.
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
    /// The fee the sender allowed is below what the network charges.
    #[error("max fee {offered} is below the required fee {required}")]
    FeeTooLow {
        /// What the sender was willing to pay.
        offered: u128,
        /// What the network charges.
        required: u128,
    },
    /// A transfer named the sender as its own recipient.
    ///
    /// Self-transfers are rejected rather than treated as a no-op. Compiled
    /// naively they would emit a debit and a credit against the same slot, and
    /// the debit's post-state would be the credit's pre-state — harmless here,
    /// but the kind of aliasing that makes single-slot reasoning subtle. There
    /// is no use for the operation, so it is excluded.
    #[error("a transfer cannot name its sender as the recipient")]
    SelfTransfer,
    /// The declared gas rate is unusable.
    #[error("gas error: {0}")]
    Gas(#[from] GasError),
    /// The governance update is not one the council may make.
    #[error("governance error: {0}")]
    Governance(#[from] GovernanceError),
}

/// Turns an authorised transaction into the instructions that execute it.
///
/// # This function must stay a pure function of the transaction
///
/// It reads no state, and it must not begin to. The reason is structural rather
/// than stylistic: when a dispute bisects down to step `n`, Aptos L1 has to know
/// which instruction sits at that index, and it derives that by compiling the
/// published batch data itself. If compilation consulted state, L1 would need a
/// witness for every slot the compiler touched, at every step — and the two
/// parties could disagree about the instruction list itself, which bisection
/// over a shared list has no way to resolve.
///
/// So anything that must be checked against state becomes an instruction in the
/// trace instead of a lookup here. That is why a transaction declares the gas
/// rate it believes applies and [`Instruction::VerifyGasAsset`] validates it,
/// and why council signatures are checked by [`Instruction::VerifyCouncil`]
/// rather than during compilation.
///
/// # Errors
///
/// Returns [`CompileError`] if the transaction is unauthorised or malformed.
pub fn compile(transaction: &Transaction) -> Result<Vec<Instruction>, CompileError> {
    transaction.authenticate()?;

    let fee = gas::fee_for(transaction.fee_rate)?;
    if transaction.max_fee < fee {
        return Err(CompileError::FeeTooLow {
            offered: transaction.max_fee,
            required: fee,
        });
    }

    let sender = transaction.sender;
    let mut instructions = vec![
        Instruction::ConsumeNonce {
            account: sender,
            expected: transaction.nonce,
        },
        // Validate the declared rate against the whitelist before charging on
        // the strength of it.
        Instruction::VerifyGasAsset {
            asset: transaction.fee_asset,
            rate: transaction.fee_rate,
        },
        Instruction::Debit {
            account: sender,
            asset: transaction.fee_asset,
            amount: fee,
        },
        Instruction::Credit {
            account: FEE_VAULT,
            asset: transaction.fee_asset,
            amount: fee,
        },
    ];

    match &transaction.payload {
        Payload::Transfer { to, asset, amount } => {
            if *to == sender {
                return Err(CompileError::SelfTransfer);
            }
            instructions.push(Instruction::Debit {
                account: sender,
                asset: *asset,
                amount: *amount,
            });
            instructions.push(Instruction::Credit {
                account: *to,
                asset: *asset,
                amount: *amount,
            });
        }
        Payload::BindIdentifier { identifier, .. } => {
            instructions.push(Instruction::BindIdentifier {
                identifier: *identifier,
                address: sender,
            });
        }
        Payload::UnbindIdentifier { identifier } => {
            instructions.push(Instruction::UnbindIdentifier {
                identifier: *identifier,
                expected_owner: sender,
            });
        }
        Payload::Governance {
            epoch,
            update,
            signatures,
        } => {
            update.check_permitted()?;
            instructions.push(Instruction::VerifyCouncil {
                digest: update.signing_digest(*epoch),
                signatures: signatures.clone(),
            });
            instructions.push(match update {
                GovernanceUpdate::SetGasAsset { record } => Instruction::SetGasAsset {
                    record: record.clone(),
                },
                GovernanceUpdate::SetParameter { name, value } => Instruction::SetParameter {
                    name: name.clone(),
                    value: *value,
                },
            });
        }
    }

    Ok(instructions)
}

/// The full record of executing a batch, and the input to a fraud proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecutionTrace {
    /// Every instruction executed, in order.
    pub instructions: Vec<Instruction>,
    /// Machine state before each instruction, plus the final state.
    ///
    /// Always one longer than `instructions`: `states[i]` is the state before
    /// `instructions[i]`, and the last entry is the state after the batch.
    /// Bisection indexes into this.
    pub states: Vec<MachineState>,
}

impl ExecutionTrace {
    /// Returns the number of steps in the trace.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns whether the trace has no steps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Returns the state the batch started from.
    ///
    /// # Panics
    ///
    /// Panics if the trace has no states, which [`execute_batch`] never produces.
    #[must_use]
    pub fn initial(&self) -> MachineState {
        *self
            .states
            .first()
            .expect("a trace always records its initial state")
    }

    /// Returns the state the batch ended in.
    ///
    /// # Panics
    ///
    /// Panics if the trace has no states, which [`execute_batch`] never produces.
    #[must_use]
    pub fn final_state(&self) -> MachineState {
        *self
            .states
            .last()
            .expect("a trace always records its final state")
    }
}

/// Why a batch could not be executed.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum BatchError {
    /// A transaction in the batch could not be compiled.
    #[error("transaction {index} could not be compiled: {source}")]
    Compile {
        /// Position of the offending transaction.
        index: usize,
        /// What went wrong.
        #[source]
        source: CompileError,
    },
    /// A step failed partway through the batch.
    #[error("transaction {index} failed at step {step}: {source}")]
    Step {
        /// Position of the offending transaction.
        index: usize,
        /// Global index of the failing step within the batch trace.
        step: usize,
        /// What went wrong.
        #[source]
        source: StepError,
    },
}

/// Executes a batch against `trie`, producing the trace an assertion commits to.
///
/// # Failure is total, by design
///
/// If any transaction in the batch cannot be executed, the whole batch is
/// rejected rather than the transaction being skipped or marked failed. This
/// keeps the rule a verifier applies unambiguous: a batch either executes
/// cleanly from its pre-state, or it is not a valid batch and any assertion
/// covering it is fraudulent. The sequencer is responsible for only including
/// transactions it has checked — mempool admission, not consensus, is where
/// invalid transactions are filtered.
///
/// The cost is that a sequencer must validate before including, and that a
/// transaction which becomes invalid due to reordering invalidates the batch.
/// Charging a fee for failed transactions, so that submitting them is not free,
/// needs the paymaster and is deferred to that phase.
///
/// # Errors
///
/// Returns [`BatchError`] identifying the transaction and step that failed.
///
/// # Panics
///
/// Panics if the trace exceeds `u64::MAX` steps, which no batch can reach. On a
/// step error the trie is left partially updated, so callers that need to retry
/// should execute against a clone.
pub fn execute_batch(
    trie: &mut MerkleTrie,
    transactions: &[Transaction],
) -> Result<ExecutionTrace, BatchError> {
    let mut instructions = Vec::new();
    let mut states = vec![MachineState::start(trie.root())];

    for (index, transaction) in transactions.iter().enumerate() {
        let compiled =
            compile(transaction).map_err(|source| BatchError::Compile { index, source })?;

        for instruction in compiled {
            let step = instructions.len();
            let root = apply(trie, &instruction).map_err(|source| BatchError::Step {
                index,
                step,
                source,
            })?;
            instructions.push(instruction);
            states.push(MachineState {
                state_root: root,
                pc: u64::try_from(instructions.len()).expect("trace length fits in u64"),
            });
        }
    }

    Ok(ExecutionTrace {
        instructions,
        states,
    })
}

/// Credits an account at genesis, returning the new state root.
///
/// The return value is informational; the point of the call is the side effect,
/// so it is not `#[must_use]`.
///
/// # Panics
///
/// Panics if the credit overflows the account's balance, which cannot happen
/// for a genesis allocation within `u128`.
pub fn genesis_credit(
    trie: &mut MerkleTrie,
    account: L2Address,
    asset: AssetId,
    amount: u128,
) -> Hash256 {
    let instruction = Instruction::Credit {
        account,
        asset,
        amount,
    };
    apply(trie, &instruction).expect("crediting a genesis account cannot fail")
}
