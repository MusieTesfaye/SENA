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
use crate::gas::{self, FeeMarket, FeeSplit, GasError, WhitelistedAsset};
use crate::governance::{self, Council, GovernanceError, GovernanceUpdate};
use crate::instruction::{Instruction, MachineState};
use crate::keyless::{KeylessConfig, KeylessContext};
use crate::social::SocialBinding;
use crate::transaction::{AuthError, Authenticator, Payload, Transaction};

/// The system-controlled vault that collects fees (REQ-GAS-007).
///
/// A fixed, unspendable-by-key address: it is not derived from any OIDC identity
/// and no signing key maps to it, so the fees it accumulates can only be moved
/// by a protocol rule, never by whoever holds a private key.
pub const FEE_VAULT: L2Address = L2Address::from_bytes([0xFE; 32]);

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
    /// The keyless proof was made against a JWK the network does not accept
    /// for that issuer, or has retired.
    #[error("JWK is not accepted for this issuer")]
    JwkNotAccepted,
    /// The transaction declared an intrinsic gas the asset does not charge.
    #[error("declared intrinsic gas {declared} does not match the asset's {on_chain}")]
    IntrinsicGasMismatch {
        /// What the transaction claimed.
        declared: u64,
        /// What the asset record holds.
        on_chain: u64,
    },
    /// The batch declared a base fee other than the one in force.
    #[error("batch declared base fee {declared}, but the fee market is at {actual}")]
    BaseFeeMismatch {
        /// What the batch declared.
        declared: u128,
        /// The base fee in force.
        actual: u128,
    },
    /// The window has no room for the transaction's gas.
    #[error("the fee market window is full")]
    WindowFull,
    /// The fee split in force is not the one declared, or there is none.
    #[error("the declared fee split is not the one in force")]
    FeeSplitMismatch,
}

/// Encodes a JWK acceptance record: one byte, `1` accepted, `0` retired.
#[must_use]
pub fn encode_jwk_record(active: bool) -> Vec<u8> {
    vec![u8::from(active)]
}

/// Decodes a JWK acceptance record, refusing anything but `0` or `1`.
///
/// # Errors
///
/// Returns [`StepError::MalformedSlot`] for any other encoding.
pub fn decode_jwk_record(bytes: &[u8]) -> Result<bool, StepError> {
    match bytes {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(StepError::MalformedSlot),
    }
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
        Instruction::VerifyGasAsset { .. }
        | Instruction::ChargeBaseFee { .. }
        | Instruction::VerifyFeeSplit { .. } => fee_transition(instruction, current),
        Instruction::VerifyCouncil { .. }
        | Instruction::SetGasAsset { .. }
        | Instruction::SetParameter { .. }
        | Instruction::SetFeeMarket { .. }
        | Instruction::SetFeeSplit { .. }
        | Instruction::DisableGasAsset { .. } => governance_transition(instruction, current),
        Instruction::VerifyJwk { .. } => {
            let bytes = current.ok_or(StepError::JwkNotAccepted)?;
            if !decode_jwk_record(bytes)? {
                return Err(StepError::JwkNotAccepted);
            }
            Ok(bytes.to_vec())
        }
        Instruction::SetJwk { active, .. } => Ok(encode_jwk_record(*active)),
    }
}

/// The fee half of [`transition`]: the checks a transaction's fee rests on.
fn fee_transition(instruction: &Instruction, current: Option<&[u8]>) -> Result<Vec<u8>, StepError> {
    match instruction {
        Instruction::VerifyGasAsset {
            rate,
            intrinsic_gas,
            ..
        } => {
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
            if record.intrinsic_gas != *intrinsic_gas {
                return Err(StepError::IntrinsicGasMismatch {
                    declared: *intrinsic_gas,
                    on_chain: record.intrinsic_gas,
                });
            }
            // A read-only step: the slot is written back byte-identical, so the
            // state root is unchanged and the step is still a single-slot write
            // like every other.
            Ok(bytes.to_vec())
        }
        Instruction::ChargeBaseFee {
            timestamp,
            base_fee,
            gas,
        } => {
            let mut market = decode_fee_market(current)?.at(*timestamp)?;
            if market.base_fee != *base_fee {
                return Err(StepError::BaseFeeMismatch {
                    declared: *base_fee,
                    actual: market.base_fee,
                });
            }
            market.window_gas = market
                .window_gas
                .checked_add(*gas)
                .filter(|g| *g <= market.window_limit())
                .ok_or(StepError::WindowFull)?;
            Ok(market.encode())
        }
        Instruction::VerifyFeeSplit { split } => {
            let bytes = current.ok_or(StepError::FeeSplitMismatch)?;
            if bytes != split.encode().as_slice() {
                return Err(StepError::FeeSplitMismatch);
            }
            Ok(bytes.to_vec())
        }
        _ => unreachable!("only fee instructions are routed here"),
    }
}

/// The governance half of [`transition`]: council verification and the two
/// writes it authorises.
fn governance_transition(
    instruction: &Instruction,
    current: Option<&[u8]>,
) -> Result<Vec<u8>, StepError> {
    match instruction {
        Instruction::VerifyCouncil {
            epoch,
            digest,
            signatures,
            guardian,
        } => {
            let bytes = current.ok_or(GovernanceError::MalformedCouncil)?;
            let mut council = Council::decode(bytes)?;
            if council.epoch != *epoch {
                return Err(GovernanceError::WrongEpoch {
                    expected: council.epoch,
                    signed: *epoch,
                }
                .into());
            }
            governance::verify_council_signatures(&council, digest, signatures, *guardian)?;
            council.epoch = council.epoch.checked_add(1).ok_or(BalanceError::Overflow)?;
            Ok(council.encode())
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
        Instruction::SetFeeMarket { floor, target } => {
            GovernanceUpdate::SetFeeMarket {
                floor: *floor,
                target: *target,
            }
            .check_permitted()?;
            let market = decode_fee_market(current)?;
            Ok(FeeMarket {
                base_fee: market.base_fee.max(*floor),
                floor: *floor,
                target: *target,
                ..market
            }
            .encode())
        }
        Instruction::SetFeeSplit { split } => {
            GovernanceUpdate::SetFeeSplit {
                split: split.clone(),
            }
            .check_permitted()?;
            Ok(split.encode())
        }
        Instruction::DisableGasAsset { .. } => {
            let bytes = current.ok_or(StepError::AssetNotWhitelisted)?;
            let mut record =
                WhitelistedAsset::decode(bytes).map_err(|_| StepError::MalformedSlot)?;
            record.enabled = false;
            Ok(record.encode())
        }
        _ => unreachable!("only governance instructions are routed here"),
    }
}

/// The fee market a slot holds; an empty slot is the genesis market, so a
/// chain started without one behaves as if it had the defaults.
fn decode_fee_market(current: Option<&[u8]>) -> Result<FeeMarket, StepError> {
    match current {
        None => Ok(FeeMarket::genesis(
            gas::DEFAULT_BASE_FEE_FLOOR,
            gas::DEFAULT_GAS_TARGET,
        )),
        Some(bytes) => FeeMarket::decode(bytes).map_err(|_| StepError::MalformedSlot),
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
    /// A fee distribution is malformed: nothing to distribute, or a split
    /// that does not add up.
    #[error("fee distribution is malformed")]
    BadDistribution,
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
    /// The transaction exceeds the wire-format limits L1 can adjudicate.
    #[error("transaction exceeds wire limits: {0}")]
    Wire(#[from] crate::wire::WireError),
}

/// What a batch is executed against, besides state.
///
/// Both values are part of the published batch data: Aptos L1 compiles a
/// disputed transaction with the same timestamp and the same keyless
/// parameters, so they must be fixed per batch rather than read from a clock.
#[derive(Clone, Copy, Debug)]
pub struct BatchContext<'a> {
    /// The batch timestamp (Unix seconds), chosen by the sequencer and bounded
    /// by L1 when the assertion is posted. Keyless ephemeral keys must not have
    /// expired at this time, and it names the fee market window.
    pub timestamp: u64,
    /// The network's keyless parameters, or `None` if keyless is disabled.
    pub keyless: Option<&'a KeylessConfig>,
    /// The base fee the batch pays, in `PRICE_SCALE`ths of a native unit per
    /// gas — what the fee market holds for `timestamp`. Published in the batch
    /// header and checked in the trace by [`Instruction::ChargeBaseFee`].
    pub base_fee: u128,
    /// Where tips go: the sequencer's account (Ethereum's coinbase).
    pub fee_recipient: L2Address,
}

impl BatchContext<'_> {
    /// A context with keyless accounts disabled, the genesis base fee, and
    /// tips paid to the fee vault.
    #[must_use]
    pub const fn without_keyless(timestamp: u64) -> Self {
        BatchContext {
            timestamp,
            keyless: None,
            base_fee: gas::DEFAULT_BASE_FEE_FLOOR,
            fee_recipient: FEE_VAULT,
        }
    }

    /// The part of the context a keyless check reads.
    #[must_use]
    pub fn keyless_context(&self) -> KeylessContext<'_> {
        KeylessContext {
            config: self.keyless,
            now: self.timestamp,
        }
    }
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
/// The context — batch timestamp and keyless parameters — is not state: it is
/// fixed for the whole batch and published with it.
///
/// # Errors
///
/// Returns [`CompileError`] if the transaction is unauthorised or malformed.
pub fn compile(
    transaction: &Transaction,
    ctx: &BatchContext<'_>,
) -> Result<Vec<Instruction>, CompileError> {
    // Size limits first: Aptos L1 must be able to decode and compile anything
    // a batch contains, and it refuses what is over these bounds.
    let encoded_len = transaction.encode().len();
    if encoded_len > crate::wire::MAX_TRANSACTION_BYTES {
        return Err(crate::wire::WireError::TooLarge(encoded_len).into());
    }
    if let Payload::Governance { signatures, .. } = &transaction.payload {
        if signatures.len() > crate::wire::MAX_COUNCIL_SIGNATURES {
            return Err(crate::wire::WireError::TooManySignatures.into());
        }
    }
    transaction.authenticate(&ctx.keyless_context())?;

    let sender = transaction.sender;
    let (charge, payload) = charge_and_payload(transaction, ctx)?;

    let asset = transaction.fee_asset;
    let mut instructions = Vec::new();
    // The proof was checked above; whether its JWK is current is state.
    if let Authenticator::Keyless(sig) = &transaction.authenticator {
        instructions.push(Instruction::VerifyJwk {
            iss_hash: sig.iss_hash,
            jwk_hash: sig.jwk_hash,
        });
    }
    instructions.extend([
        Instruction::ConsumeNonce {
            account: sender,
            expected: transaction.nonce,
        },
        // Validate what the sender declared about the asset, and what the
        // sequencer declared about the base fee, before charging on them.
        Instruction::VerifyGasAsset {
            asset,
            rate: transaction.fee_rate,
            intrinsic_gas: transaction.fee_intrinsic_gas,
        },
        Instruction::ChargeBaseFee {
            timestamp: ctx.timestamp,
            base_fee: ctx.base_fee,
            gas: charge.gas_used,
        },
        // Celo's debitGasFees: the whole limit, before the payload runs.
        Instruction::Debit {
            account: sender,
            asset,
            amount: charge.hold,
        },
    ]);
    instructions.extend(payload);
    // Celo's creditGasFees, which never credits a zero amount.
    for (account, amount) in [
        (sender, charge.refund),
        (ctx.fee_recipient, charge.tip),
        (FEE_VAULT, charge.base),
    ] {
        if amount > 0 {
            instructions.push(Instruction::Credit {
                account,
                asset,
                amount,
            });
        }
    }
    Ok(instructions)
}

/// The gas a transaction uses, for choosing its gas limit. Needs no signature.
///
/// # Errors
///
/// Returns [`CompileError`] if the payload does not compile.
pub fn gas_required(transaction: &Transaction) -> Result<u64, CompileError> {
    let mut payload = Vec::new();
    compile_payload(&transaction.payload, transaction.sender, &mut payload)?;
    Ok(gas::gas_used(transaction, &payload)?)
}

/// What a transaction pays in a batch with context `ctx`: its hold, refund,
/// tip and base fee. Needs no signature, so a wallet can quote before signing.
///
/// # Errors
///
/// Returns [`CompileError`] if the payload does not compile or the fee terms
/// do not cover the batch's base fee.
pub fn fee_charge(
    transaction: &Transaction,
    ctx: &BatchContext<'_>,
) -> Result<gas::FeeCharge, CompileError> {
    Ok(charge_and_payload(transaction, ctx)?.0)
}

fn charge_and_payload(
    transaction: &Transaction,
    ctx: &BatchContext<'_>,
) -> Result<(gas::FeeCharge, Vec<Instruction>), CompileError> {
    let mut payload = Vec::new();
    compile_payload(&transaction.payload, transaction.sender, &mut payload)?;
    let charge = gas::settle(
        transaction.gas_limit,
        gas::gas_used(transaction, &payload)?,
        transaction.max_fee_per_gas,
        transaction.max_priority_fee_per_gas,
        ctx.base_fee,
        transaction.fee_rate,
    )?;
    Ok((charge, payload))
}

/// Appends the instructions a payload compiles to, between holding the fee and
/// settling it.
fn compile_payload(
    payload: &Payload,
    sender: L2Address,
    instructions: &mut Vec<Instruction>,
) -> Result<(), CompileError> {
    match payload {
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
                epoch: *epoch,
                digest: update.signing_digest(*epoch),
                signatures: signatures.clone(),
                guardian: update.guardian_may_apply(),
            });
            instructions.push(match update {
                GovernanceUpdate::SetGasAsset { record } => Instruction::SetGasAsset {
                    record: record.clone(),
                },
                GovernanceUpdate::SetParameter { name, value } => Instruction::SetParameter {
                    name: name.clone(),
                    value: *value,
                },
                GovernanceUpdate::SetJwk {
                    iss_hash,
                    jwk_hash,
                    active,
                } => Instruction::SetJwk {
                    iss_hash: *iss_hash,
                    jwk_hash: *jwk_hash,
                    active: *active,
                },
                GovernanceUpdate::SetFeeMarket { floor, target } => Instruction::SetFeeMarket {
                    floor: *floor,
                    target: *target,
                },
                GovernanceUpdate::SetFeeSplit { split } => Instruction::SetFeeSplit {
                    split: split.clone(),
                },
                GovernanceUpdate::DisableGasAsset { asset } => {
                    Instruction::DisableGasAsset { asset: *asset }
                }
            });
        }
        Payload::DistributeFees {
            asset,
            amount,
            split,
        } => {
            if *amount == 0 || split.check().is_err() {
                return Err(CompileError::BadDistribution);
            }
            compile_distribution(*asset, *amount, split, instructions)?;
        }
    }

    Ok(())
}

/// A fee distribution: check the split, take `amount` from the vault, and pay
/// each beneficiary its share. What the shares leave, rounding included, is
/// burned by not being credited anywhere.
fn compile_distribution(
    asset: AssetId,
    amount: u128,
    split: &FeeSplit,
    instructions: &mut Vec<Instruction>,
) -> Result<(), CompileError> {
    instructions.push(Instruction::VerifyFeeSplit {
        split: split.clone(),
    });
    instructions.push(Instruction::Debit {
        account: FEE_VAULT,
        asset,
        amount,
    });
    for (account, value) in split.shares_of(amount)? {
        if value > 0 {
            instructions.push(Instruction::Credit {
                account,
                asset,
                amount: value,
            });
        }
    }
    Ok(())
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
    /// Where each transaction's instructions begin, one entry per transaction.
    /// What the batch commitment's leaves record as `start_pc`.
    pub tx_starts: Vec<u64>,
}

impl ExecutionTrace {
    /// Builds the batch commitment tree for the transactions this trace
    /// executed, in order.
    ///
    /// # Panics
    ///
    /// Panics if `transactions` is not the batch the trace was produced from
    /// (a different count).
    #[must_use]
    pub fn batch_tree(&self, transactions: &[Transaction]) -> crate::batch::BatchTree {
        assert_eq!(
            transactions.len(),
            self.tx_starts.len(),
            "the trace and the batch must match"
        );
        let leaves: Vec<(u64, Vec<u8>)> = self
            .tx_starts
            .iter()
            .zip(transactions)
            .map(|(start, tx)| (*start, tx.encode()))
            .collect();
        crate::batch::BatchTree::build(&leaves)
    }

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
    ctx: &BatchContext<'_>,
    transactions: &[Transaction],
) -> Result<ExecutionTrace, BatchError> {
    let mut instructions = Vec::new();
    let mut states = vec![MachineState::start(trie.root())];
    let mut tx_starts = Vec::with_capacity(transactions.len());

    for (index, transaction) in transactions.iter().enumerate() {
        tx_starts.push(u64::try_from(instructions.len()).expect("trace length fits in u64"));
        let compiled =
            compile(transaction, ctx).map_err(|source| BatchError::Compile { index, source })?;

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
        tx_starts,
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
