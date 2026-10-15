//! End-to-end tests for the state transition function.
//!
//! The most important test here is [`l1_verification_agrees_with_node_execution`]
//! and its property-test companion. Everything else in SENA's security argument
//! rests on the claim that what Aptos L1 computes for a disputed step is exactly
//! what an honest node computes for it. If those two paths can ever disagree,
//! either a fraudster wins a dispute they should lose, or an honest sequencer is
//! slashed for a correct assertion.

use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_primitives::{AssetId, Channel, Hash256, HashedIdentifier, L2Address, NetworkSalt};
use sena_state::MerkleTrie;
use sena_stf::execute::{genesis_credit, StepWitness};
use sena_stf::gas::{native_to_asset, DEFAULT_ASSET_INTRINSIC_GAS, DEFAULT_BASE_FEE_FLOOR};
use sena_stf::{
    apply, compile, execute_batch, keys, verify_step, Account, Authenticator, BatchContext,
    BatchError, CompileError, Council, CouncilSignature, GovernanceUpdate, Instruction,
    MachineState, Payload, SocialBinding, StepError, Transaction, WhitelistedAsset, FEE_VAULT,
    RATE_SCALE,
};
use sena_stf::{fee_charge, gas_required, GasError};

/// Ed25519 accounts only; keyless is off.
const CTX: BatchContext<'static> = BatchContext::without_keyless(0);
const USDC: AssetId = AssetId(1);

/// The rate USDC is whitelisted at in these tests: one-to-one with native units.
const USDC_RATE: u128 = RATE_SCALE;

/// What a transaction pays, net of its refund: the base fee (tips go to the
/// fee vault too under [`CTX`]).
fn fee_of(tx: &Transaction) -> u128 {
    let c = fee_charge(tx, &CTX).unwrap();
    c.base + c.tip
}

/// Sets a transaction's fee terms: the gas it needs, at the base fee.
fn with_fees(mut tx: Transaction) -> Transaction {
    tx.fee_intrinsic_gas = DEFAULT_ASSET_INTRINSIC_GAS;
    tx.max_fee_per_gas = DEFAULT_BASE_FEE_FLOOR;
    tx.max_priority_fee_per_gas = 0;
    tx.gas_limit = 0;
    // Payloads that are meant not to compile still get a usable limit.
    tx.gas_limit = gas_required(&tx).unwrap_or(100_000);
    tx
}

/// A deterministic test signer. The seed is fixed so failures reproduce.
fn signer(seed: u8) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(u64::from(seed));
    SigningKey::generate(&mut rng)
}

fn address_of(key: &SigningKey) -> L2Address {
    L2Address::from_bytes(key.verifying_key().to_bytes())
}

/// Builds a signed transaction.
fn signed(key: &SigningKey, nonce: u64, payload: Payload) -> Transaction {
    let mut tx = with_fees(Transaction {
        sender: address_of(key),
        nonce,
        fee_asset: USDC,
        fee_rate: USDC_RATE,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload,
        authenticator: Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    });
    let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature,
    };
    tx
}

/// A trie with USDC whitelisted for fees and the listed accounts funded.
/// Re-signs a transaction after its fields have been altered.
fn resign(key: &SigningKey, mut tx: Transaction) -> Transaction {
    let signature = key.sign(tx.signing_digest().as_bytes()).to_bytes();
    tx.authenticator = Authenticator::Ed25519 {
        public_key: key.verifying_key().to_bytes(),
        signature,
    };
    tx
}

fn funded_trie(accounts: &[(L2Address, u128)]) -> MerkleTrie {
    let mut trie = MerkleTrie::new();
    whitelist(&mut trie, USDC, "USDC", USDC_RATE, true);
    for (address, amount) in accounts {
        genesis_credit(&mut trie, *address, USDC, *amount);
    }
    trie
}

/// Writes a gas asset record directly, as genesis would.
fn whitelist(trie: &mut MerkleTrie, asset: AssetId, symbol: &str, rate: u128, enabled: bool) {
    let record = WhitelistedAsset {
        asset,
        symbol: symbol.to_owned(),
        rate,
        intrinsic_gas: DEFAULT_ASSET_INTRINSIC_GAS,
        enabled,
    };
    apply(trie, &Instruction::SetGasAsset { record }).unwrap();
}

/// Installs a council with the given members and threshold, at epoch 1.
fn install_council(trie: &mut MerkleTrie, keys: &[SigningKey], threshold: u32) {
    let council = Council {
        members: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        threshold,
        epoch: 1,
        guardian_threshold: 0,
    };
    trie.insert(keys::council(), council.encode());
}

/// Signs a governance update with the given council members.
fn council_sign(
    keys: &[(u32, &SigningKey)],
    update: &GovernanceUpdate,
    epoch: u64,
) -> Vec<CouncilSignature> {
    let digest = update.signing_digest(epoch);
    keys.iter()
        .map(|(index, key)| CouncilSignature {
            index: *index,
            signature: key.sign(digest.as_bytes()).to_bytes(),
        })
        .collect()
}

fn account_in(trie: &MerkleTrie, address: &L2Address) -> Account {
    trie.get(&keys::account(address))
        .map_or_else(Account::new, |b| Account::decode(b).unwrap())
}

// --- Transfers ---------------------------------------------------------------

#[test]
fn a_transfer_moves_value_and_charges_a_fee() {
    let alice = signer(1);
    let bob = address_of(&signer(2));
    let mut trie = funded_trie(&[(address_of(&alice), 10_000)]);

    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: bob,
            asset: USDC,
            amount: 2_500,
        },
    );
    let fee = fee_of(&tx);
    execute_batch(&mut trie, &CTX, &[tx]).expect("transfer should execute");

    assert_eq!(account_in(&trie, &bob).balance(USDC), 2_500);
    assert_eq!(
        account_in(&trie, &address_of(&alice)).balance(USDC),
        10_000 - 2_500 - fee
    );
    assert_eq!(account_in(&trie, &FEE_VAULT).balance(USDC), fee);
    assert_eq!(account_in(&trie, &address_of(&alice)).nonce, 1);
}

#[test]
fn value_is_conserved_across_a_batch() {
    // Nothing may be minted or destroyed: the fee vault must account for exactly
    // the difference. This is the invariant a balance-inflation fraud violates.
    let alice = signer(1);
    let bob = signer(2);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000), (address_of(&bob), 50_000)]);
    let total_before = 100_000u128;

    let batch = vec![
        signed(
            &alice,
            0,
            Payload::Transfer {
                to: address_of(&bob),
                asset: USDC,
                amount: 1_000,
            },
        ),
        signed(
            &bob,
            0,
            Payload::Transfer {
                to: address_of(&alice),
                asset: USDC,
                amount: 700,
            },
        ),
    ];
    execute_batch(&mut trie, &CTX, &batch).unwrap();

    let total_after = account_in(&trie, &address_of(&alice)).balance(USDC)
        + account_in(&trie, &address_of(&bob)).balance(USDC)
        + account_in(&trie, &FEE_VAULT).balance(USDC);
    assert_eq!(total_before, total_after, "value must be conserved");
}

#[test]
fn a_transfer_beyond_the_balance_invalidates_the_batch() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 5_000)]);

    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1_000_000,
        },
    );
    let err = execute_batch(&mut trie, &CTX, &[tx]).unwrap_err();
    assert!(matches!(err, BatchError::Step { .. }), "got {err:?}");
}

#[test]
fn a_self_transfer_is_rejected() {
    let alice = signer(1);
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&alice),
            asset: USDC,
            amount: 1,
        },
    );
    assert_eq!(compile(&tx, &CTX).unwrap_err(), CompileError::SelfTransfer);
}

// --- Authentication and replay ----------------------------------------------

#[test]
fn a_tampered_transaction_does_not_authenticate() {
    let alice = signer(1);
    let mut tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );

    // Redirect the funds after signing — the attack the signing digest exists
    // to prevent.
    tx.payload = Payload::Transfer {
        to: address_of(&signer(3)),
        asset: USDC,
        amount: 1,
    };
    assert!(compile(&tx, &CTX).is_err());
}

#[test]
fn raising_the_fee_after_signing_is_detected() {
    let alice = signer(1);
    let mut tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );
    tx.max_fee_per_gas += 1;
    assert!(
        compile(&tx, &CTX).is_err(),
        "the fee terms must be covered by the signature"
    );
}

#[test]
fn a_transaction_cannot_be_replayed() {
    // NFR-SEC-005. The second execution must fail on the nonce.
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000)]);
    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 10,
        },
    );

    execute_batch(&mut trie, &CTX, std::slice::from_ref(&tx)).expect("first execution succeeds");
    let err = execute_batch(&mut trie, &CTX, &[tx]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::NonceMismatch { .. },
                ..
            }
        ),
        "replay must be rejected, got {err:?}"
    );
}

#[test]
fn keyless_is_refused_on_a_network_without_it() {
    // A network that has not configured keyless parameters must refuse the
    // scheme outright; the proof is never looked at. (Proof verification
    // itself is covered against Aptos's vectors in keyless_aptos_vectors.rs.)
    let alice = signer(1);
    let mut tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );
    tx.authenticator = Authenticator::Keyless(Box::new(sena_stf::KeylessSignature {
        iss_hash: [0; 32],
        idc: [0; 32],
        ephemeral_public_key: alice.verifying_key().to_bytes(),
        ephemeral_signature: alice.sign(tx.signing_digest().as_bytes()).to_bytes(),
        exp_date_secs: u64::MAX,
        exp_horizon_secs: 0,
        jwt_header_hash: [0; 32],
        jwk_hash: [0; 32],
        extra_field_hash: None,
        proof: [0; 128],
    }));
    assert_eq!(
        compile(&tx, &CTX).unwrap_err(),
        CompileError::Auth(sena_stf::AuthError::Keyless(
            sena_stf::KeylessError::Disabled
        ))
    );
}

/// The key that signs must be the sender's own key.
///
/// Regression test: authentication once checked only that the signature
/// matched the key carried in the transaction, so any keypair could spend from
/// any account by naming it as the sender.
#[test]
fn a_key_cannot_spend_from_an_account_it_does_not_own() {
    let victim = signer(1);
    let thief = signer(66);
    let mut trie = funded_trie(&[(address_of(&victim), 10_000)]);

    let theft = resign(
        &thief,
        Transaction {
            sender: address_of(&victim),
            ..signed(
                &thief,
                0,
                Payload::Transfer {
                    to: address_of(&thief),
                    asset: USDC,
                    amount: 9_000,
                },
            )
        },
    );

    assert_eq!(
        compile(&theft, &CTX).unwrap_err(),
        CompileError::Auth(sena_stf::AuthError::WrongSigner)
    );
    assert!(execute_batch(&mut trie, &CTX, &[theft]).is_err());
    assert_eq!(
        account_in(&trie, &address_of(&victim)).balance(USDC),
        10_000
    );
}

/// A small-order public key is refused even with a "valid" signature.
///
/// The identity point verifies the all-zero-`R` signature for every message
/// under lenient verification. Aptos L1 uses strict verification, so the node
/// must too or the two would disagree in a dispute.
#[test]
fn a_small_order_key_is_refused() {
    let mut identity = [0u8; 32];
    identity[0] = 1; // compressed Edwards identity
    let mut signature = [0u8; 64];
    signature[0] = 1; // R = identity, S = 0
    let tx = Transaction {
        sender: L2Address::from_bytes(identity),
        nonce: 0,
        fee_asset: USDC,
        fee_rate: USDC_RATE,
        fee_intrinsic_gas: DEFAULT_ASSET_INTRINSIC_GAS,
        gas_limit: 100_000,
        max_fee_per_gas: DEFAULT_BASE_FEE_FLOOR,
        max_priority_fee_per_gas: 0,
        payload: Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
        authenticator: Authenticator::Ed25519 {
            public_key: identity,
            signature,
        },
    };
    assert!(matches!(
        compile(&tx, &CTX).unwrap_err(),
        CompileError::Auth(sena_stf::AuthError::MalformedKey | sena_stf::AuthError::BadSignature)
    ));
}

// --- Social Connect ----------------------------------------------------------

fn handle(name: &str) -> HashedIdentifier {
    HashedIdentifier::new(Channel::Handle, name, &NetworkSalt::new(*b"test-salt"))
}

#[test]
fn an_identifier_resolves_to_its_owner() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000)]);
    let id = handle("@alice");

    let tx = signed(
        &alice,
        0,
        Payload::BindIdentifier {
            channel: Channel::Handle,
            identifier: id,
        },
    );
    execute_batch(&mut trie, &CTX, &[tx]).unwrap();

    let stored = trie
        .get(&keys::social_by_identifier(&id))
        .expect("binding should exist");
    assert_eq!(
        SocialBinding::decode(stored).unwrap().address(),
        Some(address_of(&alice))
    );
}

#[test]
fn an_identifier_cannot_be_taken_from_its_owner() {
    let alice = signer(1);
    let mallory = signer(2);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000), (address_of(&mallory), 50_000)]);
    let id = handle("@alice");

    execute_batch(
        &mut trie,
        &CTX,
        &[signed(
            &alice,
            0,
            Payload::BindIdentifier {
                channel: Channel::Handle,
                identifier: id,
            },
        )],
    )
    .unwrap();

    let theft = signed(
        &mallory,
        0,
        Payload::BindIdentifier {
            channel: Channel::Handle,
            identifier: id,
        },
    );
    let err = execute_batch(&mut trie, &CTX, &[theft]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::IdentifierTaken,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn releasing_an_identifier_frees_it_for_someone_else() {
    let alice = signer(1);
    let bob = signer(2);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000), (address_of(&bob), 50_000)]);
    let id = handle("@shared");

    execute_batch(
        &mut trie,
        &CTX,
        &[
            signed(
                &alice,
                0,
                Payload::BindIdentifier {
                    channel: Channel::Handle,
                    identifier: id,
                },
            ),
            signed(&alice, 1, Payload::UnbindIdentifier { identifier: id }),
            signed(
                &bob,
                0,
                Payload::BindIdentifier {
                    channel: Channel::Handle,
                    identifier: id,
                },
            ),
        ],
    )
    .unwrap();

    let stored = trie.get(&keys::social_by_identifier(&id)).unwrap();
    assert_eq!(
        SocialBinding::decode(stored).unwrap().address(),
        Some(address_of(&bob))
    );
}

#[test]
fn releasing_an_identifier_you_do_not_hold_fails() {
    let alice = signer(1);
    let mallory = signer(2);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000), (address_of(&mallory), 50_000)]);
    let id = handle("@alice");

    execute_batch(
        &mut trie,
        &CTX,
        &[signed(
            &alice,
            0,
            Payload::BindIdentifier {
                channel: Channel::Handle,
                identifier: id,
            },
        )],
    )
    .unwrap();

    let err = execute_batch(
        &mut trie,
        &CTX,
        &[signed(
            &mallory,
            0,
            Payload::UnbindIdentifier { identifier: id },
        )],
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::IdentifierNotHeld,
                ..
            }
        ),
        "got {err:?}"
    );
}

// --- The trace ---------------------------------------------------------------

#[test]
fn the_trace_records_a_state_for_every_step_boundary() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 50_000)]);
    let pre_root = trie.root();

    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 5,
        },
    );
    let trace = execute_batch(&mut trie, &CTX, &[tx]).unwrap();

    assert_eq!(trace.states.len(), trace.instructions.len() + 1);
    assert_eq!(trace.initial().state_root, pre_root);
    assert_eq!(trace.final_state().state_root, trie.root());
    // nonce, gas-asset check, base fee charge, fee hold, transfer debit,
    // transfer credit, base fee credit. No refund (the limit is exactly the gas
    // used) and no tip, so neither is credited.
    assert_eq!(trace.len(), 7);
}

#[test]
fn determinism_the_same_batch_yields_the_same_root() {
    let alice = signer(1);
    let batch = vec![
        signed(
            &alice,
            0,
            Payload::Transfer {
                to: address_of(&signer(2)),
                asset: USDC,
                amount: 7,
            },
        ),
        signed(
            &alice,
            1,
            Payload::BindIdentifier {
                channel: Channel::Handle,
                identifier: handle("@a"),
            },
        ),
    ];

    let mut first = funded_trie(&[(address_of(&alice), 50_000)]);
    let mut second = funded_trie(&[(address_of(&alice), 50_000)]);
    let a = execute_batch(&mut first, &CTX, &batch).unwrap();
    let b = execute_batch(&mut second, &CTX, &batch).unwrap();

    println!("root={}", a.final_state().state_root);
    assert_eq!(a.final_state().state_root, b.final_state().state_root);
    assert_eq!(a.states, b.states, "the whole trace must be reproducible");
}

// --- L1 / node equivalence: the foundation of fraud proofs -------------------

/// Assembles the witness Aptos L1 would be handed for `step` of `trace`.
fn witness_for(trie_before: &MerkleTrie, instruction: &Instruction) -> StepWitness {
    let slot = instruction.slot();
    StepWitness {
        slot,
        value: trie_before.get(&slot).map(<[u8]>::to_vec),
        proof: trie_before.prove(&slot),
    }
}

#[test]
fn l1_verification_agrees_with_node_execution() {
    let alice = signer(1);
    let bob = signer(2);
    let mut trie = funded_trie(&[(address_of(&alice), 90_000), (address_of(&bob), 90_000)]);

    let batch = vec![
        signed(
            &alice,
            0,
            Payload::Transfer {
                to: address_of(&bob),
                asset: USDC,
                amount: 1_234,
            },
        ),
        signed(
            &bob,
            0,
            Payload::BindIdentifier {
                channel: Channel::Handle,
                identifier: handle("@bob"),
            },
        ),
        signed(
            &bob,
            1,
            Payload::Transfer {
                to: address_of(&alice),
                asset: USDC,
                amount: 99,
            },
        ),
    ];

    // Replay the batch one step at a time, and at each step check that the
    // stateless verifier derives exactly the state the node did.
    let mut replay = funded_trie(&[(address_of(&alice), 90_000), (address_of(&bob), 90_000)]);
    let trace = execute_batch(&mut trie, &CTX, &batch).unwrap();

    for (index, instruction) in trace.instructions.iter().enumerate() {
        let witness = witness_for(&replay, instruction);
        let pre = trace.states[index];
        let expected = trace.states[index + 1];

        let derived = verify_step(&pre, instruction, &witness)
            .unwrap_or_else(|e| panic!("step {index} failed L1 verification: {e}"));

        assert_eq!(
            derived, expected,
            "step {index}: L1 derived {derived:?} but the node computed {expected:?}"
        );
        apply(&mut replay, instruction).unwrap();
    }

    assert_eq!(replay.root(), trie.root());
}

#[test]
fn l1_rejects_a_witness_for_the_wrong_slot() {
    let alice = address_of(&signer(1));
    let mallory = address_of(&signer(2));
    let trie = funded_trie(&[(alice, 10_000), (mallory, 10_000)]);

    let instruction = Instruction::Debit {
        account: alice,
        asset: USDC,
        amount: 1,
    };
    // Substitute Mallory's slot, hoping the debit lands on her account instead.
    let wrong = Instruction::Debit {
        account: mallory,
        asset: USDC,
        amount: 1,
    };
    let witness = witness_for(&trie, &wrong);

    let err = verify_step(&MachineState::start(trie.root()), &instruction, &witness).unwrap_err();
    assert!(
        matches!(err, StepError::WitnessSlotMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn l1_rejects_a_witness_that_misreports_the_slot_contents() {
    let alice = address_of(&signer(1));
    let trie = funded_trie(&[(alice, 10_000)]);

    let instruction = Instruction::Debit {
        account: alice,
        asset: USDC,
        amount: 1,
    };
    let mut witness = witness_for(&trie, &instruction);

    // Claim a far larger balance than the account actually holds — the move that
    // would let a fraudulent debit appear valid.
    let mut inflated = Account::new();
    inflated.credit(USDC, 999_999_999).unwrap();
    witness.value = Some(inflated.encode());

    let err = verify_step(&MachineState::start(trie.root()), &instruction, &witness).unwrap_err();
    assert!(matches!(err, StepError::BadWitnessProof(_)), "got {err:?}");
}

#[test]
fn l1_rejects_a_witness_proved_against_a_different_root() {
    let alice = address_of(&signer(1));
    let trie = funded_trie(&[(alice, 10_000)]);
    let instruction = Instruction::Credit {
        account: alice,
        asset: USDC,
        amount: 1,
    };
    let witness = witness_for(&trie, &instruction);

    let unrelated = MachineState::start(Hash256::digest(b"some other state"));
    assert!(verify_step(&unrelated, &instruction, &witness).is_err());
}

#[test]
fn l1_catches_an_invalid_step_an_honest_node_would_refuse() {
    // The dispute this whole mechanism exists to resolve: a sequencer claims a
    // debit that the account cannot cover.
    let alice = address_of(&signer(1));
    let trie = funded_trie(&[(alice, 100)]);

    let fraudulent = Instruction::Debit {
        account: alice,
        asset: USDC,
        amount: 1_000_000,
    };
    let witness = witness_for(&trie, &fraudulent);

    let err = verify_step(&MachineState::start(trie.root()), &fraudulent, &witness).unwrap_err();
    assert!(matches!(err, StepError::Balance(_)), "got {err:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Over arbitrary transfer batches, every step the node executes verifies on
    /// L1 to exactly the same machine state. Any divergence would be a
    /// consensus-critical bug.
    #[test]
    fn l1_and_node_agree_on_arbitrary_batches(
        amounts in prop::collection::vec(0u128..3_000, 1..12),
    ) {
        let alice = signer(1);
        let bob = address_of(&signer(2));
        let funding = 5_000_000u128;

        let batch: Vec<_> = amounts
            .iter()
            .enumerate()
            .map(|(i, amount)| {
                let nonce = u64::try_from(i).unwrap();
                signed(&alice, nonce, Payload::Transfer { to: bob, asset: USDC, amount: *amount })
            })
            .collect();

        let mut trie = funded_trie(&[(address_of(&alice), funding)]);
        let mut replay = funded_trie(&[(address_of(&alice), funding)]);
        let trace = execute_batch(&mut trie, &CTX, &batch).unwrap();

        for (index, instruction) in trace.instructions.iter().enumerate() {
            let witness = witness_for(&replay, instruction);
            let derived = verify_step(&trace.states[index], instruction, &witness)?;
            prop_assert_eq!(derived, trace.states[index + 1]);
            apply(&mut replay, instruction).unwrap();
        }
    }
}

// --- Multi-asset gas --------------------------------------------------------

#[test]
fn a_fee_is_charged_in_the_declared_stablecoin() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);

    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 10,
        },
    );
    let fee = fee_of(&tx);
    execute_batch(&mut trie, &CTX, &[tx]).unwrap();

    // No native token was needed at any point (REQ-GAS-002).
    assert_eq!(
        account_in(&trie, &address_of(&alice)).balance(AssetId::NATIVE),
        0
    );
    assert_eq!(account_in(&trie, &FEE_VAULT).balance(USDC), fee);
}

#[test]
fn an_unlisted_asset_cannot_pay_fees() {
    let alice = signer(1);
    let mut trie = MerkleTrie::new();
    genesis_credit(&mut trie, address_of(&alice), AssetId(77), 100_000);

    let mut tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: AssetId(77),
            amount: 1,
        },
    );
    tx.fee_asset = AssetId(77);
    let tx = resign(&alice, tx);

    let err = execute_batch(&mut trie, &CTX, &[tx]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::AssetNotWhitelisted,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn a_disabled_asset_cannot_pay_fees() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    whitelist(&mut trie, USDC, "USDC", USDC_RATE, false);

    let tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );
    let err = execute_batch(&mut trie, &CTX, &[tx]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::AssetDisabled,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn a_transaction_cannot_declare_a_cheaper_rate_than_the_chain_holds() {
    // The fraud this in-trace check exists to catch: a sender (or a colluding
    // sequencer) claiming a rate that makes execution nearly free.
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);

    let mut tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );
    // A rate other than the whitelisted one, with fee terms that cover it.
    tx.fee_rate = 2 * USDC_RATE;
    tx.max_fee_per_gas = 2 * DEFAULT_BASE_FEE_FLOOR;
    let tx = resign(&alice, tx);

    let err = execute_batch(&mut trie, &CTX, &[tx]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::GasRateMismatch { .. },
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn a_max_fee_below_the_base_fee_is_refused_at_compile_time() {
    let alice = signer(1);
    let mut tx = signed(
        &alice,
        0,
        Payload::Transfer {
            to: address_of(&signer(2)),
            asset: USDC,
            amount: 1,
        },
    );
    tx.max_fee_per_gas = DEFAULT_BASE_FEE_FLOOR - 1;
    let tx = resign(&alice, tx);
    assert!(matches!(
        compile(&tx, &CTX).unwrap_err(),
        CompileError::Gas(GasError::FeeBelowBaseFee { .. })
    ));
}

#[test]
fn a_cheaper_asset_costs_proportionally_more_units() {
    // An asset worth half a native unit should cost twice as many units.
    let half_value = RATE_SCALE * 2;
    assert_eq!(
        native_to_asset(DEFAULT_BASE_FEE_FLOOR, half_value).unwrap(),
        2 * native_to_asset(DEFAULT_BASE_FEE_FLOOR, RATE_SCALE).unwrap()
    );
}

// --- Governance --------------------------------------------------------------

#[test]
fn the_council_can_whitelist_a_new_gas_asset() {
    let alice = signer(1);
    let m1 = signer(10);
    let m2 = signer(11);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, &[m1.clone(), m2.clone()], 2);

    let update = GovernanceUpdate::SetGasAsset {
        record: WhitelistedAsset {
            asset: AssetId(2),
            symbol: "EURC".to_owned(),
            rate: RATE_SCALE,
            intrinsic_gas: DEFAULT_ASSET_INTRINSIC_GAS,
            enabled: true,
        },
    };
    let signatures = council_sign(&[(0, &m1), (1, &m2)], &update, 1);

    let tx = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 1,
            update,
            signatures,
        },
    );
    execute_batch(&mut trie, &CTX, &[tx]).expect("a quorum-signed update should apply");

    let stored = trie.get(&keys::asset(2)).expect("record should exist");
    assert_eq!(WhitelistedAsset::decode(stored).unwrap().symbol, "EURC");
}

#[test]
fn an_update_without_a_quorum_is_refused() {
    let alice = signer(1);
    let m1 = signer(10);
    let m2 = signer(11);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, &[m1.clone(), m2], 2);

    let update = GovernanceUpdate::SetParameter {
        name: "batch.max_transactions".to_owned(),
        value: 5,
    };
    let signatures = council_sign(&[(0, &m1)], &update, 1); // one of two

    let tx = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 1,
            update,
            signatures,
        },
    );
    let err = execute_batch(&mut trie, &CTX, &[tx]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::Governance(_),
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn a_forged_council_signature_is_refused() {
    let alice = signer(1);
    let m1 = signer(10);
    let impostor = signer(99);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, std::slice::from_ref(&m1), 1);

    let update = GovernanceUpdate::SetParameter {
        name: "batch.max_transactions".to_owned(),
        value: 5,
    };
    let signatures = council_sign(&[(0, &impostor)], &update, 1);

    let tx = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 1,
            update,
            signatures,
        },
    );
    assert!(execute_batch(&mut trie, &CTX, &[tx]).is_err());
}

#[test]
fn a_governance_payload_cannot_be_replayed_in_a_later_epoch() {
    let alice = signer(1);
    let m1 = signer(10);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, std::slice::from_ref(&m1), 1);

    let update = GovernanceUpdate::SetParameter {
        name: "batch.max_transactions".to_owned(),
        value: 5,
    };
    let signatures = council_sign(&[(0, &m1)], &update, 1);

    // Same signatures, different epoch.
    let replayed = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 2,
            update,
            signatures,
        },
    );
    assert!(execute_batch(&mut trie, &CTX, &[replayed]).is_err());
}

/// Regression test: the epoch was signed over but never checked against state,
/// so an applied payload could be re-submitted indefinitely — re-enabling an
/// asset the council had since disabled, for instance.
#[test]
fn an_applied_governance_payload_cannot_be_applied_again() {
    let alice = signer(1);
    let m1 = signer(10);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, std::slice::from_ref(&m1), 1);

    let update = GovernanceUpdate::SetParameter {
        name: "batch.max_transactions".to_owned(),
        value: 5,
    };
    let signatures = council_sign(&[(0, &m1)], &update, 1);
    let payload = Payload::Governance {
        epoch: 1,
        update,
        signatures,
    };
    execute_batch(&mut trie, &CTX, &[signed(&alice, 0, payload.clone())])
        .expect("first application succeeds");

    let council = Council::decode(trie.get(&keys::council()).unwrap()).unwrap();
    assert_eq!(council.epoch, 2, "applying a payload consumes its epoch");

    let err = execute_batch(&mut trie, &CTX, &[signed(&alice, 1, payload)]).unwrap_err();
    assert!(
        matches!(
            err,
            BatchError::Step {
                source: StepError::Governance(sena_stf::GovernanceError::WrongEpoch {
                    expected: 2,
                    signed: 1
                }),
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn the_council_cannot_reach_the_dispute_system() {
    // REQ-GOV-007. Even a unanimous, correctly signed council must not be able
    // to touch the challenge window or anything else outside the allowlist --
    // a council that could rescue a fraudulent assertion would nullify the
    // entire fraud proof system.
    let alice = signer(1);
    let m1 = signer(10);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, std::slice::from_ref(&m1), 1);

    for name in ["challenge_window", "assertion.finalize", "dispute.outcome"] {
        let update = GovernanceUpdate::SetParameter {
            name: name.to_owned(),
            value: 0,
        };
        let signatures = council_sign(&[(0, &m1)], &update, 1);
        let tx = signed(
            &alice,
            0,
            Payload::Governance {
                epoch: 1,
                update,
                signatures,
            },
        );

        assert!(
            execute_batch(&mut trie.clone(), &CTX, &[tx]).is_err(),
            "'{name}' must be unreachable by governance"
        );
    }
}

#[test]
fn governance_changes_are_covered_by_the_execution_trace() {
    // REQ-GOV-006: a governance update is an ordinary batch step, so it is
    // disputable exactly like sequencer fraud. Verify the L1 path agrees.
    let alice = signer(1);
    let m1 = signer(10);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, std::slice::from_ref(&m1), 1);
    let mut replay = trie.clone();

    let update = GovernanceUpdate::SetParameter {
        name: "batch.max_transactions".to_owned(),
        value: 512,
    };
    let signatures = council_sign(&[(0, &m1)], &update, 1);
    let tx = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 1,
            update,
            signatures,
        },
    );

    let trace = execute_batch(&mut trie, &CTX, &[tx]).unwrap();
    for (index, instruction) in trace.instructions.iter().enumerate() {
        let witness = witness_for(&replay, instruction);
        let derived = verify_step(&trace.states[index], instruction, &witness)
            .unwrap_or_else(|e| panic!("governance step {index} failed on L1: {e}"));
        assert_eq!(derived, trace.states[index + 1]);
        apply(&mut replay, instruction).unwrap();
    }
}

// --- The fee market ---------------------------------------------------------

fn market_in(trie: &MerkleTrie) -> sena_stf::FeeMarket {
    trie.get(&keys::fee_market()).map_or(
        sena_stf::FeeMarket::genesis(DEFAULT_BASE_FEE_FLOOR, sena_stf::gas::DEFAULT_GAS_TARGET),
        |b| sena_stf::FeeMarket::decode(b).unwrap(),
    )
}

fn transfer_of(key: &SigningKey, nonce: u64, amount: u128) -> Transaction {
    signed(
        key,
        nonce,
        Payload::Transfer {
            to: address_of(&signer(99)),
            asset: USDC,
            amount,
        },
    )
}

#[test]
fn unused_gas_is_refunded_the_tip_paid_and_the_base_fee_collected() {
    let alice = signer(1);
    let sequencer = address_of(&signer(50));
    let mut trie = funded_trie(&[(address_of(&alice), 1_000_000)]);
    let mut tx = transfer_of(&alice, 0, 7);
    let used = tx.gas_limit;
    tx.gas_limit = used + 40_000;
    tx.max_fee_per_gas = 3 * DEFAULT_BASE_FEE_FLOOR;
    tx.max_priority_fee_per_gas = DEFAULT_BASE_FEE_FLOOR / 5;
    let tx = resign(&alice, tx);
    let ctx = BatchContext {
        fee_recipient: sequencer,
        ..CTX
    };

    let c = fee_charge(&tx, &ctx).unwrap();
    // Effective price: base + tip = 1.2 × floor; the 3 × floor cap is not charged.
    let price = DEFAULT_BASE_FEE_FLOOR * 6 / 5;
    assert_eq!(
        c.hold,
        u128::from(tx.gas_limit) * price / sena_stf::PRICE_SCALE
    );
    assert_eq!(c.refund + c.tip + c.base, c.hold);
    assert!(c.refund > 0 && c.tip > 0);

    execute_batch(&mut trie, &ctx, &[tx]).unwrap();
    assert_eq!(
        account_in(&trie, &address_of(&alice)).balance(USDC),
        1_000_000 - 7 - c.tip - c.base
    );
    assert_eq!(account_in(&trie, &sequencer).balance(USDC), c.tip);
    assert_eq!(account_in(&trie, &FEE_VAULT).balance(USDC), c.base);
    assert_eq!(market_in(&trie).window_gas, used);
}

#[test]
fn the_base_fee_follows_demand_between_windows() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 10_000_000)]);
    // A tiny target, so one transfer overshoots it.
    apply(
        &mut trie,
        &Instruction::SetFeeMarket {
            floor: DEFAULT_BASE_FEE_FLOOR,
            target: 1_000,
        },
    )
    .unwrap();
    let busy = BatchContext::without_keyless(10);
    let mut tx = transfer_of(&alice, 0, 1);
    tx.gas_limit = 0; // recomputed below
    let tx = resign(&alice, with_fees(tx));
    // One transaction can use at most twice the target.
    assert!(matches!(
        execute_batch(&mut trie.clone(), &busy, std::slice::from_ref(&tx)).unwrap_err(),
        BatchError::Step {
            source: StepError::WindowFull,
            ..
        }
    ));
    apply(
        &mut trie,
        &Instruction::SetFeeMarket {
            floor: DEFAULT_BASE_FEE_FLOOR,
            target: tx.gas_limit,
        },
    )
    .unwrap();
    // Two transfers fill the window to its limit: the next window costs 1/8 more.
    let second = resign(&alice, with_fees(transfer_of(&alice, 1, 1)));
    execute_batch(&mut trie, &busy, &[tx, second]).unwrap();
    let next = market_in(&trie).base_fee_at(11).unwrap();
    assert_eq!(next, DEFAULT_BASE_FEE_FLOOR + DEFAULT_BASE_FEE_FLOOR / 8);

    // A batch declaring the old base fee in the new window is fraud.
    let third = transfer_of(&alice, 2, 1);
    let stale = BatchContext::without_keyless(11);
    assert!(matches!(
        execute_batch(&mut trie.clone(), &stale, std::slice::from_ref(&third)).unwrap_err(),
        BatchError::Step {
            source: StepError::BaseFeeMismatch { .. },
            ..
        }
    ));
    let mut priced = third;
    priced.max_fee_per_gas = next;
    let priced = resign(&alice, priced);
    let right = BatchContext {
        base_fee: next,
        ..stale
    };
    execute_batch(&mut trie, &right, &[priced]).unwrap();
    // That window used exactly its target, so the fee holds; after a window
    // with nothing in it, it falls by 1/8 -- but never below the floor.
    let held = market_in(&trie).at(12).unwrap();
    assert_eq!(held.base_fee, next);
    assert_eq!(held.at(13).unwrap().base_fee, DEFAULT_BASE_FEE_FLOOR);
}

#[test]
fn an_undeclared_intrinsic_gas_is_refused_in_the_trace() {
    let alice = signer(1);
    let mut trie = funded_trie(&[(address_of(&alice), 1_000_000)]);
    let mut tx = transfer_of(&alice, 0, 1);
    tx.fee_intrinsic_gas = 0;
    tx.gas_limit = gas_required(&tx).unwrap();
    let tx = resign(&alice, tx);
    assert!(matches!(
        execute_batch(&mut trie, &CTX, &[tx]).unwrap_err(),
        BatchError::Step {
            source: StepError::IntrinsicGasMismatch { .. },
            ..
        }
    ));
}

#[test]
fn collected_fees_are_distributed_by_the_governed_split() {
    let alice = signer(1);
    let treasury = address_of(&signer(60));
    let ops = address_of(&signer(61));
    let mut trie = funded_trie(&[(address_of(&alice), 1_000_000), (FEE_VAULT, 1_000)]);
    let split = sena_stf::FeeSplit {
        beneficiaries: vec![(treasury, 700_000), (ops, 200_000)],
        burn: 100_000,
    };
    let distribute = |nonce, split: &sena_stf::FeeSplit| {
        signed(
            &alice,
            nonce,
            Payload::DistributeFees {
                asset: USDC,
                amount: 999,
                split: split.clone(),
            },
        )
    };
    // No split in force yet: nothing can be distributed.
    let tx = distribute(0, &split);
    assert!(matches!(
        execute_batch(&mut trie.clone(), &CTX, &[tx]).unwrap_err(),
        BatchError::Step {
            source: StepError::FeeSplitMismatch,
            ..
        }
    ));
    apply(
        &mut trie,
        &Instruction::SetFeeSplit {
            split: split.clone(),
        },
    )
    .unwrap();
    let tx = distribute(0, &split);
    let fee = fee_of(&tx);
    execute_batch(&mut trie, &CTX, &[tx]).unwrap();
    assert_eq!(account_in(&trie, &treasury).balance(USDC), 699);
    assert_eq!(account_in(&trie, &ops).balance(USDC), 199);
    // 999 left the vault; 101 of it (the burn and the rounding) went nowhere;
    // the distributor's own fee arrived.
    assert_eq!(
        account_in(&trie, &FEE_VAULT).balance(USDC),
        1_000 - 999 + fee
    );
    // Declaring another split is refused.
    let other = sena_stf::FeeSplit {
        beneficiaries: vec![(address_of(&alice), 1_000_000)],
        burn: 0,
    };
    assert!(execute_batch(&mut trie, &CTX, &[distribute(1, &other)]).is_err());
}

#[test]
fn guardians_can_trip_the_breaker_but_not_reset_it() {
    let alice = signer(1);
    let m: Vec<_> = (10..13).map(signer).collect();
    let mut trie = funded_trie(&[(address_of(&alice), 1_000_000)]);
    let council = Council {
        members: m.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        threshold: 3,
        epoch: 1,
        guardian_threshold: 1,
    };
    trie.insert(keys::council(), council.encode());

    let disable = GovernanceUpdate::DisableGasAsset { asset: USDC };
    let tx = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 1,
            signatures: council_sign(&[(2, &m[2])], &disable, 1),
            update: disable,
        },
    );
    execute_batch(&mut trie, &CTX, &[tx]).expect("one guardian disables");
    // USDC can no longer pay fees.
    assert!(matches!(
        execute_batch(&mut trie.clone(), &CTX, &[transfer_of(&alice, 1, 1)]).unwrap_err(),
        BatchError::Step {
            source: StepError::AssetDisabled,
            ..
        }
    ));
    // Re-enabling with one signature is refused (and could not pay its fee in
    // USDC anyway; a second asset pays it here).
    whitelist(&mut trie, AssetId(2), "EURC", RATE_SCALE, true);
    genesis_credit(&mut trie, address_of(&alice), AssetId(2), 1_000_000);
    let enable = GovernanceUpdate::SetGasAsset {
        record: WhitelistedAsset {
            asset: USDC,
            symbol: "USDC".to_owned(),
            rate: RATE_SCALE,
            intrinsic_gas: DEFAULT_ASSET_INTRINSIC_GAS,
            enabled: true,
        },
    };
    let mut tx = signed(
        &alice,
        1,
        Payload::Governance {
            epoch: 2,
            signatures: council_sign(&[(2, &m[2])], &enable, 2),
            update: enable,
        },
    );
    tx.fee_asset = AssetId(2);
    let tx = resign(&alice, tx);
    assert!(matches!(
        execute_batch(&mut trie, &CTX, &[tx]).unwrap_err(),
        BatchError::Step {
            source: StepError::Governance(sena_stf::GovernanceError::ThresholdNotMet {
                required: 3,
                ..
            }),
            ..
        }
    ));
}

#[test]
fn the_council_sets_the_base_fee_floor() {
    let mut trie = funded_trie(&[]);
    let floor = 2 * DEFAULT_BASE_FEE_FLOOR;
    apply(&mut trie, &Instruction::SetFeeMarket { floor, target: 7 }).unwrap();
    let m = market_in(&trie);
    assert_eq!(
        (m.floor, m.target, m.base_fee),
        (floor, 7, floor),
        "raised to the new floor"
    );
    assert!(apply(
        &mut trie,
        &Instruction::SetFeeMarket {
            floor: 0,
            target: 7
        }
    )
    .is_err());
}
