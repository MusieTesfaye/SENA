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
use sena_stf::gas::fee_for;
use sena_stf::{
    apply, compile, execute_batch, keys, verify_step, Account, Authenticator, BatchError,
    CompileError, Council, CouncilSignature, GovernanceUpdate, Instruction, MachineState, Payload,
    SocialBinding, StepError, Transaction, WhitelistedAsset, FEE_VAULT, RATE_SCALE,
};

const USDC: AssetId = AssetId(1);

/// The rate USDC is whitelisted at in these tests: one-to-one with native units.
const USDC_RATE: u128 = RATE_SCALE;

/// The fee a transaction costs at [`USDC_RATE`].
fn fee() -> u128 {
    fee_for(USDC_RATE).unwrap()
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
    let mut tx = Transaction {
        sender: address_of(key),
        nonce,
        fee_asset: USDC,
        max_fee: fee(),
        fee_rate: USDC_RATE,
        payload,
        authenticator: Authenticator::Ed25519 {
            public_key: key.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
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
        enabled,
    };
    apply(trie, &Instruction::SetGasAsset { record }).unwrap();
}

/// Installs a council with the given members and threshold.
fn install_council(trie: &mut MerkleTrie, keys: &[SigningKey], threshold: u32) {
    let council = Council {
        members: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        threshold,
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
    execute_batch(&mut trie, &[tx]).expect("transfer should execute");

    assert_eq!(account_in(&trie, &bob).balance(USDC), 2_500);
    assert_eq!(
        account_in(&trie, &address_of(&alice)).balance(USDC),
        10_000 - 2_500 - fee()
    );
    assert_eq!(account_in(&trie, &FEE_VAULT).balance(USDC), fee());
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
    execute_batch(&mut trie, &batch).unwrap();

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
    let err = execute_batch(&mut trie, &[tx]).unwrap_err();
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
    assert_eq!(compile(&tx).unwrap_err(), CompileError::SelfTransfer);
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
    assert!(compile(&tx).is_err());
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
    tx.max_fee = u128::MAX;
    assert!(
        compile(&tx).is_err(),
        "max_fee must be covered by the signature"
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

    execute_batch(&mut trie, std::slice::from_ref(&tx)).expect("first execution succeeds");
    let err = execute_batch(&mut trie, &[tx]).unwrap_err();
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
fn keyless_authentication_is_refused_rather_than_partially_checked() {
    // Accepting a keyless transaction on the strength of its ephemeral signature
    // alone would let anyone spend from any keyless account.
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
    tx.authenticator = Authenticator::Keyless {
        ephemeral_public_key: alice.verifying_key().to_bytes(),
        signature: alice.sign(tx.signing_digest().as_bytes()).to_bytes(),
        zk_proof: vec![0xAA; 32],
    };
    assert_eq!(
        compile(&tx).unwrap_err(),
        CompileError::Auth(sena_stf::AuthError::KeylessNotImplemented)
    );
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
    execute_batch(&mut trie, &[tx]).unwrap();

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
    let err = execute_batch(&mut trie, &[theft]).unwrap_err();
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
    let trace = execute_batch(&mut trie, &[tx]).unwrap();

    assert_eq!(trace.states.len(), trace.instructions.len() + 1);
    assert_eq!(trace.initial().state_root, pre_root);
    assert_eq!(trace.final_state().state_root, trie.root());
    // nonce, gas-asset check, fee debit, fee credit, transfer debit, transfer credit
    assert_eq!(trace.len(), 6);
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
    let a = execute_batch(&mut first, &batch).unwrap();
    let b = execute_batch(&mut second, &batch).unwrap();

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
    let trace = execute_batch(&mut trie, &batch).unwrap();

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
        let trace = execute_batch(&mut trie, &batch).unwrap();

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
    execute_batch(&mut trie, &[tx]).unwrap();

    // No native token was needed at any point (REQ-GAS-002).
    assert_eq!(
        account_in(&trie, &address_of(&alice)).balance(AssetId::NATIVE),
        0
    );
    assert_eq!(account_in(&trie, &FEE_VAULT).balance(USDC), fee());
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

    let err = execute_batch(&mut trie, &[tx]).unwrap_err();
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
    let err = execute_batch(&mut trie, &[tx]).unwrap_err();
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
    tx.fee_rate = 1;
    tx.max_fee = 1;
    let tx = resign(&alice, tx);

    let err = execute_batch(&mut trie, &[tx]).unwrap_err();
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
fn a_max_fee_below_the_real_cost_is_refused_at_compile_time() {
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
    tx.max_fee = fee() - 1;
    let tx = resign(&alice, tx);
    assert!(matches!(
        compile(&tx).unwrap_err(),
        CompileError::FeeTooLow { .. }
    ));
}

#[test]
fn a_cheaper_asset_costs_proportionally_more_units() {
    // An asset worth half a native unit should cost twice as many units.
    let half_value = RATE_SCALE * 2;
    assert_eq!(
        fee_for(half_value).unwrap(),
        2 * fee_for(RATE_SCALE).unwrap()
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
    execute_batch(&mut trie, &[tx]).expect("a quorum-signed update should apply");

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
        name: "gas.base_native".to_owned(),
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
    let err = execute_batch(&mut trie, &[tx]).unwrap_err();
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
        name: "gas.base_native".to_owned(),
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
    assert!(execute_batch(&mut trie, &[tx]).is_err());
}

#[test]
fn a_governance_payload_cannot_be_replayed_in_a_later_epoch() {
    let alice = signer(1);
    let m1 = signer(10);
    let mut trie = funded_trie(&[(address_of(&alice), 100_000)]);
    install_council(&mut trie, std::slice::from_ref(&m1), 1);

    let update = GovernanceUpdate::SetParameter {
        name: "gas.base_native".to_owned(),
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
    assert!(execute_batch(&mut trie, &[replayed]).is_err());
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
            execute_batch(&mut trie.clone(), &[tx]).is_err(),
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
    let signatures = council_sign(&[(0, &m1)], &update, 7);
    let tx = signed(
        &alice,
        0,
        Payload::Governance {
            epoch: 7,
            update,
            signatures,
        },
    );

    let trace = execute_batch(&mut trie, &[tx]).unwrap();
    for (index, instruction) in trace.instructions.iter().enumerate() {
        let witness = witness_for(&replay, instruction);
        let derived = verify_step(&trace.states[index], instruction, &witness)
            .unwrap_or_else(|e| panic!("governance step {index} failed on L1: {e}"));
        assert_eq!(derived, trace.states[index + 1]);
        apply(&mut replay, instruction).unwrap();
    }
}
