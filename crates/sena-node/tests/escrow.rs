//! Escrow: paying an identifier before its owner has linked it (Celo's
//! `Escrow`), claimed once linked, or taken back after the deadline.

use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sena_fraudproof::{AssertionChain, PartyId, DEFAULT_CHALLENGE_WINDOW};
use sena_node::{Request, Response, Sequencer};
use sena_primitives::{AssetId, HashedIdentifier, L2Address, NetworkSalt};
use sena_state::MerkleTrie;
use sena_stf::{
    apply, Authenticator, Escrow, Instruction, Payload, Transaction, WhitelistedAsset, RATE_SCALE,
};

const USDC: AssetId = AssetId(1);
const BOND: u128 = 1_000_000;
const CHAIN: u64 = sena_stf::TEST_CHAIN_ID;

/// The sequencer's clock, which the test moves.
static NOW: AtomicU64 = AtomicU64::new(1_000_000);
/// Held by each test: they share the clock.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

fn key(seed: u64) -> SigningKey {
    SigningKey::generate(&mut StdRng::seed_from_u64(seed))
}
fn addr(k: &SigningKey) -> L2Address {
    L2Address::from_bytes(k.verifying_key().to_bytes())
}

fn signed(k: &SigningKey, nonce: u64, payload: Payload) -> Transaction {
    let mut tx = Transaction {
        chain_id: CHAIN,
        sender: addr(k),
        nonce,
        fee_asset: USDC,
        fee_rate: 0,
        fee_intrinsic_gas: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        payload,
        authenticator: Authenticator::Ed25519 {
            public_key: k.verifying_key().to_bytes(),
            signature: [0; 64],
        },
    };
    sena_stf::gas::fill_default_fees(&mut tx);
    tx.authenticator = Authenticator::Ed25519 {
        public_key: k.verifying_key().to_bytes(),
        signature: k.sign(tx.signing_digest().as_bytes()).to_bytes(),
    };
    tx
}

fn node(funded: &[L2Address]) -> Sequencer {
    let mut trie = MerkleTrie::new();
    apply(
        &mut trie,
        &Instruction::SetGasAsset {
            record: WhitelistedAsset {
                asset: USDC,
                symbol: "USDC".to_owned(),
                rate: RATE_SCALE,
                intrinsic_gas: sena_stf::gas::DEFAULT_ASSET_INTRINSIC_GAS,
                enabled: true,
            },
        },
    )
    .unwrap();
    for a in funded {
        apply(
            &mut trie,
            &Instruction::Credit {
                account: *a,
                asset: USDC,
                amount: 10_000_000,
            },
        )
        .unwrap();
    }
    let chain = AssertionChain::new(trie.root(), DEFAULT_CHALLENGE_WINDOW, BOND);
    Sequencer::new(trie, chain, PartyId(1), BOND).with_clock(clock)
}

fn balance(seq: &Sequencer, who: &L2Address) -> u128 {
    seq.state
        .get(&sena_stf::keys::account(who))
        .map_or(0, |b| sena_stf::Account::decode(b).unwrap().balance(USDC))
}

/// Submits and seals one transaction; whether it made it into a block.
fn run(seq: &mut Sequencer, tx: Transaction) -> bool {
    if seq.submit(tx).is_err() {
        return false;
    }
    seq.produce(10).unwrap().is_some()
}

fn email() -> HashedIdentifier {
    HashedIdentifier::new(
        sena_primitives::prefix::EMAIL,
        "carol@example.com",
        &NetworkSalt::new(*b"escrow"),
    )
}

fn attest(issuer: &SigningKey, account: L2Address, issued_on: u64) -> Payload {
    let digest = sena_stf::attestation_digest(CHAIN, &email(), &addr(issuer), &account, issued_on);
    Payload::RegisterAttestation {
        identifier: email(),
        issuer: addr(issuer),
        account,
        issued_on,
        signature: issuer.sign(digest.as_bytes()).to_bytes(),
    }
}

fn escrows(seq: &mut Sequencer) -> Vec<sena_node::rpc::EscrowEntry> {
    match sena_node::handle(
        seq,
        "t",
        Request::GetEscrows {
            identifiers: vec![email()],
            sender: None,
        },
    ) {
        Response::Escrows { escrows } => escrows,
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_escrow_is_claimed_once_by_whoever_the_issuer_attests() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    NOW.store(1_000_000, Ordering::SeqCst);
    let (alice, carol, mallory, issuer) = (key(1), key(2), key(3), key(9));
    let mut seq = node(&[addr(&alice), addr(&carol), addr(&mallory)]);
    let expires_at = clock() + 3_600;

    // Alice pays carol@example.com, whom nobody has linked yet.
    let before = balance(&seq, &addr(&alice));
    assert!(run(
        &mut seq,
        signed(
            &alice,
            0,
            Payload::EscrowSend {
                identifier: email(),
                issuer: addr(&issuer),
                asset: USDC,
                amount: 4_000_000,
                expires_at,
            }
        )
    ));
    assert!(balance(&seq, &addr(&alice)) <= before - 4_000_000);
    let open = escrows(&mut seq);
    assert_eq!(open.len(), 1);
    let record = open[0].record;
    assert!(!record.released && record.amount == 4_000_000);
    let claim = |k: &SigningKey, nonce, record: Escrow| {
        signed(
            k,
            nonce,
            Payload::EscrowClaim {
                sender: addr(&alice),
                nonce: 0,
                record,
            },
        )
    };

    // Before Carol links it, nobody can claim it.
    assert!(
        !run(&mut seq, claim(&carol, 0, record)),
        "claimed without an attestation"
    );

    // The issuer attests the email to Carol, who submits it (her consent).
    assert!(run(
        &mut seq,
        signed(&carol, 0, attest(&issuer, addr(&carol), 100))
    ));
    // Mallory, not attested, cannot claim it; nor can anyone inflate it.
    assert!(!run(&mut seq, claim(&mallory, 0, record)));
    assert!(!run(
        &mut seq,
        claim(
            &carol,
            1,
            Escrow {
                amount: 9_000_000,
                ..record
            }
        )
    ));

    let carol_before = balance(&seq, &addr(&carol));
    assert!(run(&mut seq, claim(&carol, 1, record)));
    assert!(
        balance(&seq, &addr(&carol)) > carol_before + 3_900_000,
        "claimed less the fee"
    );
    assert!(escrows(&mut seq)[0].record.released);

    // Released: neither a second claim nor a refund pays again.
    assert!(!run(&mut seq, claim(&carol, 2, record)));
    NOW.store(expires_at + 1, Ordering::SeqCst);
    assert!(!run(
        &mut seq,
        signed(
            &alice,
            1,
            Payload::EscrowRefund {
                sender: addr(&alice),
                nonce: 0,
                record,
            }
        )
    ));
    NOW.store(1_000_000, Ordering::SeqCst);
}

#[test]
fn an_unclaimed_escrow_goes_back_to_its_sender_only_after_the_deadline() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (alice, bob, issuer) = (key(11), key(12), key(19));
    let mut seq = node(&[addr(&alice), addr(&bob)]);
    let start = 2_000_000;
    NOW.store(start, Ordering::SeqCst);
    assert!(run(
        &mut seq,
        signed(
            &alice,
            0,
            Payload::EscrowSend {
                identifier: email(),
                issuer: addr(&issuer),
                asset: USDC,
                amount: 1_000_000,
                expires_at: start + 600,
            }
        )
    ));
    let record = escrows(&mut seq)[0].record;
    let refund = |k: &SigningKey, nonce| {
        signed(
            k,
            nonce,
            Payload::EscrowRefund {
                sender: addr(&alice),
                nonce: 0,
                record,
            },
        )
    };
    assert!(
        !run(&mut seq, refund(&alice, 1)),
        "refunded before the deadline"
    );
    NOW.store(start + 600, Ordering::SeqCst);
    assert!(!run(&mut seq, refund(&bob, 0)), "someone else took it back");
    let before = balance(&seq, &addr(&alice));
    assert!(run(&mut seq, refund(&alice, 1)));
    assert!(balance(&seq, &addr(&alice)) > before + 900_000);
    // An escrow that has already expired cannot be opened.
    assert!(!run(
        &mut seq,
        signed(
            &alice,
            2,
            Payload::EscrowSend {
                identifier: email(),
                issuer: addr(&issuer),
                asset: USDC,
                amount: 1,
                expires_at: start,
            }
        )
    ));
    NOW.store(1_000_000, Ordering::SeqCst);
}

#[test]
fn a_new_account_claims_its_first_payment_and_pays_the_fee_from_it() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    NOW.store(3_000_000, Ordering::SeqCst);
    let (alice, newcomer, issuer) = (key(21), key(22), key(29));
    // The newcomer holds nothing at all; the issuer pays to submit the link.
    let mut seq = node(&[addr(&alice), addr(&issuer)]);
    assert!(run(
        &mut seq,
        signed(
            &alice,
            0,
            Payload::EscrowSend {
                identifier: email(),
                issuer: addr(&issuer),
                asset: USDC,
                amount: 2_000_000,
                expires_at: clock() + 3_600,
            }
        )
    ));
    let record = escrows(&mut seq)[0].record;
    // The issuer submits the attestation itself, as it may, so the
    // newcomer's first transaction of its own is the claim.
    assert!(run(
        &mut seq,
        signed(&issuer, 0, attest(&issuer, addr(&newcomer), 100))
    ));
    assert_eq!(balance(&seq, &addr(&newcomer)), 0);
    assert!(run(
        &mut seq,
        signed(
            &newcomer,
            0,
            Payload::EscrowClaim {
                sender: addr(&alice),
                nonce: 0,
                record,
            }
        )
    ));
    let got = balance(&seq, &addr(&newcomer));
    assert!(
        got > 1_900_000 && got < 2_000_000,
        "the claim less its own fee: {got}"
    );
}
