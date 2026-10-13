use std::time::Instant;

use sena_light_client::{
    verify_account_standalone, AccountProofPayload, LightClient, LightClientError, TrustLevel,
};
use sena_primitives::{AssetId, Channel, Hash256, HashedIdentifier, L2Address, NetworkSalt};
use sena_state::MerkleTrie;
use sena_stf::{keys, Account, SocialBinding};

const USDC: AssetId = AssetId(1);
const USDT: AssetId = AssetId(2);

fn test_address(seed: u8) -> L2Address {
    L2Address([seed; 32])
}

#[test]
fn verifies_authentic_account_balance() {
    let mut trie = MerkleTrie::new();
    let alice = test_address(0x11);

    let mut account = Account::new();
    account.nonce = 7;
    account.credit(USDC, 50_000).unwrap();
    account.credit(USDT, 25_000).unwrap();

    let slot = keys::account(&alice);
    trie.insert(slot, account.encode());

    let state_root = trie.root();
    let proof = trie.prove(&slot);

    let client = LightClient::new("sena-testnet", state_root);

    let payload = AccountProofPayload {
        address: alice,
        height: 1,
        state_root,
        nonce: 7,
        balances: vec![(USDC.get(), 50_000), (USDT.get(), 25_000)],
        siblings: proof.siblings,
        terminal: proof.terminal,
        finalized: true,
    };

    let verified = client
        .verify_account_proof(&payload)
        .expect("proof must be valid");
    assert_eq!(verified.address, alice);
    assert_eq!(verified.nonce, 7);
    assert_eq!(verified.balance(USDC), 50_000);
    assert_eq!(verified.balance(USDT), 25_000);
    assert_eq!(verified.balance(AssetId(99)), 0);
    assert_eq!(verified.trust_level, TrustLevel::Finalized);
    assert!(verified.is_finalized());
}

#[test]
fn rejects_tampered_balance_or_nonce() {
    let mut trie = MerkleTrie::new();
    let alice = test_address(0x11);

    let mut account = Account::new();
    account.nonce = 1;
    account.credit(USDC, 1_000).unwrap();

    let slot = keys::account(&alice);
    trie.insert(slot, account.encode());

    let state_root = trie.root();
    let proof = trie.prove(&slot);
    let client = LightClient::new("sena-testnet", state_root);

    // 1. Adversary inflates balance to 1,000,000
    let fake_balance_payload = AccountProofPayload {
        address: alice,
        height: 1,
        state_root,
        nonce: 1,
        balances: vec![(USDC.get(), 1_000_000)],
        siblings: proof.siblings.clone(),
        terminal: proof.terminal.clone(),
        finalized: true,
    };
    assert!(matches!(
        client.verify_account_proof(&fake_balance_payload),
        Err(LightClientError::Proof(_))
    ));

    // 2. Adversary alters nonce
    let fake_nonce_payload = AccountProofPayload {
        address: alice,
        height: 1,
        state_root,
        nonce: 2,
        balances: vec![(USDC.get(), 1_000)],
        siblings: proof.siblings.clone(),
        terminal: proof.terminal.clone(),
        finalized: true,
    };
    assert!(matches!(
        client.verify_account_proof(&fake_nonce_payload),
        Err(LightClientError::Proof(_))
    ));

    // 3. Adversary tampers with state root
    let fake_root_payload = AccountProofPayload {
        address: alice,
        height: 1,
        state_root: Hash256::digest(b"untrusted_attacker_root"),
        nonce: 1,
        balances: vec![(USDC.get(), 1_000)],
        siblings: proof.siblings,
        terminal: proof.terminal,
        finalized: true,
    };
    assert!(matches!(
        client.verify_account_proof(&fake_root_payload),
        Err(LightClientError::UntrustedRoot(_))
    ));
}

#[test]
fn verifies_unfunded_account_non_inclusion() {
    let trie = MerkleTrie::new();
    let bob = test_address(0x22);

    let slot = keys::account(&bob);
    let proof = trie.prove(&slot);
    let state_root = trie.root();

    let client = LightClient::new("sena-testnet", state_root);

    let payload = AccountProofPayload {
        address: bob,
        height: 0,
        state_root,
        nonce: 0,
        balances: vec![],
        siblings: proof.siblings.clone(),
        terminal: proof.terminal.clone(),
        finalized: true,
    };

    let verified = client
        .verify_account_proof(&payload)
        .expect("empty account must verify");
    assert_eq!(verified.nonce, 0);
    assert_eq!(verified.balance(USDC), 0);

    // If an attacker claims Bob has 100 USDC under this empty root, it fails
    let fake_payload = AccountProofPayload {
        address: bob,
        height: 0,
        state_root,
        nonce: 0,
        balances: vec![(USDC.get(), 100)],
        siblings: proof.siblings,
        terminal: proof.terminal,
        finalized: true,
    };
    assert!(client.verify_account_proof(&fake_payload).is_err());
}

#[test]
fn verifies_social_identifier_resolution() {
    let mut trie = MerkleTrie::new();
    let alice = test_address(0x11);
    let salt = NetworkSalt::new(b"test_salt".to_vec());
    let handle = HashedIdentifier::new(Channel::Handle, "alice_web3", &salt);

    let slot = keys::social_by_identifier(&handle);
    let binding = SocialBinding::Bound { address: alice };
    trie.insert(slot, binding.encode());

    let state_root = trie.root();
    let proof = trie.prove(&slot);

    let client = LightClient::new("sena-testnet", state_root);

    // Legitimate resolution verifies
    assert_eq!(
        client
            .verify_social_binding(&handle, Some(&alice), &proof, &state_root)
            .unwrap(),
        TrustLevel::Finalized
    );

    // Tampered address fails
    let eve = test_address(0xee);
    assert!(client
        .verify_social_binding(&handle, Some(&eve), &proof, &state_root)
        .is_err());
}

#[test]
fn mobile_verification_performance_is_sub_millisecond() {
    let mut trie = MerkleTrie::new();
    let user = test_address(0x42);

    let mut account = Account::new();
    account.nonce = 15;
    account.credit(USDC, 100_000).unwrap();
    account.credit(USDT, 50_000).unwrap();

    let slot = keys::account(&user);
    trie.insert(slot, account.encode());

    // Insert 50 other random accounts to ensure a realistic trie depth
    for i in 0..50u8 {
        let dummy = test_address(i + 100);
        let mut d_acc = Account::new();
        d_acc.credit(USDC, 1_000).unwrap();
        trie.insert(keys::account(&dummy), d_acc.encode());
    }

    let state_root = trie.root();
    let proof = trie.prove(&slot);
    let balances = vec![(USDC.get(), 100_000), (USDT.get(), 50_000)];

    let start = Instant::now();
    let iterations = 1_000;
    for _ in 0..iterations {
        let res = verify_account_standalone(
            &state_root,
            &user,
            15,
            &balances,
            &proof.siblings,
            &proof.terminal,
        );
        assert!(res.is_ok());
    }
    let elapsed = start.elapsed();
    let avg_per_verification = elapsed / iterations;

    println!(
        "Verified {iterations} account proofs in {:?}, avg per verification: {:?}",
        elapsed, avg_per_verification
    );
    // Must be well under 1 millisecond per verification (typically < 0.05ms)
    assert!(avg_per_verification.as_micros() < 500);
}
