//! Behavioural and property tests for the state trie.
//!
//! The trie is the foundation of every security claim SENA makes: a withdrawal
//! is an inclusion proof against a committed root, and a fraud proof is an
//! argument about how a root was computed. These tests therefore target the
//! properties those uses rely on, not merely that reads return what was written.

use proptest::prelude::*;
use sena_primitives::Hash256;
use sena_state::{MerkleTrie, ProofError};

fn key(n: u64) -> Hash256 {
    Hash256::digest(&n.to_be_bytes())
}

#[test]
fn empty_trie_has_the_zero_root() {
    assert_eq!(MerkleTrie::new().root(), Hash256::ZERO);
}

#[test]
fn reads_return_writes() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"one");
    trie.insert(key(2), b"two");
    assert_eq!(trie.get(&key(1)), Some(b"one".as_slice()));
    assert_eq!(trie.get(&key(2)), Some(b"two".as_slice()));
    assert_eq!(trie.get(&key(3)), None);
}

#[test]
fn overwriting_changes_the_root() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"before");
    let before = trie.root();
    trie.insert(key(1), b"after");
    assert_ne!(before, trie.root());
}

#[test]
fn rewriting_the_same_value_restores_the_root() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"v");
    let root = trie.root();
    trie.insert(key(1), b"other");
    trie.insert(key(1), b"v");
    assert_eq!(trie.root(), root);
}

#[test]
fn removal_restores_the_prior_root() {
    // The root must be a function of the current key set alone, not of the
    // history that produced it: two honest nodes reaching the same state by
    // different routes have to agree, or they would dispute each other.
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"one");
    let after_one = trie.root();

    trie.insert(key(2), b"two");
    trie.remove(&key(2));

    assert_eq!(trie.root(), after_one);
}

#[test]
fn removing_everything_returns_to_the_empty_root() {
    let mut trie = MerkleTrie::new();
    for i in 0..32 {
        trie.insert(key(i), format!("v{i}").into_bytes());
    }
    for i in 0..32 {
        trie.remove(&key(i));
    }
    assert_eq!(trie.root(), Hash256::ZERO);
    assert!(trie.is_empty());
}

#[test]
fn removing_an_absent_key_is_a_no_op() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"one");
    let root = trie.root();
    trie.remove(&key(999));
    assert_eq!(trie.root(), root);
}

#[test]
fn inclusion_proofs_verify_for_every_key() {
    let mut trie = MerkleTrie::new();
    for i in 0..64 {
        trie.insert(key(i), format!("value-{i}").into_bytes());
    }
    let root = trie.root();
    for i in 0..64 {
        let k = key(i);
        let proof = trie.prove(&k);
        proof
            .verify_inclusion(&root, &k, format!("value-{i}").as_bytes())
            .unwrap_or_else(|e| panic!("key {i} failed to verify: {e}"));
    }
}

#[test]
fn non_inclusion_proofs_verify_for_absent_keys() {
    let mut trie = MerkleTrie::new();
    for i in 0..64 {
        trie.insert(key(i), b"v");
    }
    let root = trie.root();
    for i in 1000..1064 {
        let k = key(i);
        trie.prove(&k)
            .verify_non_inclusion(&root, &k)
            .unwrap_or_else(|e| panic!("absent key {i} failed: {e}"));
    }
}

#[test]
fn a_proof_cannot_claim_the_wrong_value() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"1000");
    let root = trie.root();

    // The central attack this must stop: inflating a balance while presenting
    // an otherwise genuine proof.
    let err = trie
        .prove(&key(1))
        .verify_inclusion(&root, &key(1), b"999999")
        .unwrap_err();
    assert!(
        matches!(err, ProofError::ValueMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_proof_for_one_key_does_not_verify_for_another() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"v1");
    trie.insert(key(2), b"v2");
    let root = trie.root();

    let proof = trie.prove(&key(1));
    assert!(proof.verify_inclusion(&root, &key(2), b"v2").is_err());
}

#[test]
fn a_proof_does_not_verify_against_a_different_root() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"v");
    let proof = trie.prove(&key(1));
    let stale_root = trie.root();

    trie.insert(key(2), b"w");
    let err = proof
        .verify_inclusion(&trie.root(), &key(1), b"v")
        .unwrap_err();
    assert!(
        matches!(err, ProofError::RootMismatch { .. }),
        "got {err:?}"
    );
    // The proof is still valid against the root it was made for.
    assert!(proof.verify_inclusion(&stale_root, &key(1), b"v").is_ok());
}

#[test]
fn a_present_key_cannot_be_proved_absent() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"v");
    let root = trie.root();
    let err = trie
        .prove(&key(1))
        .verify_non_inclusion(&root, &key(1))
        .unwrap_err();
    assert!(matches!(err, ProofError::KeyPresent), "got {err:?}");
}

#[test]
fn tampering_with_a_sibling_invalidates_the_proof() {
    let mut trie = MerkleTrie::new();
    for i in 0..16 {
        trie.insert(key(i), b"v");
    }
    let root = trie.root();
    let mut proof = trie.prove(&key(3));
    assert!(!proof.siblings.is_empty());
    proof.siblings[0] = Hash256::digest(b"forged");
    assert!(proof.verify_inclusion(&root, &key(3), b"v").is_err());
}

#[test]
fn proof_depth_stays_logarithmic() {
    // Proofs are verified inside Aptos L1 transactions, so depth is a cost
    // constraint, not just an efficiency nicety. A naive 256-level sparse tree
    // would make every withdrawal carry 256 siblings.
    let mut trie = MerkleTrie::new();
    for i in 0..1024 {
        trie.insert(key(i), b"v");
    }
    let deepest = (0..1024)
        .map(|i| trie.prove(&key(i)).siblings.len())
        .max()
        .unwrap();
    assert!(
        deepest < 40,
        "deepest proof was {deepest} siblings, expected well under 40"
    );
}

#[test]
fn determinism_root_is_independent_of_insertion_order() {
    let mut forward = MerkleTrie::new();
    for i in 0..128 {
        forward.insert(key(i), format!("v{i}").into_bytes());
    }

    let mut backward = MerkleTrie::new();
    for i in (0..128).rev() {
        backward.insert(key(i), format!("v{i}").into_bytes());
    }

    println!("root={}", forward.root());
    assert_eq!(forward.root(), backward.root());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever the key set, every present key proves and every absent key
    /// proves absent, against the same root.
    #[test]
    fn proofs_are_sound_for_arbitrary_key_sets(
        present in prop::collection::btree_set(0u64..500, 1..60),
        probes in prop::collection::vec(0u64..1000, 1..40),
    ) {
        let mut trie = MerkleTrie::new();
        for k in &present {
            trie.insert(key(*k), k.to_be_bytes().to_vec());
        }
        let root = trie.root();

        for p in probes {
            let k = key(p);
            let proof = trie.prove(&k);
            if present.contains(&p) {
                prop_assert!(proof.verify_inclusion(&root, &k, &p.to_be_bytes()).is_ok());
            } else {
                prop_assert!(proof.verify_non_inclusion(&root, &k).is_ok());
            }
        }
    }

    /// The root depends only on the final key/value set, never on the sequence
    /// of writes and deletions that produced it.
    #[test]
    fn root_is_history_independent(
        ops in prop::collection::vec((0u64..40, prop::option::of(0u64..5)), 1..80),
    ) {
        use std::collections::BTreeMap;

        let mut trie = MerkleTrie::new();
        let mut model: BTreeMap<u64, u64> = BTreeMap::new();

        for (k, v) in ops {
            match v {
                Some(v) => {
                    trie.insert(key(k), v.to_be_bytes().to_vec());
                    model.insert(k, v);
                }
                None => {
                    trie.remove(&key(k));
                    model.remove(&k);
                }
            }
        }

        // Rebuild from the final set alone and compare.
        let mut rebuilt = MerkleTrie::new();
        for (k, v) in &model {
            rebuilt.insert(key(*k), v.to_be_bytes().to_vec());
        }

        prop_assert_eq!(trie.root(), rebuilt.root());
        prop_assert_eq!(trie.len(), model.len());
    }
}

// --- Proof-based root update -------------------------------------------------
//
// These cover the operation Aptos L1 performs during dispute resolution: derive
// the post-state root of a single write from the pre-state root and a proof,
// holding no state of its own.

#[test]
fn updating_through_a_proof_matches_updating_the_trie() {
    let mut trie = MerkleTrie::new();
    for i in 0..32 {
        trie.insert(key(i), b"old");
    }
    let target = key(7);
    let proof = trie.prove(&target);
    let derived = proof
        .compute_updated_root(&target, &sena_state::hash_value(b"new"))
        .expect("update should derive");

    trie.insert(target, b"new");
    assert_eq!(
        derived,
        trie.root(),
        "L1 must derive the same root the node computes"
    );
}

#[test]
fn inserting_a_new_key_through_a_proof_matches_the_trie() {
    let mut trie = MerkleTrie::new();
    for i in 0..32 {
        trie.insert(key(i), b"v");
    }
    let fresh = key(9_999);
    let proof = trie.prove(&fresh);
    let derived = proof
        .compute_updated_root(&fresh, &sena_state::hash_value(b"new"))
        .expect("insert should derive");

    trie.insert(fresh, b"new");
    assert_eq!(
        derived,
        trie.root(),
        "insertion must handle growing the tree"
    );
}

#[test]
fn inserting_into_an_empty_trie_through_a_proof() {
    let trie = MerkleTrie::new();
    let k = key(1);
    let derived = trie
        .prove(&k)
        .compute_updated_root(&k, &sena_state::hash_value(b"v"))
        .unwrap();

    let mut applied = MerkleTrie::new();
    applied.insert(k, b"v");
    assert_eq!(derived, applied.root());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// For any populated trie and any key, present or absent, deriving the
    /// post-state root from a proof agrees with applying the write directly.
    /// This equivalence is what makes the one-step verifier sound.
    #[test]
    fn proof_update_agrees_with_direct_update(
        populate in prop::collection::btree_set(0u64..300, 1..50),
        target in 0u64..400,
        value in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let mut trie = MerkleTrie::new();
        for k in &populate {
            trie.insert(key(*k), k.to_be_bytes().to_vec());
        }

        let k = key(target);
        let derived = trie
            .prove(&k)
            .compute_updated_root(&k, &sena_state::hash_value(&value))?;

        trie.insert(k, value);
        prop_assert_eq!(derived, trie.root());
    }
}

// --- Persistence -------------------------------------------------------------

#[test]
fn a_snapshot_round_trips() {
    let mut trie = MerkleTrie::new();
    for i in 0..128 {
        trie.insert(key(i), format!("value-{i}").into_bytes());
    }

    let restored = MerkleTrie::from_bytes(&trie.to_bytes()).expect("snapshot should load");
    assert_eq!(restored.root(), trie.root());
    assert_eq!(restored.len(), trie.len());
    for i in 0..128 {
        assert_eq!(restored.get(&key(i)), Some(format!("value-{i}").as_bytes()));
    }
}

#[test]
fn an_empty_trie_round_trips() {
    let restored = MerkleTrie::from_bytes(&MerkleTrie::new().to_bytes()).unwrap();
    assert_eq!(restored.root(), Hash256::ZERO);
    assert!(restored.is_empty());
}

#[test]
fn a_corrupted_snapshot_is_rejected_rather_than_served() {
    // The point of recording the root is that a node which cannot reproduce it
    // must refuse to start, rather than quietly serving state nobody else
    // agrees with.
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"original");
    let mut bytes = trie.to_bytes();

    // Corrupt a value byte, leaving the recorded root untouched.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    assert!(matches!(
        MerkleTrie::from_bytes(&bytes),
        Err(sena_state::LoadError::RootMismatch { .. })
    ));
}

#[test]
fn a_truncated_snapshot_is_rejected() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"v");
    let bytes = trie.to_bytes();
    for cut in 0..bytes.len() {
        assert!(
            MerkleTrie::from_bytes(&bytes[..cut]).is_err(),
            "prefix of {cut} must not load"
        );
    }
}

// --- Historical proofs -------------------------------------------------------

#[test]
fn a_proof_can_be_made_against_an_earlier_root() {
    // Withdrawals are checked against a finalized assertion, whose root is at
    // least a challenge window old. Proving only against the current root would
    // produce proofs the bridge rejects.
    let mut trie = MerkleTrie::new();
    for i in 0..32 {
        trie.insert(key(i), format!("v{i}").into_bytes());
    }
    let historical_root = trie.root();

    // The chain moves on.
    for i in 32..64 {
        trie.insert(key(i), format!("v{i}").into_bytes());
    }
    assert_ne!(trie.root(), historical_root);

    // A proof against the old root still verifies against it.
    let proof = trie.prove_at(historical_root, &key(7));
    proof
        .verify_inclusion(&historical_root, &key(7), b"v7")
        .expect("historical proof must verify against its own root");

    // And does not verify against the current one.
    assert!(proof
        .verify_inclusion(&trie.root(), &key(7), b"v7")
        .is_err());
}

#[test]
fn a_historical_proof_reflects_the_value_at_that_root() {
    let mut trie = MerkleTrie::new();
    trie.insert(key(1), b"before");
    let old_root = trie.root();
    trie.insert(key(1), b"after");

    trie.prove_at(old_root, &key(1))
        .verify_inclusion(&old_root, &key(1), b"before")
        .expect("the old root must still prove the old value");

    trie.prove(&key(1))
        .verify_inclusion(&trie.root(), &key(1), b"after")
        .expect("the current root proves the current value");
}
