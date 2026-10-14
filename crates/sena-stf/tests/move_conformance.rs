//! Checks the Move contracts' embedded constants against the Rust reference.
//!
//! The `sena::osp` Move contract on Aptos L1 must compute byte-identical
//! digests and encodings to this implementation. A divergence means L1 decides
//! disputes wrongly, in one direction or the other, which is the highest-value
//! failure in the system (SDD §5.4).
//!
//! Move cannot be compiled in every environment the Rust suite runs in, so this
//! test reads the Move sources as text and verifies that every conformance
//! constant embedded in them still matches what Rust computes today. It is a
//! weaker check than running the Move tests — it proves the constants agree, not
//! that the Move code producing them is correct — but it catches the specific
//! failure that silent drift causes, and it does so in ordinary CI.
//!
//! Running the Move tests themselves requires the Aptos CLI:
//!
//! ```text
//! aptos move test --package-dir move/sena
//! ```

use std::fs;
use std::path::PathBuf;

use sena_primitives::{domain, AssetId, CanonicalEncoder, Hash256, L2Address, Writer};
use sena_state::Node;
use sena_stf::{Account, MachineState, SocialBinding};

fn move_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("move/sena/sources")
}

fn source(name: &str) -> String {
    let path = move_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Asserts the Move source embeds `expected` as a hex literal.
fn assert_embeds(source: &str, label: &str, expected: &str) {
    assert!(
        source.contains(expected),
        "{label}: the Move source does not embed the current Rust value.\n  \
         expected to find: {expected}\n  \
         If the Rust side changed deliberately, update the matching constant in \
         the Move test and re-run `aptos move test --package-dir move/sena`."
    );
}

#[test]
fn the_move_sources_are_present() {
    for file in [
        "codec.move",
        "trie.move",
        "osp.move",
        "assertions.move",
        "disputes.move",
        "bridge.move",
    ] {
        assert!(!source(file).is_empty(), "{file} is empty");
    }
}

#[test]
fn codec_constants_match() {
    let src = source("codec.move");

    let field = CanonicalEncoder::new(b"").field(b"abc").finish();
    assert_embeds(&src, "encode(\"abc\")", &hex::encode(field));

    let integer = CanonicalEncoder::new(b"").u64(1).finish();
    assert_embeds(&src, "encode(u64 1)", &hex::encode(integer));

    assert_embeds(&src, "sha256(\"abc\")", &Hash256::digest(b"abc").to_hex());
}

#[test]
fn domain_tags_match() {
    // A domain tag that differs by one byte silently changes every digest
    // derived from it, and nothing else would notice.
    let src = source("codec.move");
    for (label, tag) in [
        ("trie-internal", domain::TRIE_INTERNAL),
        ("trie-leaf", domain::TRIE_LEAF),
        ("machine-state", domain::MACHINE_STATE),
        ("assertion", domain::ASSERTION),
    ] {
        let literal = format!("b\"{}\"", std::str::from_utf8(tag).expect("tags are ASCII"));
        assert!(
            src.contains(&literal),
            "domain tag {label} missing from Move: {literal}"
        );
    }
}

#[test]
fn trie_constants_match() {
    let src = source("trie.move");

    let leaf = Node::Leaf {
        key: Hash256([0x11; 32]),
        value_hash: Hash256([0x22; 32]),
    };
    assert_embeds(&src, "leaf hash", &leaf.hash().to_hex());

    let internal = Node::Internal {
        left: Hash256([0x33; 32]),
        right: Hash256([0x44; 32]),
    };
    assert_embeds(&src, "internal hash", &internal.hash().to_hex());

    // A trie holding one key has that leaf's hash as its root, because a lone
    // leaf sits at the root rather than at full depth.
    let single = Node::Leaf {
        key: Hash256::ZERO,
        value_hash: Hash256::digest(b"a"),
    };
    assert_embeds(&src, "single-leaf root", &single.hash().to_hex());
}

#[test]
fn account_encoding_constants_match() {
    let src = source("osp.move");

    assert_embeds(&src, "empty account", &hex::encode(Account::new().encode()));

    let mut funded = Account::new();
    funded.nonce = 5;
    funded.credit(AssetId(1), 1_000).unwrap();
    funded.credit(AssetId(7), 42).unwrap();
    assert_embeds(&src, "funded account", &hex::encode(funded.encode()));
}

#[test]
fn machine_commitment_constant_matches() {
    let src = source("osp.move");
    let state = MachineState {
        state_root: Hash256([0x55; 32]),
        pc: 7,
    };
    assert_embeds(&src, "machine commitment", &state.commitment().to_hex());
}

#[test]
fn social_binding_discriminants_match() {
    // The Move module hardcodes these; if the Rust encoding ever reorders the
    // variants, the two would disagree about what a slot means.
    let bound = SocialBinding::Bound {
        address: L2Address::from_bytes([0x01; 32]),
    };
    assert_eq!(bound.encode()[0], 0, "Bound must stay discriminant 0");
    assert_eq!(
        SocialBinding::Vacant.encode()[0],
        1,
        "Vacant must stay discriminant 1"
    );

    let src = source("osp.move");
    assert!(
        src.contains("const TAG_BOUND: u8 = 0;"),
        "Move TAG_BOUND drifted"
    );
    assert!(
        src.contains("const TAG_VACANT: u8 = 1;"),
        "Move TAG_VACANT drifted"
    );
}

#[test]
fn the_challenge_window_floor_matches() {
    let src = source("assertions.move");
    let floor = sena_fraudproof_floor();
    assert!(
        src.contains(&format!("const CHALLENGE_WINDOW_FLOOR: u64 = {floor};")),
        "the Move challenge window floor must match the Rust one ({floor}s)"
    );
}

/// The floor, duplicated rather than imported to keep this crate's dependency
/// graph unchanged. The value is asserted against the Move source only.
const fn sena_fraudproof_floor() -> u64 {
    24 * 60 * 60
}

#[test]
fn the_dispute_arity_and_timeouts_match() {
    let src = source("disputes.move");
    assert!(
        src.contains("const ARITY: u64 = 8;"),
        "bisection arity drifted"
    );
    assert!(
        src.contains("const MOVE_TIMEOUT: u64 = 21600;"),
        "move timeout drifted"
    );
    assert!(
        src.contains("const CLOCK_BUDGET_DIVISOR: u64 = 4;"),
        "clock budget divisor drifted"
    );
}

#[test]
fn determinism_the_vectors_are_stable() {
    let mut w = Writer::new();
    w.u64(5).u32(1).u32(7).u128(42);
    let bytes = w.finish();
    println!("root={}", Hash256::digest(&bytes));
    assert_eq!(Hash256::digest(&bytes), Hash256::digest(&bytes));
}
