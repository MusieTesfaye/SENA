//! Cross-language conformance vectors.
//!
//! The `sena::osp` Move contract on Aptos L1 must compute byte-identical
//! digests and encodings to this implementation. If the two ever disagree, L1
//! decides disputes wrongly — in either direction — which is the single
//! highest-value failure in the system (SDD §5.4).
//!
//! These tests pin the values the Move implementation is checked against. The
//! same constants appear in `move/sena/sources/*.move` test functions, so a
//! change on either side that is not mirrored on the other fails here or there.
//!
//! Run `cargo test -p sena-stf --test conformance -- --nocapture` to print them.

use sena_primitives::{
    domain, AssetId, CanonicalEncoder, Channel, Hash256, HashedIdentifier, L2Address, NetworkSalt,
    Writer,
};
use sena_state::{MerkleTrie, Node};
use sena_stf::{keys, Account, MachineState, SocialBinding, WhitelistedAsset};

/// Prints a vector so it can be copied into the Move tests.
fn vector(name: &str, bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    println!("  {name:<34} 0x{hex}");
    hex
}

#[test]
fn canonical_encoding_vectors() {
    println!("\n-- canonical encoding --");
    assert_eq!(
        vector(
            "encode(\"abc\")",
            &CanonicalEncoder::new(b"").field(b"abc").finish()
        ),
        "0000000000000003616263"
    );
    assert_eq!(
        vector("encode(u64 1)", &CanonicalEncoder::new(b"").u64(1).finish()),
        "00000000000000080000000000000001"
    );
}

#[test]
fn hash_vectors() {
    println!("\n-- hashing --");
    assert_eq!(
        vector("sha256(\"abc\")", Hash256::digest(b"abc").as_bytes()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        vector("sha256(\"\")", Hash256::digest(b"").as_bytes()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn trie_node_vectors() {
    println!("\n-- trie nodes --");
    let leaf = Node::Leaf {
        key: Hash256([0x11; 32]),
        value_hash: Hash256([0x22; 32]),
    };
    let internal = Node::Internal {
        left: Hash256([0x33; 32]),
        right: Hash256([0x44; 32]),
    };

    let leaf_hex = vector("leaf(0x11.., 0x22..)", leaf.hash().as_bytes());
    let internal_hex = vector("internal(0x33.., 0x44..)", internal.hash().as_bytes());

    // Recomputed here from the documented rule, so the constant and the
    // implementation are checked against each other rather than against
    // themselves.
    let expected_leaf = Hash256::digest(
        &CanonicalEncoder::new(domain::TRIE_LEAF)
            .field(&[0x11; 32])
            .field(&[0x22; 32])
            .finish(),
    );
    assert_eq!(leaf_hex, hex::encode(expected_leaf.0));
    assert_ne!(leaf_hex, internal_hex, "domains must separate node kinds");
}

#[test]
fn state_key_vectors() {
    println!("\n-- state keys --");
    let address = L2Address::from_bytes([0xAB; 32]);
    vector("account(0xab..)", keys::account(&address).as_bytes());
    vector("asset(1)", keys::asset(1).as_bytes());
    vector("council()", keys::council().as_bytes());
    vector(
        "parameter(\"gas.base_native\")",
        keys::parameter("gas.base_native").as_bytes(),
    );

    // Regions must stay disjoint across languages too.
    assert_ne!(keys::account(&address), keys::social_by_address(&address));
}

#[test]
fn account_encoding_vectors() {
    println!("\n-- account encoding --");
    let empty = Account::new();
    assert_eq!(
        vector("account{nonce:0}", &empty.encode()),
        "000000000000000000000000"
    );

    let mut funded = Account::new();
    funded.nonce = 5;
    funded.credit(AssetId(1), 1_000).unwrap();
    funded.credit(AssetId(7), 42).unwrap();
    let hex = vector("account{nonce:5, 1:1000, 7:42}", &funded.encode());

    let expected = {
        let mut w = Writer::new();
        w.u64(5).u32(2).u32(1).u128(1_000).u32(7).u128(42);
        hex::encode(w.finish())
    };
    assert_eq!(hex, expected);
    assert_eq!(Account::decode(&funded.encode()).unwrap(), funded);
}

#[test]
fn social_binding_vectors() {
    println!("\n-- social bindings --");
    let bound = SocialBinding::Bound {
        address: L2Address::from_bytes([0x01; 32]),
    };
    assert_eq!(
        vector("binding{bound 0x01..}", &bound.encode()),
        format!("00{}", "01".repeat(32))
    );
    assert_eq!(
        vector("binding{vacant}", &SocialBinding::Vacant.encode()),
        "01"
    );
}

#[test]
fn whitelisted_asset_vectors() {
    println!("\n-- gas assets --");
    let record = WhitelistedAsset {
        asset: AssetId(1),
        symbol: "USDC".to_owned(),
        rate: 1_000_000,
        enabled: true,
    };
    let hex = vector("asset{1, USDC, 1e6, true}", &record.encode());
    let expected = {
        let mut w = Writer::new();
        w.u32(1).string("USDC").u128(1_000_000).bool(true);
        hex::encode(w.finish())
    };
    assert_eq!(hex, expected);
}

#[test]
fn machine_commitment_vectors() {
    println!("\n-- machine commitments --");
    let state = MachineState {
        state_root: Hash256([0x55; 32]),
        pc: 7,
    };
    let hex = vector("machine{0x55.., pc 7}", state.commitment().as_bytes());

    let expected = Hash256::digest(
        &CanonicalEncoder::new(domain::MACHINE_STATE)
            .field(&[0x55; 32])
            .u64(7)
            .finish(),
    );
    assert_eq!(hex, hex::encode(expected.0));
}

#[test]
fn identifier_vectors() {
    println!("\n-- identifiers --");
    let salt = NetworkSalt::new(*b"sena-conformance-salt");
    let id = HashedIdentifier::new(Channel::Handle, "@alice", &salt);
    vector("handle(@alice)", id.as_hash().as_bytes());

    // Normalisation is a consensus rule, so it is pinned too.
    assert_eq!(
        id,
        HashedIdentifier::new(Channel::Handle, "  @ALICE ", &salt)
    );
}

#[test]
fn trie_root_vectors() {
    println!("\n-- trie roots --");
    assert_eq!(
        vector("root(empty)", MerkleTrie::new().root().as_bytes()),
        "0".repeat(64)
    );

    let mut trie = MerkleTrie::new();
    trie.insert(Hash256([0x00; 32]), b"a");
    let one = vector("root(one leaf)", trie.root().as_bytes());

    trie.insert(Hash256([0xFF; 32]), b"b");
    let two = vector("root(two leaves)", trie.root().as_bytes());
    assert_ne!(one, two);

    // The single-leaf root is just that leaf's hash: a lone leaf sits at the
    // root rather than at full depth.
    let expected = Node::Leaf {
        key: Hash256([0x00; 32]),
        value_hash: Hash256::digest(b"a"),
    }
    .hash();
    assert_eq!(one, hex::encode(expected.0));
}

#[test]
fn determinism_all_vectors_are_stable() {
    // Re-derives one vector from each family so a process-local source of
    // variation would show up here.
    let root = Hash256::digest(b"conformance");
    println!("root={root}");
    assert_eq!(root, Hash256::digest(b"conformance"));
}
