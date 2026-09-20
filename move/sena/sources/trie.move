/// Sparse Merkle trie proof verification on Aptos L1.
///
/// This is the module a withdrawal is checked against, and the one a One-Step
/// Proof relies on. It reimplements `sena-state` and must agree with it
/// exactly: a divergence would either let a forged proof through or reject a
/// genuine one.
module sena::trie {
    use std::vector;
    use sena::codec;

    /// The proof path is longer than the key has bits.
    const E_TOO_DEEP: u64 = 10;
    /// The path did not reconstruct to the expected root.
    const E_ROOT_MISMATCH: u64 = 11;
    /// The terminal leaf does not lie on the queried key's path.
    const E_LEAF_OFF_PATH: u64 = 12;
    /// The key is absent where inclusion was required.
    const E_KEY_ABSENT: u64 = 13;
    /// The key is present where absence was required.
    const E_KEY_PRESENT: u64 = 14;
    /// The proven value differs from the expected one.
    const E_VALUE_MISMATCH: u64 = 15;
    /// Two keys claimed to be distinct agree on all 256 bits.
    const E_KEYS_NOT_DISTINCT: u64 = 16;

    const MAX_DEPTH: u64 = 256;

    /// What the proof path ends in.
    ///
    /// `is_leaf == false` means an empty subtree, in which case the key and
    /// value fields are ignored.
    struct Terminal has copy, drop, store {
        is_leaf: bool,
        key: vector<u8>,
        value_hash: vector<u8>,
    }

    /// A proof of what a key holds, or that it holds nothing.
    struct Proof has copy, drop, store {
        /// Sibling hashes, ordered root-first.
        siblings: vector<vector<u8>>,
        terminal: Terminal,
    }

    public fun empty_terminal(): Terminal {
        Terminal { is_leaf: false, key: vector::empty(), value_hash: vector::empty() }
    }

    public fun leaf_terminal(key: vector<u8>, value_hash: vector<u8>): Terminal {
        Terminal { is_leaf: true, key, value_hash }
    }

    public fun new_proof(siblings: vector<vector<u8>>, terminal: Terminal): Proof {
        Proof { siblings, terminal }
    }

    public fun zero(): vector<u8> {
        let out = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut out, 0); i = i + 1; };
        out
    }

    /// Returns bit `index` of a 32-byte key, most significant bit first.
    public fun bit(key: &vector<u8>, index: u64): bool {
        let byte = *vector::borrow(key, index / 8);
        ((byte >> ((7 - (index % 8)) as u8)) & 1) == 1
    }

    /// Hashes a leaf.
    ///
    /// The leaf commits to its whole key, not only its value. Without that a
    /// leaf high in the tree would verify at any position beneath it, letting a
    /// prover relocate a genuine leaf to answer a query about another key.
    public fun hash_leaf(key: vector<u8>, value_hash: vector<u8>): vector<u8> {
        let buf = codec::begin(codec::domain_trie_leaf());
        codec::put_field(&mut buf, key);
        codec::put_field(&mut buf, value_hash);
        codec::commit(buf)
    }

    /// Hashes an internal node.
    public fun hash_internal(left: vector<u8>, right: vector<u8>): vector<u8> {
        let buf = codec::begin(codec::domain_trie_internal());
        codec::put_field(&mut buf, left);
        codec::put_field(&mut buf, right);
        codec::commit(buf)
    }

    /// Hashes a stored value.
    public fun hash_value(value: vector<u8>): vector<u8> {
        codec::commit(value)
    }

    fun terminal_hash(t: &Terminal): vector<u8> {
        if (t.is_leaf) { hash_leaf(t.key, t.value_hash) } else { zero() }
    }

    /// Reconstructs the root this proof implies for `key`.
    ///
    /// Folding upward uses the *queried* key's bits to decide left or right at
    /// each level, so siblings or a terminal lifted from elsewhere in the tree
    /// reconstruct to some other root and are rejected by the caller.
    public fun reconstruct_root(proof: &Proof, key: vector<u8>): vector<u8> {
        let depth = vector::length(&proof.siblings);
        assert!(depth <= MAX_DEPTH, E_TOO_DEEP);

        if (proof.terminal.is_leaf) {
            let i = 0;
            while (i < depth) {
                assert!(bit(&proof.terminal.key, i) == bit(&key, i), E_LEAF_OFF_PATH);
                i = i + 1;
            };
        };

        let running = terminal_hash(&proof.terminal);
        let level = depth;
        while (level > 0) {
            level = level - 1;
            let sibling = *vector::borrow(&proof.siblings, level);
            running = if (bit(&key, level)) {
                hash_internal(sibling, running)
            } else {
                hash_internal(running, sibling)
            };
        };
        running
    }

    /// Verifies that `key` holds `value_hash` under `root`.
    public fun verify_inclusion(
        proof: &Proof,
        root: vector<u8>,
        key: vector<u8>,
        value_hash: vector<u8>,
    ) {
        assert!(reconstruct_root(proof, key) == root, E_ROOT_MISMATCH);
        assert!(proof.terminal.is_leaf, E_KEY_ABSENT);
        assert!(proof.terminal.key == key, E_KEY_ABSENT);
        assert!(proof.terminal.value_hash == value_hash, E_VALUE_MISMATCH);
    }

    /// Verifies that `key` is absent under `root`.
    ///
    /// Absence has two shapes: the path hits an empty subtree, or it hits a leaf
    /// holding a different key. The second is what keeps the tree compact.
    public fun verify_non_inclusion(proof: &Proof, root: vector<u8>, key: vector<u8>) {
        assert!(reconstruct_root(proof, key) == root, E_ROOT_MISMATCH);
        if (proof.terminal.is_leaf) {
            assert!(proof.terminal.key != key, E_KEY_PRESENT);
        };
    }

    /// Builds the subtree separating two keys that agree down to `depth`.
    fun split_hash(
        depth: u64,
        key_a: vector<u8>,
        value_a: vector<u8>,
        key_b: vector<u8>,
        value_b: vector<u8>,
    ): vector<u8> {
        assert!(depth < MAX_DEPTH, E_KEYS_NOT_DISTINCT);
        let bit_a = bit(&key_a, depth);
        if (bit_a == bit(&key_b, depth)) {
            let child = split_hash(depth + 1, key_a, value_a, key_b, value_b);
            if (bit_a) { hash_internal(zero(), child) } else { hash_internal(child, zero()) }
        } else {
            let leaf_a = hash_leaf(key_a, value_a);
            let leaf_b = hash_leaf(key_b, value_b);
            if (bit_a) { hash_internal(leaf_b, leaf_a) } else { hash_internal(leaf_a, leaf_b) }
        }
    }

    /// Derives the root that results from writing `new_value_hash` at `key`.
    ///
    /// This is how L1 obtains a post-state root while holding no state. Three
    /// cases: the slot is empty, the slot holds this key, or the slot holds a
    /// different key and the tree has to grow.
    ///
    /// Only writes and insertions are covered, never removals -- collapsing a
    /// branch depends on a subtree shape the proof does not describe. The state
    /// transition function is append-only for exactly this reason.
    public fun compute_updated_root(
        proof: &Proof,
        key: vector<u8>,
        new_value_hash: vector<u8>,
    ): vector<u8> {
        let depth = vector::length(&proof.siblings);
        assert!(depth <= MAX_DEPTH, E_TOO_DEEP);

        let running = if (!proof.terminal.is_leaf) {
            hash_leaf(key, new_value_hash)
        } else if (proof.terminal.key == key) {
            hash_leaf(key, new_value_hash)
        } else {
            let i = 0;
            while (i < depth) {
                assert!(bit(&proof.terminal.key, i) == bit(&key, i), E_LEAF_OFF_PATH);
                i = i + 1;
            };
            split_hash(depth, key, new_value_hash, proof.terminal.key, proof.terminal.value_hash)
        };

        let level = depth;
        while (level > 0) {
            level = level - 1;
            let sibling = *vector::borrow(&proof.siblings, level);
            running = if (bit(&key, level)) {
                hash_internal(sibling, running)
            } else {
                hash_internal(running, sibling)
            };
        };
        running
    }

    // --- Conformance tests ---------------------------------------------------

    #[test]
    fun leaf_hash_matches_rust() {
        let key = vector::empty<u8>();
        let value = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut key, 0x11);
            vector::push_back(&mut value, 0x22);
            i = i + 1;
        };
        assert!(
            hash_leaf(key, value)
                == x"73c5510a8cd653a71e35e8f8490ef69d79ddb2ba6dafa87979e1911437847a5e",
            0
        );
    }

    #[test]
    fun internal_hash_matches_rust() {
        let left = vector::empty<u8>();
        let right = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut left, 0x33);
            vector::push_back(&mut right, 0x44);
            i = i + 1;
        };
        assert!(
            hash_internal(left, right)
                == x"1ce5eb0f34bb4dfa71f05fb3d1ccc7e3b52c158f35ba7086a26a2abae6df3ff2",
            0
        );
    }

    #[test]
    fun single_leaf_root_matches_rust() {
        // A lone leaf sits at the root rather than at full depth, so the root
        // of a one-key trie is just that leaf's hash.
        let key = zero();
        let root = hash_leaf(key, hash_value(b"a"));
        assert!(
            root == x"01bb0ea15ec5c5d9427e68a1338c7dbc18373a2a5090874f1366d6fcb39cc6e8",
            0
        );
    }

    #[test]
    fun bits_read_most_significant_first() {
        let key = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut key, 0xA0); i = i + 1; };
        assert!(bit(&key, 0), 0);
        assert!(!bit(&key, 1), 1);
        assert!(bit(&key, 2), 2);
        assert!(!bit(&key, 3), 3);
    }

    #[test]
    fun a_lone_leaf_verifies_against_its_own_root() {
        let key = zero();
        let value_hash = hash_value(b"a");
        let proof = new_proof(vector::empty(), leaf_terminal(key, value_hash));
        verify_inclusion(&proof, hash_leaf(key, value_hash), key, value_hash);
    }

    #[test]
    #[expected_failure(abort_code = E_VALUE_MISMATCH)]
    fun a_proof_cannot_claim_the_wrong_value() {
        let key = zero();
        let real = hash_value(b"1000");
        let proof = new_proof(vector::empty(), leaf_terminal(key, real));
        verify_inclusion(&proof, hash_leaf(key, real), key, hash_value(b"999999"));
    }

    #[test]
    fun an_empty_trie_proves_non_inclusion() {
        let proof = new_proof(vector::empty(), empty_terminal());
        verify_non_inclusion(&proof, zero(), zero());
    }

    #[test]
    #[expected_failure(abort_code = E_KEY_PRESENT)]
    fun a_present_key_cannot_be_proved_absent() {
        let key = zero();
        let value_hash = hash_value(b"a");
        let proof = new_proof(vector::empty(), leaf_terminal(key, value_hash));
        verify_non_inclusion(&proof, hash_leaf(key, value_hash), key);
    }

    #[test]
    fun writing_into_an_empty_trie_yields_the_leaf_root() {
        let key = zero();
        let proof = new_proof(vector::empty(), empty_terminal());
        let updated = compute_updated_root(&proof, key, hash_value(b"a"));
        assert!(
            updated == x"01bb0ea15ec5c5d9427e68a1338c7dbc18373a2a5090874f1366d6fcb39cc6e8",
            0
        );
    }

    #[test]
    fun overwriting_a_leaf_replaces_its_value() {
        let key = zero();
        let proof = new_proof(vector::empty(), leaf_terminal(key, hash_value(b"old")));
        let updated = compute_updated_root(&proof, key, hash_value(b"new"));
        assert!(updated == hash_leaf(key, hash_value(b"new")), 0);
    }
}
