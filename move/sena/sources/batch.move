/// The batch commitment, as `sena_stf::batch` builds it.
///
/// ```text
/// leaf_i  = H(BATCH_LEAF, i, start_pc_i, tx_bytes_i)
/// node    = H(BATCH_NODE, left, right)
/// header  = H(BATCH, timestamp, tx_count, root)
/// ```
///
/// A dispute proves one leaf against the root an assertion carries, then
/// compiles that leaf's transaction to find the instruction at a step.
module sena::batch {
    use std::vector;
    use sena::codec;

    const DOMAIN_BATCH: vector<u8> = b"SENA:v1:batch";
    const DOMAIN_BATCH_LEAF: vector<u8> = b"SENA:v1:batch-leaf";
    const DOMAIN_BATCH_NODE: vector<u8> = b"SENA:v1:batch-node";

    /// More siblings than any batch tree can have.
    const MAX_DEPTH: u64 = 32;

    public fun leaf_hash(index: u64, start_pc: u64, tx_bytes: vector<u8>): vector<u8> {
        let buf = codec::begin(DOMAIN_BATCH_LEAF);
        codec::put_field_u64(&mut buf, index);
        codec::put_field_u64(&mut buf, start_pc);
        codec::put_field(&mut buf, tx_bytes);
        codec::commit(buf)
    }

    fun node_hash(left: vector<u8>, right: vector<u8>): vector<u8> {
        let buf = codec::begin(DOMAIN_BATCH_NODE);
        codec::put_field(&mut buf, left);
        codec::put_field(&mut buf, right);
        codec::commit(buf)
    }

    /// The header commitment an assertion carries.
    public fun header_commitment(
        timestamp: u64,
        base_fee: u128,
        fee_recipient: vector<u8>,
        tx_count: u64,
        tx_root: vector<u8>,
    ): vector<u8> {
        let buf = codec::begin(DOMAIN_BATCH);
        codec::put_field_u64(&mut buf, timestamp);
        codec::put_field_u128(&mut buf, base_fee);
        codec::put_field(&mut buf, fee_recipient);
        codec::put_field_u64(&mut buf, tx_count);
        codec::put_field(&mut buf, tx_root);
        codec::commit(buf)
    }

    /// The root over published transactions, as `BatchTree::build` computes
    /// it: leaves padded with zero hashes to a power of two.
    public fun root_of(tx_bytes: &vector<vector<u8>>, tx_starts: &vector<u64>): vector<u8> {
        let n = vector::length(tx_bytes);
        let level = vector::empty<vector<u8>>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut level, leaf_hash(i, *vector::borrow(tx_starts, i), *vector::borrow(tx_bytes, i)));
            i = i + 1;
        };
        let width = 1;
        while (width < n) { width = width * 2 };
        while (vector::length(&level) < width) { vector::push_back(&mut level, zero()) };
        while (vector::length(&level) > 1) {
            let above = vector::empty<vector<u8>>();
            let j = 0;
            while (j < vector::length(&level)) {
                vector::push_back(&mut above, node_hash(*vector::borrow(&level, j), *vector::borrow(&level, j + 1)));
                j = j + 2;
            };
            level = above;
        };
        *vector::borrow(&level, 0)
    }

    fun zero(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, 0); i = i + 1; };
        v
    }

    /// The root a leaf and its sibling path imply (`LeafProof::root_for`).
    public fun root_for(leaf: vector<u8>, index: u64, siblings: &vector<vector<u8>>): vector<u8> {
        let depth = vector::length(siblings);
        assert!(depth <= MAX_DEPTH, 0);
        let node = leaf;
        let i = index;
        let level = 0;
        while (level < depth) {
            let sibling = *vector::borrow(siblings, level);
            node = if (i % 2 == 0) { node_hash(node, sibling) } else { node_hash(sibling, node) };
            i = i / 2;
            level = level + 1;
        };
        node
    }

    /// Whether `tx_bytes` is leaf `index` of a batch with `tx_count` leaves and
    /// root `tx_root`, starting at `start_pc`.
    ///
    /// The path length is checked against the tree height `tx_count` implies,
    /// so a proof cannot claim a leaf at a depth the tree does not have.
    public fun proves(
        tx_root: vector<u8>,
        tx_count: u64,
        index: u64,
        start_pc: u64,
        tx_bytes: vector<u8>,
        siblings: &vector<vector<u8>>,
    ): bool {
        if (index >= tx_count) { return false };
        let width = 1;
        let height = 0;
        while (width < tx_count) { width = width * 2; height = height + 1; };
        if (vector::length(siblings) != height) { return false };
        root_for(leaf_hash(index, start_pc, tx_bytes), index, siblings) == tx_root
    }
}
