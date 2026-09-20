/// Canonical encoding, mirrored from the Rust implementation.
///
/// Every digest this module produces must be byte-identical to the one
/// `sena-primitives` produces for the same input. That is not a nice-to-have:
/// this module is what Aptos L1 uses to decide disputes, and a divergence
/// decides them wrongly in one direction or the other. The tests at the bottom
/// pin the shared conformance vectors, and the same values are asserted on the
/// Rust side in `crates/sena-stf/tests/conformance.rs`.
module sena::codec {
    use std::hash;
    use std::vector;

    // --- Domain tags ---------------------------------------------------------
    // Two constructions must never share a preimage, even given identical
    // field values.

    const DOMAIN_TRIE_INTERNAL: vector<u8> = b"SENA:v1:trie-internal";
    const DOMAIN_TRIE_LEAF: vector<u8> = b"SENA:v1:trie-leaf";
    const DOMAIN_MACHINE_STATE: vector<u8> = b"SENA:v1:machine-state";
    const DOMAIN_ASSERTION: vector<u8> = b"SENA:v1:assertion";

    // --- Errors --------------------------------------------------------------

    /// Input ended before the value did.
    const E_TRUNCATED: u64 = 1;
    /// Bytes remained after the value was decoded.
    const E_TRAILING_BYTES: u64 = 2;
    /// A discriminant did not name a known variant.
    const E_UNKNOWN_VARIANT: u64 = 3;
    /// Balances were not in strictly ascending asset order, or a zero balance
    /// was stored. Either would give one account state two valid encodings.
    const E_NOT_CANONICAL: u64 = 4;

    public fun domain_trie_internal(): vector<u8> { DOMAIN_TRIE_INTERNAL }
    public fun domain_trie_leaf(): vector<u8> { DOMAIN_TRIE_LEAF }
    public fun domain_machine_state(): vector<u8> { DOMAIN_MACHINE_STATE }
    public fun domain_assertion(): vector<u8> { DOMAIN_ASSERTION }

    // --- Writing -------------------------------------------------------------

    /// Appends a big-endian u32.
    public fun put_u32(buf: &mut vector<u8>, value: u32) {
        vector::push_back(buf, (((value >> 24) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 16) & 0xFF) as u8));
        vector::push_back(buf, (((value >> 8) & 0xFF) as u8));
        vector::push_back(buf, ((value & 0xFF) as u8));
    }

    /// Appends a big-endian u64.
    public fun put_u64(buf: &mut vector<u8>, value: u64) {
        let i = 8;
        while (i > 0) {
            i = i - 1;
            vector::push_back(buf, (((value >> ((i * 8) as u8)) & 0xFF) as u8));
        }
    }

    /// Appends a big-endian u128.
    public fun put_u128(buf: &mut vector<u8>, value: u128) {
        let i = 16;
        while (i > 0) {
            i = i - 1;
            vector::push_back(buf, (((value >> ((i * 8) as u8)) & 0xFF) as u8));
        }
    }

    /// Appends a length-prefixed field, as `CanonicalEncoder::field` does.
    ///
    /// Framing is what stops `("ab", "c")` and `("a", "bc")` sharing a
    /// preimage -- which, for address derivation, would mean two users deriving
    /// one address.
    public fun put_field(buf: &mut vector<u8>, bytes: vector<u8>) {
        put_u32(buf, (vector::length(&bytes) as u32));
        vector::append(buf, bytes);
    }

    /// Starts a canonical encoding in `domain`.
    public fun begin(domain: vector<u8>): vector<u8> {
        let buf = vector::empty<u8>();
        put_field(&mut buf, domain);
        buf
    }

    /// Hashes an encoding.
    public fun commit(buf: vector<u8>): vector<u8> {
        hash::sha2_256(buf)
    }

    // --- Reading -------------------------------------------------------------

    /// A cursor over a byte string.
    struct Reader has copy, drop {
        input: vector<u8>,
        offset: u64,
    }

    public fun reader(input: vector<u8>): Reader {
        Reader { input, offset: 0 }
    }

    public fun take_u8(r: &mut Reader): u8 {
        assert!(r.offset < vector::length(&r.input), E_TRUNCATED);
        let byte = *vector::borrow(&r.input, r.offset);
        r.offset = r.offset + 1;
        byte
    }

    public fun take_u32(r: &mut Reader): u32 {
        let value: u32 = 0;
        let i = 0;
        while (i < 4) {
            value = (value << 8) | (take_u8(r) as u32);
            i = i + 1;
        };
        value
    }

    public fun take_u64(r: &mut Reader): u64 {
        let value: u64 = 0;
        let i = 0;
        while (i < 8) {
            value = (value << 8) | (take_u8(r) as u64);
            i = i + 1;
        };
        value
    }

    public fun take_u128(r: &mut Reader): u128 {
        let value: u128 = 0;
        let i = 0;
        while (i < 16) {
            value = (value << 8) | (take_u8(r) as u128);
            i = i + 1;
        };
        value
    }

    public fun take_bytes(r: &mut Reader, n: u64): vector<u8> {
        assert!(r.offset + n <= vector::length(&r.input), E_TRUNCATED);
        let out = vector::empty<u8>();
        let i = 0;
        while (i < n) {
            vector::push_back(&mut out, *vector::borrow(&r.input, r.offset + i));
            i = i + 1;
        };
        r.offset = r.offset + n;
        out
    }

    public fun take_field(r: &mut Reader): vector<u8> {
        let len = (take_u32(r) as u64);
        take_bytes(r, len)
    }

    public fun take_bool(r: &mut Reader): bool {
        let byte = take_u8(r);
        assert!(byte == 0 || byte == 1, E_UNKNOWN_VARIANT);
        byte == 1
    }

    /// Asserts the value consumed all of its input.
    ///
    /// Trailing bytes are rejected rather than ignored: tolerating them would
    /// give one value two encodings, and the trie commits to bytes.
    public fun finish(r: &Reader) {
        assert!(r.offset == vector::length(&r.input), E_TRAILING_BYTES);
    }

    public fun error_not_canonical(): u64 { E_NOT_CANONICAL }
    public fun error_unknown_variant(): u64 { E_UNKNOWN_VARIANT }

    // --- Conformance tests ---------------------------------------------------
    // These constants are produced by the Rust reference implementation; see
    // `crates/sena-stf/tests/conformance.rs`.

    #[test]
    fun field_framing_matches_rust() {
        // encode("abc") in the empty domain.
        let buf = begin(b"");
        put_field(&mut buf, b"abc");
        assert!(buf == x"0000000000000003616263", 0);
    }

    #[test]
    fun u64_framing_matches_rust() {
        let buf = begin(b"");
        let field = vector::empty<u8>();
        put_u64(&mut field, 1);
        put_field(&mut buf, field);
        assert!(buf == x"00000000000000080000000000000001", 0);
    }

    #[test]
    fun sha256_matches_rust() {
        assert!(
            commit(b"abc")
                == x"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            0
        );
    }

    #[test]
    fun framing_disambiguates_field_boundaries() {
        let a = begin(b"d");
        put_field(&mut a, b"ab");
        put_field(&mut a, b"c");
        let b = begin(b"d");
        put_field(&mut b, b"a");
        put_field(&mut b, b"bc");
        assert!(a != b, 0);
    }

    #[test]
    fun integers_round_trip() {
        let buf = vector::empty<u8>();
        put_u32(&mut buf, 305419896);
        put_u64(&mut buf, 1311768467463790320);
        put_u128(&mut buf, 42);
        let r = reader(buf);
        assert!(take_u32(&mut r) == 305419896, 0);
        assert!(take_u64(&mut r) == 1311768467463790320, 1);
        assert!(take_u128(&mut r) == 42, 2);
        finish(&r);
    }

    #[test]
    #[expected_failure(abort_code = E_TRAILING_BYTES)]
    fun trailing_bytes_are_rejected() {
        let buf = vector::empty<u8>();
        put_u64(&mut buf, 1);
        vector::push_back(&mut buf, 0);
        let r = reader(buf);
        take_u64(&mut r);
        finish(&r);
    }

    #[test]
    #[expected_failure(abort_code = E_TRUNCATED)]
    fun truncated_input_is_rejected() {
        let r = reader(x"000000");
        take_u32(&mut r);
    }

    #[test]
    #[expected_failure(abort_code = E_UNKNOWN_VARIANT)]
    fun a_non_boolean_byte_is_rejected() {
        let r = reader(x"02");
        take_bool(&mut r);
    }
}
