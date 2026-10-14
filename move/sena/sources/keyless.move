/// Keyless accounts on the Aptos Keyless circuit, as Aptos L1 checks them.
///
/// Mirrors `sena_stf::keyless`: the same public-input hash, the same canonical
/// encoding rules, the same verification keys. When a dispute reaches a
/// keyless transaction, `sena::compiler` calls `verify` here; if this module
/// and the Rust node ever disagreed about a proof, a dispute over it would be
/// decided wrongly.
///
/// Nothing here aborts on bad input. A transaction whose keyless proof does not
/// verify is a transaction that should never have been in a batch, and the
/// caller needs to *learn* that, not have the call reverted.
module sena::keyless {
    use std::option;
    use std::vector;
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::bn254_algebra::{Fr, FormatFrLsb, G1, G2, Gt, FormatG1Compr, FormatG2Compr};
    use aptos_std::ed25519;
    use sena::codec;
    use sena::poseidon;

    /// Keyless accounts are disabled.
    const SETUP_DISABLED: u8 = 0;
    /// The Aptos mainnet ceremony, January 2025, circuit v1.0.1.
    const SETUP_APTOS_MAINNET_2025_01: u8 = 1;
    /// The Aptos devnet single-party test setup. Insecure.
    const SETUP_APTOS_DEVNET_INSECURE: u8 = 2;

    /// The setup id is not one this module knows.
    const E_UNKNOWN_SETUP: u64 = 1;

    const DOMAIN_KEYLESS_ADDRESS: vector<u8> = b"SENA:v1:keyless-address";

    // Shared by every Aptos Keyless setup to date (arkworks-compressed).
    const VK_ALPHA_G1: vector<u8> = x"e2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2d";
    const VK_BETA_G2: vector<u8> = x"abb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789";
    const VK_GAMMA_G2: vector<u8> = x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19";

    // aptos-keyless-trusted-setup-contributions-jan-2025, verification_key.json.
    const MAINNET_DELTA_G2: vector<u8> = x"b106619932d0ef372c46909a2492e246d5de739aa140e27f2c71c0470662f125219049cfe15e4d140d7e4bb911284aad1cad19880efb86f2d9dd4b1bb344ef8f";
    const MAINNET_IC0: vector<u8> = x"6123b6fea40de2a7e3595f9c35210da8a45a7e8c2f7da9eb4548e9210cfea81a";
    const MAINNET_IC1: vector<u8> = x"32a9b8347c512483812ee922dc75952842f8f3083edb6fe8d5c3c07e1340b683";
    const MAINNET_MAX_EXP_HORIZON_SECS: u64 = 10000000;

    // aptos-labs/devnet-groth16-keys, commit 02e5675f.
    const DEVNET_DELTA_G2: vector<u8> = x"6176de7d77e614e09ef5e8e19cbf785ffed405d6531cee13cd71a46e2b4ef30deb18f6976c172bdcd7ea8ab2b509991bb5ce34f9fbb42486b78aac62a894a480";
    const DEVNET_IC0: vector<u8> = x"7e92d0c6818f2e51248cd1e8e82eb14521d990b0bb155ab0e3cf99b888bc5387";
    const DEVNET_IC1: vector<u8> = x"be1ad9f5fec081770956f846e1d0ea97219a3f6499acc33e1a67aef6d6e16898";
    const DEVNET_MAX_EXP_HORIZON_SECS: u64 = 1000000000000;

    /// Poseidon of " " padded to 350 bytes: the circuit's "no extra field".
    const EMPTY_EXTRA_FIELD_HASH: vector<u8> = x"b95de4e43ec6d914226448629e8b4b3b5b091ac76d08919ee3d3681e4fcaa912";
    /// Poseidon of "" padded to 120 bytes: the unused override-`aud` slot.
    const EMPTY_OVERRIDE_AUD_HASH: vector<u8> = x"bc950a162b345ee72f2ec4ab2ec61891bf4fe1ab6093077eaf6cbebe41be6620";

    /// Bytes the circuit commits to for the ephemeral key: three 31-byte scalars.
    const MAX_COMMITTED_EPK_BYTES: u64 = 93;

    /// A keyless authorisation, as `sena::txcodec` decodes it.
    struct Signature has copy, drop, store {
        iss_hash: vector<u8>,
        idc: vector<u8>,
        ephemeral_public_key: vector<u8>,
        ephemeral_signature: vector<u8>,
        exp_date_secs: u64,
        exp_horizon_secs: u64,
        jwt_header_hash: vector<u8>,
        jwk_hash: vector<u8>,
        has_extra_field: bool,
        extra_field_hash: vector<u8>,
        proof: vector<u8>,
    }

    public fun new_signature(
        iss_hash: vector<u8>,
        idc: vector<u8>,
        ephemeral_public_key: vector<u8>,
        ephemeral_signature: vector<u8>,
        exp_date_secs: u64,
        exp_horizon_secs: u64,
        jwt_header_hash: vector<u8>,
        jwk_hash: vector<u8>,
        has_extra_field: bool,
        extra_field_hash: vector<u8>,
        proof: vector<u8>,
    ): Signature {
        Signature {
            iss_hash, idc, ephemeral_public_key, ephemeral_signature, exp_date_secs,
            exp_horizon_secs, jwt_header_hash, jwk_hash, has_extra_field, extra_field_hash, proof,
        }
    }

    public fun iss_hash(sig: &Signature): vector<u8> { sig.iss_hash }
    public fun jwk_hash(sig: &Signature): vector<u8> { sig.jwk_hash }

    public fun setup_disabled(): u8 { SETUP_DISABLED }
    public fun setup_aptos_mainnet(): u8 { SETUP_APTOS_MAINNET_2025_01 }
    public fun setup_aptos_devnet_insecure(): u8 { SETUP_APTOS_DEVNET_INSECURE }

    /// Aborts unless `setup` names a known parameter set. Used once, when the
    /// dispute registry is created; afterwards the choice cannot change.
    public fun assert_known_setup(setup: u8) {
        assert!(setup <= SETUP_APTOS_DEVNET_INSECURE, E_UNKNOWN_SETUP);
    }

    /// The address a keyless identity controls: `H(iss_hash, idc)`.
    public fun address_of(sig: &Signature): vector<u8> {
        let buf = codec::begin(DOMAIN_KEYLESS_ADDRESS);
        codec::put_field(&mut buf, sig.iss_hash);
        codec::put_field(&mut buf, sig.idc);
        codec::commit(buf)
    }

    fun fr_canonical(bytes: &vector<u8>): option::Option<Element<Fr>> {
        if (vector::length(bytes) != 32) { return option::none() };
        // The deserialiser refuses values at or above the modulus, which is
        // exactly the canonical-encoding rule the Rust node enforces.
        crypto_algebra::deserialize<Fr, FormatFrLsb>(bytes)
    }

    /// Packs up to 31 little-endian bytes into one scalar.
    fun pack31(bytes: &vector<u8>, from: u64, to: u64): Element<Fr> {
        let out = vector::empty<u8>();
        let i = from;
        while (i < to) {
            vector::push_back(&mut out, *vector::borrow(bytes, i));
            i = i + 1;
        };
        while (vector::length(&out) < 32) { vector::push_back(&mut out, 0) };
        option::extract(&mut crypto_algebra::deserialize<Fr, FormatFrLsb>(&out))
    }

    /// The ephemeral key as the circuit commits to it: its Aptos BCS encoding
    /// (0x00, 0x20, key) padded to 93 bytes, three scalars, then the length.
    fun epk_scalars(epk: &vector<u8>): vector<Element<Fr>> {
        let bcs = vector[0u8, 32u8];
        vector::append(&mut bcs, *epk);
        let len = vector::length(&bcs);
        while (vector::length(&bcs) < MAX_COMMITTED_EPK_BYTES) { vector::push_back(&mut bcs, 0) };
        vector[
            pack31(&bcs, 0, 31),
            pack31(&bcs, 31, 62),
            pack31(&bcs, 62, 93),
            crypto_algebra::from_u64<Fr>(len),
        ]
    }

    /// The circuit's single public input. `none` if any field element is not
    /// canonically encoded.
    public fun public_inputs_hash(sig: &Signature): option::Option<Element<Fr>> {
        let idc = fr_canonical(&sig.idc);
        let iss = fr_canonical(&sig.iss_hash);
        let header = fr_canonical(&sig.jwt_header_hash);
        let jwk = fr_canonical(&sig.jwk_hash);
        let extra = if (sig.has_extra_field) {
            fr_canonical(&sig.extra_field_hash)
        } else {
            fr_canonical(&EMPTY_EXTRA_FIELD_HASH)
        };
        if (option::is_none(&idc) || option::is_none(&iss) || option::is_none(&header)
            || option::is_none(&jwk) || option::is_none(&extra)
            || vector::length(&sig.ephemeral_public_key) != 32) {
            return option::none()
        };

        let s = epk_scalars(&sig.ephemeral_public_key);
        vector::push_back(&mut s, option::extract(&mut idc));
        vector::push_back(&mut s, crypto_algebra::from_u64<Fr>(sig.exp_date_secs));
        vector::push_back(&mut s, crypto_algebra::from_u64<Fr>(sig.exp_horizon_secs));
        vector::push_back(&mut s, option::extract(&mut iss));
        vector::push_back(&mut s, crypto_algebra::from_u64<Fr>(if (sig.has_extra_field) { 1 } else { 0 }));
        vector::push_back(&mut s, option::extract(&mut extra));
        vector::push_back(&mut s, option::extract(&mut header));
        vector::push_back(&mut s, option::extract(&mut jwk));
        vector::push_back(&mut s, option::extract(&mut fr_canonical(&EMPTY_OVERRIDE_AUD_HASH)));
        vector::push_back(&mut s, crypto_algebra::zero<Fr>()); // use_override_aud
        option::some(poseidon::hash14(&s))
    }

    fun g1(bytes: &vector<u8>): option::Option<Element<G1>> {
        crypto_algebra::deserialize<G1, FormatG1Compr>(bytes)
    }

    fun g2(bytes: &vector<u8>): option::Option<Element<G2>> {
        crypto_algebra::deserialize<G2, FormatG2Compr>(bytes)
    }

    /// Checks a Groth16 proof (A ‖ B ‖ C, compressed) against one public input.
    fun groth16_verify(setup: u8, proof: &vector<u8>, x: &Element<Fr>): bool {
        if (vector::length(proof) != 128) { return false };
        let a_bytes = vector::empty<u8>();
        let b_bytes = vector::empty<u8>();
        let c_bytes = vector::empty<u8>();
        let i = 0;
        while (i < 128) {
            let byte = *vector::borrow(proof, i);
            if (i < 32) { vector::push_back(&mut a_bytes, byte) }
            else if (i < 96) { vector::push_back(&mut b_bytes, byte) }
            else { vector::push_back(&mut c_bytes, byte) };
            i = i + 1;
        };
        let a = g1(&a_bytes);
        let b = g2(&b_bytes);
        let c = g1(&c_bytes);
        if (option::is_none(&a) || option::is_none(&b) || option::is_none(&c)) { return false };

        let (delta, ic0, ic1) = if (setup == SETUP_APTOS_MAINNET_2025_01) {
            (MAINNET_DELTA_G2, MAINNET_IC0, MAINNET_IC1)
        } else {
            (DEVNET_DELTA_G2, DEVNET_IC0, DEVNET_IC1)
        };
        let alpha = option::extract(&mut g1(&VK_ALPHA_G1));
        let beta = option::extract(&mut g2(&VK_BETA_G2));
        let gamma = option::extract(&mut g2(&VK_GAMMA_G2));
        let delta = option::extract(&mut g2(&delta));
        let ic0 = option::extract(&mut g1(&ic0));
        let ic1 = option::extract(&mut g1(&ic1));

        // L = IC0 + x * IC1. The check e(A, B) = e(alpha, beta) e(L, gamma)
        // e(C, delta) is evaluated as one multi-pairing equal to the identity.
        let l = crypto_algebra::add(&ic0, &crypto_algebra::scalar_mul(&ic1, x));
        let lhs = vector[
            crypto_algebra::neg(&option::extract(&mut a)),
            alpha,
            l,
            option::extract(&mut c),
        ];
        let rhs = vector[option::extract(&mut b), beta, gamma, delta];
        let product = crypto_algebra::multi_pairing<G1, G2, Gt>(&lhs, &rhs);
        crypto_algebra::eq(&product, &crypto_algebra::zero<Gt>())
    }

    /// Verifies a keyless authorisation of `digest` for `sender`, at batch time
    /// `now`, under `setup`. Mirrors `sena_stf::keyless::verify`.
    public fun verify(
        setup: u8,
        sig: &Signature,
        sender: &vector<u8>,
        digest: &vector<u8>,
        now: u64,
    ): bool {
        if (setup == SETUP_DISABLED || setup > SETUP_APTOS_DEVNET_INSECURE) { return false };
        if (address_of(sig) != *sender) { return false };
        let max_horizon = if (setup == SETUP_APTOS_MAINNET_2025_01) {
            MAINNET_MAX_EXP_HORIZON_SECS
        } else {
            DEVNET_MAX_EXP_HORIZON_SECS
        };
        if (sig.exp_horizon_secs > max_horizon) { return false };
        if (now >= sig.exp_date_secs) { return false };
        if (!verify_ed25519_strict(&sig.ephemeral_public_key, &sig.ephemeral_signature, digest)) {
            return false
        };
        let pih = public_inputs_hash(sig);
        if (option::is_none(&pih)) { return false };
        groth16_verify(setup, &sig.proof, &option::extract(&mut pih))
    }

    /// Strict Ed25519 verification, as the Rust node performs it.
    public fun verify_ed25519_strict(
        public_key: &vector<u8>,
        signature: &vector<u8>,
        message: &vector<u8>,
    ): bool {
        if (vector::length(public_key) != 32 || vector::length(signature) != 64) { return false };
        let sig = ed25519::new_signature_from_bytes(*signature);
        let pk = ed25519::new_unvalidated_public_key_from_bytes(*public_key);
        ed25519::signature_verify_strict(&sig, &pk, *message)
    }

    #[test_only]
    public fun aptos_sample_for_test(ephemeral_signature: vector<u8>): Signature {
        Signature {
            iss_hash: x"99ea393f95ab3ea2a738c93533a88809b66606cfe1b783b287c820232424e50c",
            idc: x"c390842e61c06e1ec945fc8504ad0830652ec1b6fc7bb0a095026be7551e001d",
            ephemeral_public_key: x"20fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a144",
            ephemeral_signature,
            exp_date_secs: 111111111111,
            exp_horizon_secs: 999999999999,
            jwt_header_hash: x"17d823f3faf10d12f1165f265539558049822e861107482fe937593bf790fb2b",
            jwk_hash: x"e8456e1566778048562a66f27e17322798406f095d689c590c6189138cd79b10",
            has_extra_field: true,
            extra_field_hash: x"4f4bf0bc011ecaa660c418f40c18083b3cc855e3571a8220e497236a57c7aa03",
            proof: x"3304cc0defd488d770af0439480ec24c8473b30dbcbfad9fdf99ca62256bd9082f432b9459375ed2032bcb1ff3ccc1dd5d05a752d6956d2bb003f4e3b42d0b242cf4ab4d3dc8dc700ede17bbfeaddedd42033691e3d85ff8d6621663cb2e779ad44ee2772f4b48fdb0dbd8d870d3fb4401cd3a28fbdde535e9c57bac9a263f9c",
        }
    }

    #[test]
    /// The public-input hash of Aptos's sample, as aptos-core and the Rust node
    /// compute it.
    fun the_public_inputs_hash_matches_aptos() {
        let sig = aptos_sample_for_test(vector::empty());
        let pih = option::extract(&mut public_inputs_hash(&sig));
        let expected = option::extract(&mut fr_canonical(
            &x"f35c81dd7960104f5bdbc26def36c247544b7ebc21500890e77afa046742ac23"
        ));
        assert!(crypto_algebra::eq(&pih, &expected), 0);
    }

    #[test]
    /// Aptos's sample proof verifies under the devnet setup, and not under the
    /// mainnet one.
    fun the_aptos_sample_proof_verifies() {
        let sig = aptos_sample_for_test(vector::empty());
        let x = option::extract(&mut public_inputs_hash(&sig));
        assert!(groth16_verify(SETUP_APTOS_DEVNET_INSECURE, &sig.proof, &x), 0);
        assert!(!groth16_verify(SETUP_APTOS_MAINNET_2025_01, &sig.proof, &x), 1);
        // Any change to the public input breaks it.
        let y = crypto_algebra::add(&x, &crypto_algebra::one<Fr>());
        assert!(!groth16_verify(SETUP_APTOS_DEVNET_INSECURE, &sig.proof, &y), 2);
    }

    #[test]
    fun the_sample_address_matches_rust() {
        let sig = aptos_sample_for_test(vector::empty());
        assert!(address_of(&sig) == x"4953f4e88ea6ed81e7f7e755ac4205de8191b47841060658c8a281fa05bc54ad", 0);
    }

    #[test]
    fun non_canonical_scalars_yield_no_hash() {
        let sig = aptos_sample_for_test(vector::empty());
        sig.jwk_hash = x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(option::is_none(&public_inputs_hash(&sig)), 0);
    }
}
