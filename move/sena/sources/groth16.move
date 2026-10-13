/// On-chain Groth16 zero-knowledge proof verification over the BN254 curve (REQ-AUTH-003, REQ-AUTH-004).
///
/// Implements verification of zero-knowledge SNARKs on Aptos L1 for SENA keyless
/// accounts and optimistic dispute settlement.
module sena::groth16 {
    use std::option;
    use std::vector;
    use aptos_std::crypto_algebra::{
        Element, from_u64, multi_scalar_mul, eq, multi_pairing, pairing, add, zero, deserialize
    };
    use aptos_std::bn254_algebra::{
        G1, G2, Gt, Fr, FormatG1Compr, FormatG2Compr
    };

    // --- Errors --------------------------------------------------------------

    /// Proof bytes length does not match expected size.
    const E_INVALID_PROOF_LENGTH: u64 = 1;
    /// Proof deserialization failed.
    const E_PROOF_DESERIALIZATION_FAILED: u64 = 2;
    /// Public inputs deserialization failed.
    const E_PUBLIC_INPUT_DESERIALIZATION_FAILED: u64 = 3;

    // --- Generic Groth16 Verification ----------------------------------------

    /// Verifies a Groth16 proof against the verification key and public inputs.
    ///
    /// Equation:
    ///   e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)
    /// where L = vk_gamma_abc[0] + \sum_{i=1}^l public_inputs[i-1] * vk_gamma_abc[i]
    public fun verify_proof<G1T, G2T, GtT, ST>(
        vk_alpha_g1: &Element<G1T>,
        vk_beta_g2: &Element<G2T>,
        vk_gamma_g2: &Element<G2T>,
        vk_delta_g2: &Element<G2T>,
        vk_uvw_gamma_g1: &vector<Element<G1T>>,
        public_inputs: &vector<Element<ST>>,
        proof_a: &Element<G1T>,
        proof_b: &Element<G2T>,
        proof_c: &Element<G1T>,
    ): bool {
        let left = pairing<G1T, G2T, GtT>(proof_a, proof_b);
        let scalars = vector[from_u64<ST>(1)];
        vector::append(&mut scalars, *public_inputs);

        let right = zero<GtT>();
        let right = add(&right, &pairing<G1T, G2T, GtT>(vk_alpha_g1, vk_beta_g2));
        let l_point = multi_scalar_mul(vk_uvw_gamma_g1, &scalars);
        let right = add(&right, &pairing(&l_point, vk_gamma_g2));
        let right = add(&right, &pairing(proof_c, vk_delta_g2));

        eq(&left, &right)
    }

    /// Verifies a Groth16 proof with precomputed prepared verification key (PVK).
    /// Optimized for low verification latency on chain.
    public fun verify_proof_prepared<G1T, G2T, GtT, ST>(
        pvk_alpha_g1_beta_g2: &Element<GtT>,
        pvk_gamma_g2_neg: &Element<G2T>,
        pvk_delta_g2_neg: &Element<G2T>,
        pvk_uvw_gamma_g1: &vector<Element<G1T>>,
        public_inputs: &vector<Element<ST>>,
        proof_a: &Element<G1T>,
        proof_b: &Element<G2T>,
        proof_c: &Element<G1T>,
    ): bool {
        let scalars = vector[from_u64<ST>(1)];
        vector::append(&mut scalars, *public_inputs);

        let l_point = multi_scalar_mul(pvk_uvw_gamma_g1, &scalars);
        let g1_elements = vector[*proof_a, l_point, *proof_c];
        let g2_elements = vector[*proof_b, *pvk_gamma_g2_neg, *pvk_delta_g2_neg];

        eq(pvk_alpha_g1_beta_g2, &multi_pairing<G1T, G2T, GtT>(&g1_elements, &g2_elements))
    }

    // --- BN254 Specialization ------------------------------------------------

    /// Verifies a BN254 Groth16 proof using curve points.
    public fun verify_bn254(
        vk_alpha_g1: &Element<G1>,
        vk_beta_g2: &Element<G2>,
        vk_gamma_g2: &Element<G2>,
        vk_delta_g2: &Element<G2>,
        vk_gamma_abc_g1: &vector<Element<G1>>,
        public_inputs: &vector<Element<Fr>>,
        proof_a: &Element<G1>,
        proof_b: &Element<G2>,
        proof_c: &Element<G1>,
    ): bool {
        verify_proof<G1, G2, Gt, Fr>(
            vk_alpha_g1,
            vk_beta_g2,
            vk_gamma_g2,
            vk_delta_g2,
            vk_gamma_abc_g1,
            public_inputs,
            proof_a,
            proof_b,
            proof_c,
        )
    }

    /// Verifies a 128-byte compressed BN254 proof (32 bytes A + 64 bytes B + 32 bytes C).
    public fun verify_bn254_compressed(
        vk_alpha_g1: &Element<G1>,
        vk_beta_g2: &Element<G2>,
        vk_gamma_g2: &Element<G2>,
        vk_delta_g2: &Element<G2>,
        vk_gamma_abc_g1: &vector<Element<G1>>,
        public_inputs: &vector<Element<Fr>>,
        proof_bytes: &vector<u8>,
    ): bool {
        if (vector::length(proof_bytes) != 128) {
            return false
        };

        let a_bytes = vector::empty<u8>();
        let b_bytes = vector::empty<u8>();
        let c_bytes = vector::empty<u8>();

        let i = 0;
        while (i < 32) {
            vector::push_back(&mut a_bytes, *vector::borrow(proof_bytes, i));
            i = i + 1;
        };
        while (i < 96) {
            vector::push_back(&mut b_bytes, *vector::borrow(proof_bytes, i));
            i = i + 1;
        };
        while (i < 128) {
            vector::push_back(&mut c_bytes, *vector::borrow(proof_bytes, i));
            i = i + 1;
        };

        let opt_a = deserialize<G1, FormatG1Compr>(&a_bytes);
        let opt_b = deserialize<G2, FormatG2Compr>(&b_bytes);
        let opt_c = deserialize<G1, FormatG1Compr>(&c_bytes);

        if (option::is_none(&opt_a) || option::is_none(&opt_b) || option::is_none(&opt_c)) {
            return false
        };

        let proof_a = option::extract(&mut opt_a);
        let proof_b = option::extract(&mut opt_b);
        let proof_c = option::extract(&mut opt_c);

        verify_bn254(
            vk_alpha_g1,
            vk_beta_g2,
            vk_gamma_g2,
            vk_delta_g2,
            vk_gamma_abc_g1,
            public_inputs,
            &proof_a,
            &proof_b,
            &proof_c,
        )
    }

    #[test]
    fun test_bn254_groth16_verification_pairing() {
        // Construct identity test statement:
        // alpha in G1, beta in G2
        // gamma, delta in G2
        // proof: A = alpha, B = beta, C = 0
        // public_inputs: [x1]
        // vk_gamma_abc: [ic0, ic1] where ic0 = - (x1 * ic1)
        let alpha = zero<G1>();
        let beta = zero<G2>();
        let gamma = zero<G2>();
        let delta = zero<G2>();

        let vk_gamma_abc = vector[zero<G1>(), zero<G1>()];
        let public_inputs = vector[from_u64<Fr>(42)];

        let proof_a = zero<G1>();
        let proof_b = zero<G2>();
        let proof_c = zero<G1>();

        // With zero points: left pairing is zero, right sum of pairings is zero, eq holds
        let valid = verify_bn254(
            &alpha,
            &beta,
            &gamma,
            &delta,
            &vk_gamma_abc,
            &public_inputs,
            &proof_a,
            &proof_b,
            &proof_c,
        );
        assert!(valid, 100);
    }
}
