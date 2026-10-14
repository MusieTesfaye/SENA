// End-to-end disputes on Aptos L1, replaying vectors the Rust node generated.
//
// `sena::vectors` is written by crates/sena-fraudproof/tests/move_vectors.rs:
// a real batch (two Ed25519 transfers and a keyless transfer carrying Aptos's
// real circuit proof), the honest trace, a forged trace, and the moves of the
// disputes the Rust dispute model plays over them. These tests make the actual
// contracts play the same games and check they reach the same verdicts -- and
// that the compiler on L1 turns every published transaction into exactly the
// instructions the node did.
#[test_only]
module sena::dispute_e2e_test {
    use std::option;
    use std::signer;
    use std::string;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::fungible_asset::{Self, MintRef, Metadata};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;

    use sena::assertions;
    use sena::batch;
    use sena::compiler;
    use sena::disputes;
    use sena::keyless;
    use sena::keyless_jobs;
    use sena::osp;
    use sena::txcodec;
    use sena::vectors as v;

    const WINDOW: u64 = 604800;
    const BOND: u128 = 1000000;
    const FUNDING: u64 = 10000000;
    const TREASURY: address = @0x7EA;
    const MAX_BATCH_AGE: u64 = 3600;

    // --- Compiler conformance -------------------------------------------------

    #[test]
    fun the_l1_compiler_matches_the_node_on_every_case() {
        let n = v::compile_case_count();
        let i = 0;
        while (i < n) {
            let (bytes, ts, setup, expected_ok, expected_program, expected_digest) = v::compile_case(i);
            let (ok, program) = compiler::compile(bytes, ts, setup);
            assert!(ok == expected_ok, 1000 + i);
            if (ok) {
                assert!(vector::length(&program) == vector::length(&expected_program), 2000 + i);
                let k = 0;
                while (k < vector::length(&program)) {
                    assert!(
                        osp::encode_instruction(vector::borrow(&program, k))
                            == *vector::borrow(&expected_program, k),
                        3000 + i * 10 + k
                    );
                    k = k + 1;
                };
            };
            let decoded = txcodec::decode(bytes);
            if (option::is_some(&decoded)) {
                assert!(txcodec::signing_digest(option::borrow(&decoded)) == expected_digest, 4000 + i);
            };
            i = i + 1;
        };
    }

    #[test]
    fun council_verification_consumes_the_epoch_as_the_node_does() {
        // Case 11 is the council-signed SetJwk; its fifth step is VerifyCouncil.
        let (bytes, ts, setup, _, _, _) = v::compile_case(11);
        let (ok, program) = compiler::compile(bytes, ts, setup);
        assert!(ok, 0);
        let verify = vector::borrow(&program, 4);
        assert!(osp::encode_instruction(verify) == v::council_instruction(), 1);
        assert!(osp::slot_of(verify) == v::council_slot(), 2);
        let (ok, after) = osp::transition(verify, true, v::council_before());
        assert!(ok && after == v::council_after(), 3);
        // Replaying the same signed payload against the advanced council fails.
        let (ok, _) = osp::transition(verify, true, after);
        assert!(!ok, 4);
    }

    #[test]
    fun the_batch_root_matches_the_node() {
        assert!(batch::root_of(&v::batch_txs(), &v::batch_starts()) == v::batch_root(), 0);
        let txs = v::batch_txs();
        let starts = v::batch_starts();
        assert!(batch::proves(v::batch_root(), 3, 0, *vector::borrow(&starts, 0), *vector::borrow(&txs, 0), &v::batch_siblings_0()), 1);
        assert!(batch::proves(v::batch_root(), 3, 2, *vector::borrow(&starts, 2), *vector::borrow(&txs, 2), &v::batch_siblings_2()), 2);
        // A leaf cannot be claimed at another position.
        assert!(!batch::proves(v::batch_root(), 3, 1, *vector::borrow(&starts, 0), *vector::borrow(&txs, 0), &v::batch_siblings_0()), 3);
    }

    // --- Setup ------------------------------------------------------------------

    fun create_asset(admin: &signer): (MintRef, Object<Metadata>) {
        let constructor = object::create_named_object(admin, b"SENA_TEST_USD");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor, option::none(), string::utf8(b"Test USD"), string::utf8(b"TUSD"), 6,
            string::utf8(b""), string::utf8(b""),
        );
        let mint_ref = fungible_asset::generate_mint_ref(&constructor);
        let metadata = object::object_from_constructor_ref<Metadata>(&constructor);
        (mint_ref, metadata)
    }

    fun fund(mint_ref: &MintRef, metadata: Object<Metadata>, who: address) {
        account::create_account_for_test(who);
        let store = primary_fungible_store::ensure_primary_store_exists(who, metadata);
        fungible_asset::mint_to(mint_ref, store, FUNDING);
    }

    fun balance(metadata: Object<Metadata>, who: address): u64 {
        primary_fungible_store::balance(who, metadata)
    }

    /// Stands L1 up at the batch's genesis root, with the devnet keyless
    /// setup the vectors' keyless proof was made under.
    fun setup(aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer): Object<Metadata> {
        timestamp::set_time_has_started_for_testing(aptos);
        timestamp::update_global_time_for_test_secs(v::batch_timestamp() + 30);
        account::create_account_for_test(signer::address_of(admin));
        let (mint_ref, metadata) = create_asset(admin);
        assertions::initialize(admin, v::genesis_root(), WINDOW, BOND, metadata, TREASURY, MAX_BATCH_AGE);
        disputes::initialize(admin, signer::address_of(admin), keyless::setup_aptos_devnet_insecure());
        account::create_account_for_test(TREASURY);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        fund(&mint_ref, metadata, signer::address_of(challenger));
        metadata
    }

    fun zero32(): vector<u8> {
        let z = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut z, 0); i = i + 1; };
        z
    }

    fun genesis_id(): vector<u8> {
        assertions::assertion_id(zero32(), 0, zero32(), v::genesis_root(), zero32(), 0, 0)
    }

    /// Posts the vectors' batch claiming `post_root`, returning the assertion id.
    fun post_batch(
        proposer: &signer,
        admin_addr: address,
        txs: vector<vector<u8>>,
        starts: vector<u64>,
        post_root: vector<u8>,
        trace_length: u64,
    ): vector<u8> {
        let commitment = batch::header_commitment(
            v::batch_timestamp(), vector::length(&txs), batch::root_of(&txs, &starts)
        );
        assertions::post(
            proposer, admin_addr, genesis_id(), v::genesis_root(), post_root,
            v::batch_timestamp(), txs, starts, trace_length, BOND,
        );
        assertions::assertion_id(genesis_id(), 0, v::genesis_root(), post_root, commitment, trace_length, BOND)
    }

    /// Runs a keyless verification job to completion, in three chunks, the way
    /// a client spreads it over transactions on a real chain.
    fun verify_keyless(caller: &signer, admin_addr: address, tx: vector<u8>) {
        let setup = keyless::setup_aptos_devnet_insecure();
        keyless_jobs::start(caller, admin_addr, tx, v::batch_timestamp(), setup);
        let id = keyless_jobs::job_id(tx, v::batch_timestamp(), setup);
        keyless_jobs::advance(caller, admin_addr, id, 25);
        keyless_jobs::advance(caller, admin_addr, id, 25);
        keyless_jobs::advance(caller, admin_addr, id, 25);
        keyless_jobs::finish(caller, admin_addr, id);
    }

    // --- The games --------------------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    /// A sequencer asserts a root in which Bob's keyless transfer was credited
    /// a thousand times over. The honest challenger bisects to that step, and
    /// L1 -- compiling the keyless transaction, recomputing its Poseidon public
    /// input and checking its Groth16 proof -- executes it and rejects the
    /// assertion.
    fun a_fraudulent_keyless_credit_is_caught_on_l1(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let metadata = setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let id = post_batch(proposer, admin_addr, v::batch_txs(), v::batch_starts(), v::fraud_post_root(), v::trace_length());

        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::open(challenger, admin_addr, id);
        let did = disputes::dispute_id(id, signer::address_of(challenger));

        let selections = v::fraud_selections();
        let r = 0;
        while (r < v::fraud_rounds()) {
            disputes::dissect(proposer, admin_addr, did, v::fraud_dissection(r));
            disputes::select(challenger, admin_addr, did, *vector::borrow(&selections, r));
            r = r + 1;
        };
        assert!(disputes::disputed_step(admin_addr, did) == v::fraud_step(), 0);

        // The disputed step is inside the keyless transaction: its verdict is
        // computed first, over several transactions.
        verify_keyless(challenger, admin_addr, v::fraud_leaf_tx());
        disputes::one_step(
            challenger, admin_addr, did,
            v::fraud_leaf_index(), v::fraud_leaf_start(), v::fraud_leaf_tx(), v::fraud_leaf_siblings(),
            v::fraud_pre_root(), v::fraud_slot(), v::fraud_present(), v::fraud_value(),
            v::fraud_trie_siblings(), v::fraud_terminal_is_leaf(), v::fraud_terminal_key(),
            v::fraud_terminal_value_hash(),
        );

        assert!(disputes::winner(admin_addr, did) == disputes::party_challenger(), 1);
        assert!(assertions::status(admin_addr, id) == assertions::status_rejected(), 2);
        let reward = (BOND as u64) * 50 / 100;
        assert!(balance(metadata, signer::address_of(challenger)) == FUNDING + reward, 3);
        assert!(balance(metadata, signer::address_of(proposer)) == FUNDING - (BOND as u64), 4);
        assert!(assertions::escrow_balance(admin_addr) == 0, 5);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    /// The converse: an honest assertion, challenged by someone who believes
    /// the forged trace. The game ends at the same step; honest execution there
    /// reproduces the defender's claim, and the challenger loses its bond.
    fun an_honest_assertion_survives_a_wrong_challenge(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let metadata = setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let id = post_batch(proposer, admin_addr, v::batch_txs(), v::batch_starts(), v::honest_post_root(), v::trace_length());

        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::open(challenger, admin_addr, id);
        let did = disputes::dispute_id(id, signer::address_of(challenger));

        let selections = v::honest_selections();
        let r = 0;
        while (r < v::honest_rounds()) {
            disputes::dissect(proposer, admin_addr, did, v::honest_dissection(r));
            disputes::select(challenger, admin_addr, did, *vector::borrow(&selections, r));
            r = r + 1;
        };

        verify_keyless(challenger, admin_addr, v::honest_leaf_tx());
        disputes::one_step(
            challenger, admin_addr, did,
            v::honest_leaf_index(), v::honest_leaf_start(), v::honest_leaf_tx(), v::honest_leaf_siblings(),
            v::honest_pre_root(), v::honest_slot(), v::honest_present(), v::honest_value(),
            v::honest_trie_siblings(), v::honest_terminal_is_leaf(), v::honest_terminal_key(),
            v::honest_terminal_value_hash(),
        );

        assert!(disputes::winner(admin_addr, did) == disputes::party_defender(), 0);
        assert!(assertions::status(admin_addr, id) == assertions::status_pending(), 1);
        assert!(balance(metadata, signer::address_of(challenger)) == FUNDING - (BOND as u64), 2);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    #[expected_failure(abort_code = 65, location = sena::disputes)]
    fun a_keyless_step_needs_its_verdict_first(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let id = post_batch(proposer, admin_addr, v::batch_txs(), v::batch_starts(), v::fraud_post_root(), v::trace_length());
        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::open(challenger, admin_addr, id);
        let did = disputes::dispute_id(id, signer::address_of(challenger));
        let selections = v::fraud_selections();
        let r = 0;
        while (r < v::fraud_rounds()) {
            disputes::dissect(proposer, admin_addr, did, v::fraud_dissection(r));
            disputes::select(challenger, admin_addr, did, *vector::borrow(&selections, r));
            r = r + 1;
        };
        disputes::one_step(
            challenger, admin_addr, did,
            v::fraud_leaf_index(), v::fraud_leaf_start(), v::fraud_leaf_tx(), v::fraud_leaf_siblings(),
            v::fraud_pre_root(), v::fraud_slot(), v::fraud_present(), v::fraud_value(),
            v::fraud_trie_siblings(), v::fraud_terminal_is_leaf(), v::fraud_terminal_key(),
            v::fraud_terminal_value_hash(),
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    /// The resumable verdict is the one-call verdict, accepting and refusing.
    fun the_job_verdict_is_the_one_call_verdict(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let setup = keyless::setup_aptos_devnet_insecure();
        let tx = v::fraud_leaf_tx();
        verify_keyless(challenger, admin_addr, tx);
        let (done, ok) = keyless_jobs::verdict(admin_addr, keyless_jobs::job_id(tx, v::batch_timestamp(), setup));
        assert!(done && ok, 0);
        let (inline_ok, _) = compiler::compile(tx, v::batch_timestamp(), setup);
        assert!(inline_ok, 1);

        // At a batch time past the ephemeral key's expiry, both refuse; the
        // job finishes at `start` without running the permutation.
        let late = 111111111111;
        keyless_jobs::start(challenger, admin_addr, tx, late, setup);
        let (done, ok) = keyless_jobs::verdict(admin_addr, keyless_jobs::job_id(tx, late, setup));
        assert!(done && !ok, 2);
        let (inline_ok, _) = compiler::compile(tx, late, setup);
        assert!(!inline_ok, 3);
    }

    // --- Batch-structure fraud ----------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun start_positions_that_skip_steps_are_fraud(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let txs = v::gap_txs();
        let starts = v::gap_starts();
        let id = post_batch(proposer, admin_addr, txs, starts, v::honest_post_root(), 12);
        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::prove_start_gap(
            challenger, admin_addr, id, 0,
            *vector::borrow(&starts, 0), *vector::borrow(&txs, 0), v::gap_siblings_0(),
            *vector::borrow(&starts, 1), *vector::borrow(&txs, 1), v::gap_siblings_1(),
        );
        assert!(assertions::status(admin_addr, id) == assertions::status_rejected(), 0);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun a_trace_longer_than_its_transactions_is_fraud(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let txs = v::batch_txs();
        let starts = v::batch_starts();
        // One phantom step past the end, where the sequencer could put anything.
        let id = post_batch(proposer, admin_addr, txs, starts, v::honest_post_root(), v::trace_length() + 1);
        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::prove_trace_length(
            challenger, admin_addr, id, *vector::borrow(&starts, 2), *vector::borrow(&txs, 2), v::batch_siblings_2(),
        );
        assert!(assertions::status(admin_addr, id) == assertions::status_rejected(), 0);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun an_unauthorised_transaction_in_a_batch_is_fraud(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let id = post_batch(proposer, admin_addr, vector[v::bad_signature_tx()], vector[0], v::honest_post_root(), 6);
        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::prove_uncompilable(challenger, admin_addr, id, 0, 0, v::bad_signature_tx(), vector::empty());
        assert!(assertions::status(admin_addr, id) == assertions::status_rejected(), 0);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    #[expected_failure(abort_code = 63, location = sena::disputes)]
    fun an_honest_batch_admits_no_structural_proof(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let txs = v::batch_txs();
        let starts = v::batch_starts();
        let id = post_batch(proposer, admin_addr, txs, starts, v::honest_post_root(), v::trace_length());
        assertions::open_challenge(challenger, admin_addr, id, BOND);
        disputes::prove_start_gap(
            challenger, admin_addr, id, 0,
            *vector::borrow(&starts, 0), *vector::borrow(&txs, 0), v::batch_siblings_0(),
            *vector::borrow(&starts, 1), *vector::borrow(&txs, 1), v::batch_siblings_1(),
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, second = @0xC0C)]
    fun every_right_challenger_gets_its_bond_back(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, second: &signer,
    ) {
        // Regression test: rejecting an assertion used to strand every other
        // challenger's bond in escrow.
        let metadata = setup(aptos, admin, proposer, challenger);
        let admin_addr = signer::address_of(admin);
        let id = post_batch(proposer, admin_addr, vector[v::bad_signature_tx()], vector[0], v::honest_post_root(), 6);
        assertions::open_challenge(challenger, admin_addr, id, BOND);
        // The second challenger needs funds of their own.
        account::create_account_for_test(signer::address_of(second));
        primary_fungible_store::transfer(challenger, metadata, signer::address_of(second), (BOND as u64));
        assertions::open_challenge(second, admin_addr, id, BOND);

        disputes::prove_uncompilable(challenger, admin_addr, id, 0, 0, v::bad_signature_tx(), vector::empty());
        assert!(balance(metadata, signer::address_of(second)) == (BOND as u64), 0);
        assert!(assertions::escrow_balance(admin_addr) == 0, 1);
    }
}
