// End-to-end lifecycle tests through the entry points, with real bonds.
//
// The module tests call Move functions directly, which is why they did not
// catch that `disputes::Registry` was never created by anything: a resource
// never moved to an account cannot be borrowed, and every dispute entry point
// borrows it. That was only visible when the contracts were driven the way a
// transaction drives them.
//
// These tests use a real fungible asset for bonds, so the economic claims are
// checked rather than assumed: a rejected assertion must actually cost its
// proposer, and a groundless challenge must actually cost its challenger.
#[test_only]
module sena::lifecycle_test {
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
    use sena::disputes;
    use sena::keyless;

    /// The batch header's base fee and tip recipient; posting does not check
    /// them (the trace does), so any values serve.
    const BASE_FEE: u128 = 25000000000;
    const TIPS: vector<u8> = x"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    const GENESIS_ROOT: vector<u8> = x"1111111111111111111111111111111111111111111111111111111111111111";
    const NEXT_ROOT: vector<u8> = x"2222222222222222222222222222222222222222222222222222222222222222";
    /// Placeholder batch data: these tests exercise the assertion lifecycle,
    /// not the transactions. A batch of one transaction, ten steps long.
    const TX: vector<u8> = b"opaque transaction bytes";
    const TRACE: u64 = 10;
    const MAX_BATCH_AGE: u64 = 3600;

    const WINDOW: u64 = 604800;
    const BOND: u128 = 1000000;
    const FUNDING: u64 = 10000000;
    const TREASURY: address = @0x7EA;

    fun zero32(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, 0); i = i + 1; };
        v
    }

    /// A test stablecoin with no supply cap, so bonds are not capped either.
    fun create_asset(admin: &signer): (MintRef, Object<Metadata>) {
        let constructor = object::create_named_object(admin, b"SENA_TEST_USD");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor,
            option::none(),
            string::utf8(b"Test USD"),
            string::utf8(b"TUSD"),
            6,
            string::utf8(b""),
            string::utf8(b""),
        );
        let mint_ref = fungible_asset::generate_mint_ref(&constructor);
        let metadata = object::object_from_constructor_ref<Metadata>(&constructor);
        (mint_ref, metadata)
    }

    fun fund(mint_ref: &MintRef, metadata: Object<Metadata>, who: address, amount: u64) {
        account::create_account_for_test(who);
        let store = primary_fungible_store::ensure_primary_store_exists(who, metadata);
        fungible_asset::mint_to(mint_ref, store, amount);
    }

    fun balance_of(metadata: Object<Metadata>, who: address): u64 {
        primary_fungible_store::balance(who, metadata)
    }

    /// The interior commitments a dissection of `lo..hi` requires.
    ///
    /// One fewer than the number of boundaries: the endpoints are already
    /// agreed, so only the divisions between them are published.
    fun dissection_for(lo: u64, hi: u64): vector<vector<u8>> {
        let bounds = disputes::boundaries(lo, hi);
        let out = vector::empty<vector<u8>>();
        let i = 1;
        while (i < vector::length(&bounds) - 1) {
            vector::push_back(&mut out, zero32());
            i = i + 1;
        };
        out
    }

    /// Stands the whole system up the way a deployment would.
    fun setup(aptos: &signer, admin: &signer): (MintRef, Object<Metadata>) {
        timestamp::set_time_has_started_for_testing(aptos);
        account::create_account_for_test(signer::address_of(admin));
        let (mint_ref, metadata) = create_asset(admin);
        assertions::initialize(admin, GENESIS_ROOT, WINDOW, BOND, metadata, TREASURY, MAX_BATCH_AGE);
        disputes::initialize(admin, signer::address_of(admin), keyless::setup_disabled());
        account::create_account_for_test(TREASURY);
        (mint_ref, metadata)
    }

    fun genesis_id(): vector<u8> {
        assertions::assertion_id(zero32(), 0, zero32(), GENESIS_ROOT, zero32(), 0, 0)
    }

    fun commitment(): vector<u8> {
        batch::header_commitment(0, BASE_FEE, TIPS, 1, batch::root_of(&vector[TX], &vector[0]))
    }

    fun child_id(): vector<u8> {
        assertions::assertion_id(genesis_id(), 0, GENESIS_ROOT, NEXT_ROOT, commitment(), TRACE, BOND)
    }

    fun post_one(proposer: &signer, admin_addr: address) {
        assertions::post(
            proposer, admin_addr, genesis_id(),
            GENESIS_ROOT, NEXT_ROOT, 0, BASE_FEE, TIPS, vector[TX], vector[0], TRACE, BOND,
        );
    }

    fun dispute_of(challenger: &signer): vector<u8> {
        disputes::dispute_id(child_id(), signer::address_of(challenger))
    }

    // --- Bonds --------------------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    fun posting_escrows_the_bond(aptos: &signer, admin: &signer, proposer: &signer) {
        // The point of the whole change: an assertion on the books must have
        // its bond actually at risk, not recorded as a number.
        let (mint_ref, metadata) = setup(aptos, admin);
        let p = signer::address_of(proposer);
        fund(&mint_ref, metadata, p, FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);

        assert!(balance_of(metadata, p) == FUNDING - (BOND as u64), 0);
        assert!(assertions::escrow_balance(admin_addr) == (BOND as u64), 1);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    fun finalizing_returns_the_bond(aptos: &signer, admin: &signer, proposer: &signer) {
        // The bond was at risk only while the assertion could be overturned.
        let (mint_ref, metadata) = setup(aptos, admin);
        let p = signer::address_of(proposer);
        fund(&mint_ref, metadata, p, FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, child_id());

        assert!(balance_of(metadata, p) == FUNDING, 0);
        assert!(assertions::escrow_balance(admin_addr) == 0, 1);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    fun a_rejected_assertion_costs_its_proposer(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, anyone: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let p = signer::address_of(proposer);
        let c = signer::address_of(challenger);
        fund(&mint_ref, metadata, p, FUNDING);
        fund(&mint_ref, metadata, c, FUNDING);
        account::create_account_for_test(signer::address_of(anyone));
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        disputes::open(challenger, admin_addr, child_id());

        // The defender stops responding and forfeits.
        timestamp::fast_forward_seconds(WINDOW);
        disputes::claim_timeout(anyone, admin_addr, dispute_of(challenger));

        assert!(assertions::status(admin_addr, child_id()) == assertions::status_rejected(), 0);

        // Proposer lost its whole bond.
        assert!(balance_of(metadata, p) == FUNDING - (BOND as u64), 1);

        // Challenger got its own bond back plus half the forfeited one; the
        // treasury got the rest, so self-challenging is not profitable.
        let reward = (BOND as u64) * 50 / 100;
        assert!(balance_of(metadata, c) == FUNDING + reward, 2);
        assert!(balance_of(metadata, TREASURY) == (BOND as u64) - reward, 3);
        assert!(assertions::escrow_balance(admin_addr) == 0, 4);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    fun a_groundless_challenge_costs_its_challenger(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, anyone: &signer,
    ) {
        // The converse, and the reason delaying an honest chain is not free
        // (REQ-FRAUD-021).
        let (mint_ref, metadata) = setup(aptos, admin);
        let p = signer::address_of(proposer);
        let c = signer::address_of(challenger);
        fund(&mint_ref, metadata, p, FUNDING);
        fund(&mint_ref, metadata, c, FUNDING);
        account::create_account_for_test(signer::address_of(anyone));
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        disputes::open(challenger, admin_addr, child_id());

        // The challenger opened and then went silent; the defender's dissection
        // is due first, so move past the challenger's own deadline instead.
        disputes::dissect(proposer, admin_addr, dispute_of(challenger), dissection_for(0, TRACE));
        timestamp::fast_forward_seconds(WINDOW);
        disputes::claim_timeout(anyone, admin_addr, dispute_of(challenger));

        // Assertion survives and returns to pending.
        assert!(assertions::status(admin_addr, child_id()) == assertions::status_pending(), 0);

        // Challenger lost its bond; the proposer received the winner's share.
        let reward = (BOND as u64) * 50 / 100;
        assert!(balance_of(metadata, c) == FUNDING - (BOND as u64), 1);
        assert!(balance_of(metadata, p) == FUNDING - (BOND as u64) + reward, 2);
        assert!(balance_of(metadata, TREASURY) == (BOND as u64) - reward, 3);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 63, location = sena::assertions)]
    fun a_proposer_cannot_challenge_itself(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        // Otherwise a proposer could shuffle its own bond between its own
        // pockets and burn a challenge window doing it.
        let (mint_ref, metadata) = setup(aptos, admin);
        let p = signer::address_of(proposer);
        fund(&mint_ref, metadata, p, FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(proposer, admin_addr, child_id(), BOND);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    #[expected_failure(abort_code = 62, location = sena::assertions)]
    fun one_party_cannot_open_two_challenges(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        fund(&mint_ref, metadata, signer::address_of(challenger), FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    #[expected_failure(abort_code = 35, location = sena::assertions)]
    fun an_underbonded_challenge_is_refused(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        fund(&mint_ref, metadata, signer::address_of(challenger), FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND - 1);
    }

    // --- Lifecycle ----------------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    fun an_assertion_can_be_posted_through_a_transaction(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        let admin_addr = signer::address_of(admin);
        post_one(proposer, admin_addr);
        assert!(assertions::status(admin_addr, child_id()) == assertions::status_pending(), 0);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 35, location = sena::assertions)]
    fun an_underbonded_assertion_is_refused(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        assertions::post(
            proposer, signer::address_of(admin), genesis_id(),
            GENESIS_ROOT, NEXT_ROOT, 0, BASE_FEE, TIPS, vector[TX], vector[0], TRACE, BOND - 1,
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 34, location = sena::assertions)]
    fun an_assertion_that_breaks_the_chain_is_refused(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        assertions::post(
            proposer, signer::address_of(admin), genesis_id(),
            NEXT_ROOT, NEXT_ROOT, 0, BASE_FEE, TIPS, vector[TX], vector[0], TRACE, BOND,
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun a_challenge_blocks_finalization(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        fund(&mint_ref, metadata, signer::address_of(challenger), FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        assert!(assertions::status(admin_addr, child_id()) == assertions::status_challenged(), 0);

        timestamp::fast_forward_seconds(WINDOW * 2);
        assert!(assertions::status(admin_addr, child_id()) == assertions::status_challenged(), 1);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    fun an_unchallenged_assertion_finalizes_after_its_window(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, child_id());
        assert!(assertions::status(admin_addr, child_id()) == assertions::status_finalized(), 0);
        assert!(assertions::finalized_root(admin_addr, child_id()) == NEXT_ROOT, 1);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 37, location = sena::assertions)]
    fun finalizing_early_is_refused(aptos: &signer, admin: &signer, proposer: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        let admin_addr = signer::address_of(admin);
        post_one(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW - 1);
        assertions::finalize(admin_addr, child_id());
    }

    // --- Dispute authorization ----------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, outsider = @0xDEAD)]
    #[expected_failure(abort_code = 56, location = sena::disputes)]
    fun a_non_party_cannot_move_in_a_dispute(
        aptos: &signer, admin: &signer, proposer: &signer,
        challenger: &signer, outsider: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        fund(&mint_ref, metadata, signer::address_of(challenger), FUNDING);
        account::create_account_for_test(signer::address_of(outsider));
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        disputes::open(challenger, admin_addr, child_id());
        disputes::dissect(outsider, admin_addr, dispute_of(challenger), dissection_for(0, TRACE));
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    #[expected_failure(abort_code = 51, location = sena::disputes)]
    fun the_challenger_cannot_move_on_the_defenders_turn(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        fund(&mint_ref, metadata, signer::address_of(challenger), FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        disputes::open(challenger, admin_addr, child_id());
        disputes::select(challenger, admin_addr, dispute_of(challenger), 0);
    }

    // Regression test: `open` used to take the defender, trace length and
    // commitments from the caller. Anyone could name a sock-puppet defender
    // who never answered, win by timeout, and reject a sound assertion. Now
    // there is nothing to name, and opening requires a bonded challenge.
    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, mallory = @0xBAD)]
    #[expected_failure(abort_code = 59, location = sena::disputes)]
    fun a_dispute_cannot_be_opened_without_a_challenge(
        aptos: &signer, admin: &signer, proposer: &signer, mallory: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        account::create_account_for_test(signer::address_of(mallory));
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        disputes::open(mallory, admin_addr, child_id());
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun the_defender_is_always_the_proposer(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        // The proposer, and only the proposer, can make the defender's move.
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        fund(&mint_ref, metadata, signer::address_of(challenger), FUNDING);
        let admin_addr = signer::address_of(admin);

        post_one(proposer, admin_addr);
        assertions::open_challenge(challenger, admin_addr, child_id(), BOND);
        disputes::open(challenger, admin_addr, child_id());
        disputes::dissect(proposer, admin_addr, dispute_of(challenger), dissection_for(0, TRACE));
    }

    // --- Timestamps and batch shape -------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 66, location = sena::assertions)]
    fun a_stale_batch_is_refused(aptos: &signer, admin: &signer, proposer: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        timestamp::fast_forward_seconds(MAX_BATCH_AGE + 1);
        post_one(proposer, signer::address_of(admin));
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 65, location = sena::assertions)]
    fun a_future_batch_is_refused(aptos: &signer, admin: &signer, proposer: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        assertions::post(
            proposer, signer::address_of(admin), genesis_id(),
            GENESIS_ROOT, NEXT_ROOT, 3600, BASE_FEE, TIPS, vector[TX], vector[0], TRACE, BOND,
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 67, location = sena::assertions)]
    fun start_positions_must_begin_at_zero(aptos: &signer, admin: &signer, proposer: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        assertions::post(
            proposer, signer::address_of(admin), genesis_id(),
            GENESIS_ROOT, NEXT_ROOT, 0, BASE_FEE, TIPS, vector[TX], vector[1], TRACE, BOND,
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 67, location = sena::assertions)]
    fun an_empty_batch_cannot_change_state(aptos: &signer, admin: &signer, proposer: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), FUNDING);
        assertions::post(
            proposer, signer::address_of(admin), genesis_id(),
            GENESIS_ROOT, NEXT_ROOT, 0, BASE_FEE, TIPS, vector::empty(), vector::empty(), 0, BOND,
        );
    }
}
