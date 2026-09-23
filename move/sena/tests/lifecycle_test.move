/// End-to-end lifecycle tests through the entry points.
///
/// The module tests call Move functions directly, which is why they did not
/// catch that `disputes::Registry` was never created by anything: a resource
/// that is never moved to an account cannot be borrowed, and every dispute
/// entry point borrows it. That bug was only visible when the contracts were
/// driven the way a transaction drives them.
///
/// These tests therefore go through `initialize`, `post`, `open_challenge` and
/// the dispute moves as an account would, and check the authorization that
/// separates "compiles" from "safe to deploy".
#[test_only]
module sena::lifecycle_test {
    use std::signer;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::timestamp;

    use sena::assertions;
    use sena::disputes;

    const GENESIS_ROOT: vector<u8> = x"1111111111111111111111111111111111111111111111111111111111111111";
    const NEXT_ROOT: vector<u8> = x"2222222222222222222222222222222222222222222222222222222222222222";
    const BATCH: vector<u8> = x"3333333333333333333333333333333333333333333333333333333333333333";

    const WINDOW: u64 = 604800; // 7 days
    const BOND: u128 = 1000000;

    fun zero32(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, 0); i = i + 1; };
        v
    }

    /// Stands the whole system up the way a deployment would.
    fun setup(aptos: &signer, admin: &signer) {
        timestamp::set_time_has_started_for_testing(aptos);
        account::create_account_for_test(signer::address_of(admin));
        assertions::initialize(admin, GENESIS_ROOT, WINDOW, BOND);
        disputes::initialize(admin, signer::address_of(admin));
    }

    fun genesis_id(admin_addr: address): vector<u8> {
        let _ = admin_addr;
        assertions::assertion_id(zero32(), 0, zero32(), GENESIS_ROOT, zero32(), 0, 0)
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    fun an_assertion_can_be_posted_through_a_transaction(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        let admin_addr = signer::address_of(admin);

        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );

        let id = assertions::assertion_id(
            genesis_id(admin_addr), 0, GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );
        assert!(assertions::status(admin_addr, id) == assertions::status_pending(), 0);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 35, location = sena::assertions)]
    fun an_underbonded_assertion_is_refused(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        let admin_addr = signer::address_of(admin);

        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND - 1,
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 34, location = sena::assertions)]
    fun an_assertion_that_breaks_the_chain_is_refused(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        let admin_addr = signer::address_of(admin);

        // Pre-state root that does not continue genesis.
        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            NEXT_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun a_challenge_blocks_finalization(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        account::create_account_for_test(signer::address_of(challenger));
        let admin_addr = signer::address_of(admin);

        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );
        let id = assertions::assertion_id(
            genesis_id(admin_addr), 0, GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );

        // Anyone may challenge (REQ-FRAUD-011).
        assertions::open_challenge(challenger, admin_addr, id);
        assert!(assertions::status(admin_addr, id) == assertions::status_challenged(), 0);

        // Even well past the window, a challenged assertion must not finalize.
        timestamp::fast_forward_seconds(WINDOW * 2);
        assert!(assertions::status(admin_addr, id) == assertions::status_challenged(), 1);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    fun an_unchallenged_assertion_finalizes_after_its_window(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        let admin_addr = signer::address_of(admin);

        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );
        let id = assertions::assertion_id(
            genesis_id(admin_addr), 0, GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );

        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, id);
        assert!(assertions::status(admin_addr, id) == assertions::status_finalized(), 0);
        assert!(assertions::finalized_root(admin_addr, id) == NEXT_ROOT, 1);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 37, location = sena::assertions)]
    fun finalizing_early_is_refused(
        aptos: &signer, admin: &signer, proposer: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        let admin_addr = signer::address_of(admin);

        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );
        let id = assertions::assertion_id(
            genesis_id(admin_addr), 0, GENESIS_ROOT, NEXT_ROOT, BATCH, 10, BOND,
        );

        timestamp::fast_forward_seconds(WINDOW - 1);
        assertions::finalize(admin_addr, id);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, outsider = @0xDEAD)]
    #[expected_failure(abort_code = 56, location = sena::disputes)]
    fun a_non_party_cannot_move_in_a_dispute(
        aptos: &signer,
        admin: &signer,
        proposer: &signer,
        challenger: &signer,
        outsider: &signer,
    ) {
        // The authorization that matters: before this, the party was a
        // parameter, so any account could move as either side and the turn and
        // clock checks were decorative.
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        account::create_account_for_test(signer::address_of(challenger));
        account::create_account_for_test(signer::address_of(outsider));
        let admin_addr = signer::address_of(admin);

        disputes::open(
            challenger, admin_addr, BATCH, BATCH,
            signer::address_of(proposer), 64, GENESIS_ROOT, NEXT_ROOT, WINDOW,
        );

        disputes::dissect(outsider, admin_addr, BATCH, vector::empty<vector<u8>>());
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    #[expected_failure(abort_code = 51, location = sena::disputes)]
    fun the_challenger_cannot_move_on_the_defenders_turn(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        account::create_account_for_test(signer::address_of(challenger));
        let admin_addr = signer::address_of(admin);

        disputes::open(
            challenger, admin_addr, BATCH, BATCH,
            signer::address_of(proposer), 64, GENESIS_ROOT, NEXT_ROOT, WINDOW,
        );

        // Opening leaves it the defender's turn.
        disputes::select(challenger, admin_addr, BATCH, 0);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    fun a_timeout_resolves_the_dispute_and_the_assertion(
        aptos: &signer,
        admin: &signer,
        proposer: &signer,
        challenger: &signer,
        anyone: &signer,
    ) {
        // The link between adjudication and status. Recording a winner without
        // applying it would let a fraudulent assertion lose its dispute and
        // still finalize.
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(proposer));
        account::create_account_for_test(signer::address_of(challenger));
        account::create_account_for_test(signer::address_of(anyone));
        let admin_addr = signer::address_of(admin);

        assertions::post(
            proposer, admin_addr, genesis_id(admin_addr),
            GENESIS_ROOT, NEXT_ROOT, BATCH, 64, BOND,
        );
        let id = assertions::assertion_id(
            genesis_id(admin_addr), 0, GENESIS_ROOT, NEXT_ROOT, BATCH, 64, BOND,
        );
        assertions::open_challenge(challenger, admin_addr, id);

        disputes::open(
            challenger, admin_addr, id, id,
            signer::address_of(proposer), 64, GENESIS_ROOT, NEXT_ROOT, WINDOW,
        );

        // The defender stops responding. Anyone may claim the timeout -- a party
        // that has gone silent will not report itself.
        timestamp::fast_forward_seconds(WINDOW);
        disputes::claim_timeout(anyone, admin_addr, id);

        // The challenger won, so the assertion is rejected, not merely noted.
        assert!(assertions::status(admin_addr, id) == assertions::status_rejected(), 0);
    }
}
