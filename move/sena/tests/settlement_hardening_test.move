// Regression tests for the settlement-layer fixes from the 2026-11 security
// audit: who may adjudicate, who may post, which branch finalizes, who owns
// escrow and custody, the one-step deadline, and challenges left without a game.
#[test_only]
module sena::settlement_hardening_test {
    use std::option;
    use std::signer;
    use std::string;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::fungible_asset::{Self, MintRef, Metadata, FungibleStore};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;

    use sena::assertions;
    use sena::batch;
    use sena::bridge;
    use sena::disputes;
    use sena::keyless;

    const BASE_FEE: u128 = 25000000000;
    const TIPS: vector<u8> = x"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    const GENESIS_ROOT: vector<u8> = x"1111111111111111111111111111111111111111111111111111111111111111";
    const NEXT_ROOT: vector<u8> = x"2222222222222222222222222222222222222222222222222222222222222222";
    const TX: vector<u8> = b"opaque transaction bytes";
    const TRACE: u64 = 10;
    // The window floor: the clock budget (window / 4) then equals MOVE_TIMEOUT,
    // so one late dissection drains the defender's clock to zero.
    const WINDOW: u64 = 86400;
    const MOVE_TIMEOUT: u64 = 21600;
    const BOND: u128 = 1000000;
    const FUNDING: u64 = 10000000;
    const TREASURY: address = @0x7EA;

    fun zero32(): vector<u8> {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut v, 0); i = i + 1; };
        v
    }

    fun create_asset(admin: &signer): (MintRef, Object<Metadata>) {
        let constructor = object::create_named_object(admin, b"SENA_HARDENING_USD");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor, option::none(), string::utf8(b"Test USD"), string::utf8(b"TUSD"), 6,
            string::utf8(b""), string::utf8(b""),
        );
        (fungible_asset::generate_mint_ref(&constructor), object::object_from_constructor_ref<Metadata>(&constructor))
    }

    fun fund(mint_ref: &MintRef, metadata: Object<Metadata>, who: address) {
        account::create_account_for_test(who);
        let store = primary_fungible_store::ensure_primary_store_exists(who, metadata);
        fungible_asset::mint_to(mint_ref, store, FUNDING);
    }

    fun setup(aptos: &signer, admin: &signer): (MintRef, Object<Metadata>) {
        timestamp::set_time_has_started_for_testing(aptos);
        let a = signer::address_of(admin);
        account::create_account_for_test(a);
        let (mint_ref, metadata) = create_asset(admin);
        assertions::initialize(admin, GENESIS_ROOT, WINDOW, BOND, metadata, TREASURY, 3600);
        assertions::set_proposers(admin, a, vector[a, @0xA11CE]);
        disputes::initialize(admin, a, keyless::setup_disabled(), 0);
        account::create_account_for_test(TREASURY);
        (mint_ref, metadata)
    }

    fun genesis_id(): vector<u8> {
        assertions::assertion_id(zero32(), 0, zero32(), GENESIS_ROOT, zero32(), 0, 0)
    }

    fun commitment(): vector<u8> {
        batch::header_commitment(0, BASE_FEE, TIPS, 1, batch::root_of(&vector[TX], &vector[0]))
    }

    fun child(bond: u128): vector<u8> {
        assertions::assertion_id(genesis_id(), 0, GENESIS_ROOT, NEXT_ROOT, commitment(), TRACE, bond)
    }

    fun post(proposer: &signer, chain: address, bond: u128) {
        assertions::post(proposer, chain, genesis_id(), GENESIS_ROOT, NEXT_ROOT, 0, BASE_FEE, TIPS,
            vector[TX], vector[0], TRACE, bond);
    }

    fun eight_zeros(): vector<vector<u8>> {
        let bounds = disputes::boundaries(0, TRACE);
        let out = vector::empty<vector<u8>>();
        let i = 1;
        while (i < vector::length(&bounds) - 1) { vector::push_back(&mut out, zero32()); i = i + 1; };
        out
    }

    // --- Who may adjudicate --------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, mallory = @0xBAD)]
    #[expected_failure(abort_code = 66, location = sena::disputes)]
    fun a_registry_for_someone_elses_chain_is_refused(aptos: &signer, admin: &signer, mallory: &signer) {
        // The attack: a registry with the wrong chain id, bound to the real
        // chain, makes every honest transaction "uncompilable".
        setup(aptos, admin);
        account::create_account_for_test(signer::address_of(mallory));
        disputes::initialize(mallory, signer::address_of(admin), keyless::setup_disabled(), 999);
    }

    // --- Who may post, and which branch finalizes ----------------------------

    #[test(aptos = @0x1, admin = @sena, mallory = @0xBAD)]
    #[expected_failure(abort_code = 68, location = sena::assertions)]
    fun an_unlisted_account_cannot_post(aptos: &signer, admin: &signer, mallory: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(mallory));
        post(mallory, signer::address_of(admin), BOND);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE)]
    #[expected_failure(abort_code = 69, location = sena::assertions)]
    fun a_sibling_cannot_finalize_once_one_branch_has(aptos: &signer, admin: &signer, proposer: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let chain = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        post(proposer, chain, BOND);
        post(proposer, chain, BOND + 1); // same parent, different id
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(chain, child(BOND));
        assertions::finalize(chain, child(BOND + 1));
    }

    // --- Nobody owns escrow or custody ---------------------------------------

    #[test(aptos = @0x1, admin = @sena)]
    fun escrow_and_custody_belong_to_no_one(aptos: &signer, admin: &signer) {
        let (_mint_ref, metadata) = setup(aptos, admin);
        let a = signer::address_of(admin);
        bridge::initialize(admin, a, metadata, 7);
        let escrow = object::address_to_object<FungibleStore>(assertions::escrow_store(a));
        let custody = object::address_to_object<FungibleStore>(bridge::custody_store(a));
        assert!(object::owner(escrow) == assertions::burn_address(), 0);
        assert!(object::owner(custody) == assertions::burn_address(), 1);
        assert!(!object::owns(escrow, a), 2);
        assert!(!object::owns(custody, a), 3);
    }

    #[test(aptos = @0x1, admin = @sena)]
    fun a_bridge_for_an_untransferable_asset_belongs_to_no_one(aptos: &signer, admin: &signer) {
        // Circle's USDC marks its stores untransferable: custody must still
        // end up owned by no one, and initialising must not abort.
        setup(aptos, admin);
        let a = signer::address_of(admin);
        let constructor = object::create_named_object(admin, b"SENA_UNTRANSFERABLE");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor, option::none(), string::utf8(b"Locked"), string::utf8(b"LCK"), 6,
            string::utf8(b""), string::utf8(b""),
        );
        fungible_asset::set_untransferable(&constructor);
        let metadata = object::object_from_constructor_ref<Metadata>(&constructor);
        bridge::initialize(admin, a, metadata, 8);
        let custody = object::address_to_object<FungibleStore>(bridge::custody_store(a));
        assert!(object::owner(custody) == assertions::burn_address(), 0);
        assert!(!object::owns(custody, a), 1);
    }

    #[test(aptos = @0x1, admin = @sena)]
    #[expected_failure]
    fun the_admin_cannot_withdraw_from_custody(aptos: &signer, admin: &signer) {
        let (_mint_ref, metadata) = setup(aptos, admin);
        let a = signer::address_of(admin);
        bridge::initialize(admin, a, metadata, 7);
        let custody = object::address_to_object<FungibleStore>(bridge::custody_store(a));
        let to = primary_fungible_store::ensure_primary_store_exists(a, metadata);
        fungible_asset::transfer(admin, custody, to, 0);
    }

    // --- The one-step deadline -----------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B)]
    fun the_one_step_deadline_comes_from_the_challengers_clock(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let chain = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        fund(&mint_ref, metadata, signer::address_of(challenger));
        post(proposer, chain, BOND);
        assertions::open_challenge(challenger, chain, child(BOND), BOND);
        disputes::open(challenger, chain, child(BOND));
        let id = disputes::dispute_id(child(BOND), signer::address_of(challenger));

        // The defender answers at the last possible second, draining its clock.
        timestamp::fast_forward_seconds(MOVE_TIMEOUT);
        disputes::dissect(proposer, chain, id, eight_zeros());
        // The challenger narrows to one step at once.
        disputes::select(challenger, chain, id, 0);

        let (_, stage, turn, _, _, _, _, deadline) = disputes::dispute_state(chain, id);
        assert!(stage == 1 && turn == 1, 0);
        // Before the fix this was `now`: zero seconds to submit the proof.
        assert!(deadline == timestamp::now_seconds() + MOVE_TIMEOUT, 1);
    }

    // --- Challenges left without a game --------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    fun a_challenge_never_played_is_dismissed(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, anyone: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let chain = signer::address_of(admin);
        let c = signer::address_of(challenger);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        fund(&mint_ref, metadata, c);
        account::create_account_for_test(signer::address_of(anyone));
        post(proposer, chain, BOND);
        assertions::open_challenge(challenger, chain, child(BOND), BOND);

        timestamp::fast_forward_seconds(MOVE_TIMEOUT + 1);
        disputes::dismiss_stale_challenge(anyone, chain, child(BOND), c);

        assert!(assertions::status(chain, child(BOND)) == assertions::status_pending(), 0);
        assert!(primary_fungible_store::balance(c, metadata) == FUNDING - (BOND as u64), 1);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(chain, child(BOND));
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    #[expected_failure(abort_code = 67, location = sena::disputes)]
    fun a_fresh_challenge_is_not_dismissed(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, anyone: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let chain = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        fund(&mint_ref, metadata, signer::address_of(challenger));
        account::create_account_for_test(signer::address_of(anyone));
        post(proposer, chain, BOND);
        assertions::open_challenge(challenger, chain, child(BOND), BOND);
        timestamp::fast_forward_seconds(MOVE_TIMEOUT - 1);
        disputes::dismiss_stale_challenge(anyone, chain, child(BOND), signer::address_of(challenger));
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    #[expected_failure(abort_code = 67, location = sena::disputes)]
    fun a_challenge_with_a_live_game_is_not_dismissed(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, anyone: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let chain = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        fund(&mint_ref, metadata, signer::address_of(challenger));
        account::create_account_for_test(signer::address_of(anyone));
        post(proposer, chain, BOND);
        assertions::open_challenge(challenger, chain, child(BOND), BOND);
        disputes::open(challenger, chain, child(BOND));
        timestamp::fast_forward_seconds(MOVE_TIMEOUT + 1);
        disputes::dismiss_stale_challenge(anyone, chain, child(BOND), signer::address_of(challenger));
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, challenger = @0xB0B, anyone = @0xDEAD)]
    fun a_challenger_who_lost_can_play_again(
        aptos: &signer, admin: &signer, proposer: &signer, challenger: &signer, anyone: &signer,
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let chain = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer));
        fund(&mint_ref, metadata, signer::address_of(challenger));
        account::create_account_for_test(signer::address_of(anyone));
        post(proposer, chain, BOND);
        let id = disputes::dispute_id(child(BOND), signer::address_of(challenger));

        assertions::open_challenge(challenger, chain, child(BOND), BOND);
        disputes::open(challenger, chain, child(BOND));
        disputes::dissect(proposer, chain, id, eight_zeros());
        timestamp::fast_forward_seconds(MOVE_TIMEOUT + 1);
        disputes::claim_timeout(anyone, chain, id); // the challenger went silent and lost

        // Before the fix the finished game blocked a new one forever, and the
        // second challenge froze the assertion.
        assertions::open_challenge(challenger, chain, child(BOND), BOND);
        disputes::open(challenger, chain, child(BOND));
        let (exists, stage, _, _, _, _, _, _) = disputes::dispute_state(chain, id);
        assert!(exists && stage == 0, 0);
    }
}
