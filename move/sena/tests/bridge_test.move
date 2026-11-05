// The bridge with a real fungible asset: deposits enter the chain's log and
// custody, and a withdrawal recorded on the L2 is paid once, to the recipient
// it names, only against a finalized root.
#[test_only]
module sena::bridge_test {
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
    use sena::bridge;
    use sena::deposits;
    use sena::vectors as v;

    const BASE_FEE: u128 = 25000000000;
    const TIPS: vector<u8> = x"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    const GENESIS_ROOT: vector<u8> = x"1111111111111111111111111111111111111111111111111111111111111111";
    const TX: vector<u8> = b"opaque transaction bytes";
    const TRACE: u64 = 10;
    const WINDOW: u64 = 604800;
    const BOND: u128 = 1000000;
    const L2_ASSET: u32 = 1;
    /// The recipient `vectors::withdrawal_record` names: 32 bytes of 0xA7.
    const RECIPIENT: address = @0xA7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7;
    const L2_ALICE: vector<u8> = x"0101010101010101010101010101010101010101010101010101010101010101";

    fun zero32(): vector<u8> {
        let v = vector::empty<u8>();
        while (vector::length(&v) < 32) { vector::push_back(&mut v, 0) };
        v
    }

    fun create_asset(admin: &signer): (MintRef, Object<Metadata>) {
        let constructor = object::create_named_object(admin, b"SENA_BRIDGE_USD");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor, option::none(), string::utf8(b"Test USD"), string::utf8(b"TUSD"), 6,
            string::utf8(b""), string::utf8(b""),
        );
        (fungible_asset::generate_mint_ref(&constructor), object::object_from_constructor_ref<Metadata>(&constructor))
    }

    fun fund(mint_ref: &MintRef, metadata: Object<Metadata>, who: address, amount: u64) {
        account::create_account_for_test(who);
        let store = primary_fungible_store::ensure_primary_store_exists(who, metadata);
        fungible_asset::mint_to(mint_ref, store, amount);
    }

    /// The chain and a bridge for it at the admin's address, registered.
    fun setup(aptos: &signer, admin: &signer): (MintRef, Object<Metadata>) {
        timestamp::set_time_has_started_for_testing(aptos);
        let admin_addr = signer::address_of(admin);
        account::create_account_for_test(admin_addr);
        let (mint_ref, metadata) = create_asset(admin);
        assertions::initialize(admin, GENESIS_ROOT, WINDOW, BOND, metadata, @0x7EA, 3600);
        assertions::set_proposers(admin, admin_addr, vector[admin_addr, @0xA11CE]);
        account::create_account_for_test(@0x7EA);
        bridge::initialize(admin, admin_addr, metadata, L2_ASSET);
        deposits::register_bridge(admin, admin_addr, L2_ASSET);
        (mint_ref, metadata)
    }

    fun genesis_id(): vector<u8> {
        assertions::assertion_id(zero32(), 0, zero32(), GENESIS_ROOT, zero32(), 0, 0)
    }

    fun commitment(): vector<u8> {
        batch::header_commitment(0, BASE_FEE, TIPS, 1, batch::root_of(&vector[TX], &vector[0]))
    }

    /// Posts an assertion whose post-state holds the withdrawal record.
    fun post_withdrawal_root(proposer: &signer, admin_addr: address): vector<u8> {
        assertions::post(
            proposer, admin_addr, genesis_id(), GENESIS_ROOT, v::withdrawal_root(), 0, BASE_FEE, TIPS,
            vector[TX], vector[0], TRACE, BOND,
        );
        assertions::assertion_id(genesis_id(), 0, GENESIS_ROOT, v::withdrawal_root(), commitment(), TRACE, BOND)
    }

    fun claim_with(caller: &signer, admin_addr: address, id: vector<u8>, nonce: u64, record: vector<u8>) {
        bridge::claim(
            caller, admin_addr, id, v::withdrawal_sender(), nonce, record,
            v::withdrawal_siblings(), v::withdrawal_terminal_key(), v::withdrawal_terminal_value_hash(),
        );
    }

    // --- Deposits ----------------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, user = @0xD00D)]
    fun a_deposit_enters_custody_and_the_log(aptos: &signer, admin: &signer, user: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(user), 1000);

        bridge::deposit_to(user, admin_addr, L2_ALICE, 600);
        assert!(bridge::custody_balance(admin_addr) == 600, 0);
        assert!(primary_fungible_store::balance(signer::address_of(user), metadata) == 400, 1);
        assert!(deposits::count(admin_addr) == 1, 2);
        let (found, to, asset, amount) = deposits::record(admin_addr, 1);
        assert!(found && to == L2_ALICE && asset == L2_ASSET && amount == 600, 3);

        // The plain entry point names the depositor's own address.
        bridge::deposit(user, admin_addr, 100);
        let (found, to, _, amount) = deposits::record(admin_addr, 2);
        assert!(found && amount == 100, 4);
        assert!(to == std::bcs::to_bytes(&signer::address_of(user)), 5);
    }

    #[test(aptos = @0x1, admin = @sena, user = @0xD00D)]
    #[expected_failure(abort_code = 48, location = sena::bridge)]
    fun a_recipient_must_be_an_address(aptos: &signer, admin: &signer, user: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        fund(&mint_ref, metadata, signer::address_of(user), 1000);
        bridge::deposit_to(user, signer::address_of(admin), x"0102", 10);
    }

    #[test(aptos = @0x1, admin = @sena, rogue = @0xBAD, user = @0xD00D)]
    #[expected_failure(abort_code = 60, location = sena::deposits)]
    fun an_unregistered_bridge_takes_no_deposits(aptos: &signer, admin: &signer, rogue: &signer, user: &signer) {
        // Anyone can create a bridge for the chain, over any token; it cannot
        // credit the L2 until the chain's owner registers it.
        let (_, _) = setup(aptos, admin);
        account::create_account_for_test(signer::address_of(rogue));
        let (rogue_mint, rogue_coin) = create_asset(rogue);
        bridge::initialize(rogue, signer::address_of(admin), rogue_coin, L2_ASSET);
        fund(&rogue_mint, rogue_coin, signer::address_of(user), 1000);
        bridge::deposit_to(user, signer::address_of(rogue), L2_ALICE, 1000);
    }

    // --- Withdrawals -------------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, user = @0xD00D, anyone = @0x5EE)]
    fun a_recorded_withdrawal_is_paid_once_to_its_recipient(
        aptos: &signer, admin: &signer, proposer: &signer, user: &signer, anyone: &signer
    ) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), 10000000);
        fund(&mint_ref, metadata, signer::address_of(user), 5000);
        bridge::deposit_to(user, admin_addr, L2_ALICE, 5000);

        let id = post_withdrawal_root(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, id);

        // Whoever submits, the record's recipient is paid the record's amount.
        claim_with(anyone, admin_addr, id, v::withdrawal_nonce(), v::withdrawal_record());
        assert!(primary_fungible_store::balance(RECIPIENT, metadata) == 1234, 0);
        assert!(bridge::custody_balance(admin_addr) == 5000 - 1234, 1);
        assert!(bridge::is_spent(admin_addr, v::withdrawal_slot()), 2);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, user = @0xD00D)]
    #[expected_failure(abort_code = 40, location = sena::bridge)]
    fun a_withdrawal_cannot_be_paid_twice(aptos: &signer, admin: &signer, proposer: &signer, user: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), 10000000);
        fund(&mint_ref, metadata, signer::address_of(user), 5000);
        bridge::deposit_to(user, admin_addr, L2_ALICE, 5000);
        let id = post_withdrawal_root(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, id);
        claim_with(user, admin_addr, id, v::withdrawal_nonce(), v::withdrawal_record());
        claim_with(user, admin_addr, id, v::withdrawal_nonce(), v::withdrawal_record());
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, user = @0xD00D)]
    #[expected_failure]
    fun a_pending_root_pays_nothing(aptos: &signer, admin: &signer, proposer: &signer, user: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), 10000000);
        fund(&mint_ref, metadata, signer::address_of(user), 5000);
        bridge::deposit_to(user, admin_addr, L2_ALICE, 5000);
        let id = post_withdrawal_root(proposer, admin_addr);
        claim_with(user, admin_addr, id, v::withdrawal_nonce(), v::withdrawal_record());
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, user = @0xD00D)]
    #[expected_failure]
    fun a_record_cannot_be_inflated(aptos: &signer, admin: &signer, proposer: &signer, user: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), 10000000);
        fund(&mint_ref, metadata, signer::address_of(user), 5000);
        bridge::deposit_to(user, admin_addr, L2_ALICE, 5000);
        let id = post_withdrawal_root(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, id);
        let forged = v::withdrawal_record();
        *vector::borrow_mut(&mut forged, 51) = 0xFF; // a larger amount
        claim_with(user, admin_addr, id, v::withdrawal_nonce(), forged);
    }

    #[test(aptos = @0x1, admin = @sena, proposer = @0xA11CE, user = @0xD00D)]
    #[expected_failure]
    fun another_transactions_slot_is_not_this_record(aptos: &signer, admin: &signer, proposer: &signer, user: &signer) {
        let (mint_ref, metadata) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        fund(&mint_ref, metadata, signer::address_of(proposer), 10000000);
        fund(&mint_ref, metadata, signer::address_of(user), 5000);
        bridge::deposit_to(user, admin_addr, L2_ALICE, 5000);
        let id = post_withdrawal_root(proposer, admin_addr);
        timestamp::fast_forward_seconds(WINDOW);
        assertions::finalize(admin_addr, id);
        claim_with(user, admin_addr, id, v::withdrawal_nonce() + 1, v::withdrawal_record());
    }

    // --- Forced inclusion --------------------------------------------------

    #[test(aptos = @0x1, admin = @sena, user = @0xD00D, stranger = @0xBAD)]
    #[expected_failure(abort_code = 49, location = sena::bridge)]
    fun only_the_bridge_marks_forced_entries_included(aptos: &signer, admin: &signer, user: &signer, stranger: &signer) {
        let (_, _) = setup(aptos, admin);
        bridge::force_include(user, signer::address_of(admin), b"forced tx");
        let id = bridge::forced_entry_id(signer::address_of(user), b"forced tx");
        bridge::mark_included(stranger, signer::address_of(admin), id);
    }

    #[test(aptos = @0x1, admin = @sena, user = @0xD00D, other = @0x0DD)]
    fun forced_entry_ids_cannot_be_squatted(aptos: &signer, admin: &signer, user: &signer, other: &signer) {
        let (_, _) = setup(aptos, admin);
        let admin_addr = signer::address_of(admin);
        // Someone else submitting the same bytes gets their own entry.
        bridge::force_include(other, admin_addr, b"forced tx");
        bridge::force_include(user, admin_addr, b"forced tx");
        let id = bridge::forced_entry_id(signer::address_of(user), b"forced tx");
        assert!(!bridge::is_overdue(admin_addr, id), 0);
        bridge::mark_included(admin, admin_addr, id);
    }
}
