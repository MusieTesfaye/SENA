/// The L1 bridge: custody, deposits, withdrawals, and forced inclusion.
///
/// The rule this module exists to enforce is one line long: assets leave custody
/// only against a state root whose assertion has **finalized** (REQ-FRAUD-005).
/// That is what makes the challenge window mean something to a user's funds
/// rather than being a number in a document.
///
/// # Asset model
///
/// One fungible asset per bridge, fixed at initialization. Beta scope calls for
/// exactly one test asset (BETA_BUILD_PLAN.md §3.3); supporting several would
/// add accounting surface without adding proof.
///
/// Transfers go through `dispatchable_fungible_asset` rather than
/// `fungible_asset`. Circle's USDC is a *dispatchable* asset: its blocklist and
/// pause hooks run on every move, and calling the plain entry point would either
/// abort or bypass controls the issuer requires.
///
/// # Withdrawals
///
/// A withdrawal is an L2 transaction first: it burns the amount on the L2 and
/// records who to pay on L1. `claim` pays that record, once, against a
/// finalized root. The L2 balance is therefore reduced before custody pays,
/// and custody never pays against a balance that is still spendable on L2.
module sena::bridge {
    use std::signer;
    use std::vector;
    use aptos_std::from_bcs;
    use aptos_std::table::{Self, Table};
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, FungibleStore, Metadata};
    use aptos_framework::object::{Self, Object, ExtendRef};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;

    use sena::assertions;
    use sena::codec;
    use sena::deposits;
    use sena::osp;
    use sena::trie;

    /// This withdrawal has already been paid.
    const E_ALREADY_WITHDRAWN: u64 = 40;
    /// The forced-inclusion entry does not exist.
    const E_NO_SUCH_ENTRY: u64 = 41;
    /// The bridge has already been initialized.
    const E_ALREADY_INITIALIZED: u64 = 43;
    /// The proven balance is zero, so there is nothing to withdraw.
    const E_NOTHING_TO_WITHDRAW: u64 = 44;
    /// The withdrawal record is for another asset, or malformed.
    const E_WRONG_ASSET: u64 = 45;
    /// The deposit amount is zero.
    const E_ZERO_AMOUNT: u64 = 46;
    /// Custody holds less than the withdrawal requires.
    const E_CUSTODY_SHORTFALL: u64 = 47;
    /// An L2 recipient is a 32-byte address.
    const E_BAD_RECIPIENT: u64 = 48;
    /// Only the bridge's account may do this.
    const E_NOT_OPERATOR: u64 = 49;
    /// This submitter already submitted this payload.
    const E_ALREADY_SUBMITTED: u64 = 50;

    /// Domain tag for forced-entry ids.
    const DOMAIN_FORCED: vector<u8> = b"SENA:v1:forced-entry";

    /// How long the sequencer has to include a forced transaction before anyone
    /// may include it and the sequencer's bond becomes slashable (REQ-FRAUD-029).
    const FORCED_INCLUSION_TIMEOUT: u64 = 86400;

    /// Domain tag for the L2 account state key, mirroring `sena_stf::keys`.
    const DOMAIN_ACCOUNT_KEY: vector<u8> = b"SENA:v1:state:account";

    struct Bridge has key {
        /// Assertion chain this bridge trusts for finality.
        chain: address,
        /// The asset this bridge custodies.
        metadata: Object<Metadata>,
        /// The L2 asset id the L2 records this asset under.
        l2_asset_id: u32,
        /// Where deposited assets are held.
        custody: Object<FungibleStore>,
        /// Lets the module sign for the custody object when paying out.
        custody_extend: ExtendRef,
        /// Withdrawals already paid, keyed by their derived identifier.
        spent: Table<vector<u8>, bool>,
        /// Monotonic counter making each deposit individually identifiable.
        deposit_count: u64,
        /// Transactions submitted directly to L1 (REQ-FRAUD-028).
        forced: Table<vector<u8>, ForcedEntry>,
    }

    struct ForcedEntry has store, copy, drop {
        submitter: address,
        payload: vector<u8>,
        submitted_at: u64,
        included: bool,
    }

    #[event]
    struct Deposited has drop, store {
        /// Who deposited on L1.
        depositor: address,
        /// The L2 account credited.
        recipient: vector<u8>,
        amount: u64,
        /// The chain-wide id in `sena::deposits`; the L2 credits each exactly
        /// once, in order.
        deposit_id: u64,
    }

    #[event]
    struct ForcedSubmitted has drop, store {
        submitter: address,
        entry_id: vector<u8>,
    }

    #[event]
    struct Withdrawn has drop, store {
        /// Who was paid: the recipient the L2 record names.
        recipient: address,
        amount: u64,
        assertion: vector<u8>,
        withdrawal_id: vector<u8>,
    }

    /// Creates the bridge and its custody store.
    public entry fun initialize(
        admin: &signer,
        chain: address,
        metadata: Object<Metadata>,
        l2_asset_id: u32,
    ) {
        let admin_addr = signer::address_of(admin);
        assert!(!exists<Bridge>(admin_addr), E_ALREADY_INITIALIZED);

        // Custody lives in its own object rather than the admin's primary store,
        // so the admin's own balance of the asset can never be confused with, or
        // spent as, user deposits.
        // Owned by no one: the owner of a store can withdraw from it through
        // the framework's transfer functions, bypassing `claim` entirely.
        // Payouts still work through `custody_extend`. Created that way rather
        // than transferred, since some assets' stores cannot be transferred.
        let constructor = object::create_object(assertions::burn_address());
        let custody_extend = object::generate_extend_ref(&constructor);
        let custody = fungible_asset::create_store(&constructor, metadata);

        move_to(admin, Bridge {
            chain,
            metadata,
            l2_asset_id,
            custody,
            custody_extend,
            spent: table::new<vector<u8>, bool>(),
            deposit_count: 0,
            forced: table::new<vector<u8>, ForcedEntry>(),
        });
    }

    /// Deposits the bridged asset to the depositor's own address on the L2.
    ///
    /// The depositor's Aptos address is used as the L2 address, which is what
    /// `withdraw` pays. An L2 account whose address is an Ed25519 key or a
    /// keyless identity is not an Aptos address; use `deposit_to` for those.
    public entry fun deposit(
        depositor: &signer,
        bridge_addr: address,
        amount: u64,
    ) acquires Bridge {
        deposit_to(depositor, bridge_addr, bcs_address_bytes(signer::address_of(depositor)), amount)
    }

    /// Deposits the bridged asset, to be credited to `recipient` on the L2.
    ///
    /// The deposit is appended to the chain's log in `sena::deposits`, which
    /// is what the L2 credits from and what L1 checks a credit against in a
    /// dispute. Each deposit gets the next chain-wide id; the L2 credits them
    /// once each, in order. Aborts unless the chain's owner registered this
    /// bridge, so a bridge nobody vouched for cannot mint L2 balances.
    public entry fun deposit_to(
        depositor: &signer,
        bridge_addr: address,
        recipient: vector<u8>,
        amount: u64,
    ) acquires Bridge {
        assert!(amount > 0, E_ZERO_AMOUNT);
        assert!(vector::length(&recipient) == 32, E_BAD_RECIPIENT);
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        let from = primary_fungible_store::ensure_primary_store_exists(
            signer::address_of(depositor), bridge.metadata
        );

        // Dispatchable withdraw so the issuer's hooks run -- a blocked or frozen
        // account must fail here rather than silently succeed.
        let assets = dispatchable_fungible_asset::withdraw(depositor, from, amount);
        dispatchable_fungible_asset::deposit(bridge.custody, assets);

        bridge.deposit_count = bridge.deposit_count + 1;
        let deposit_id = deposits::append(
            bridge.chain, bridge_addr, recipient, bridge.l2_asset_id, amount
        );
        event::emit(Deposited {
            depositor: signer::address_of(depositor),
            recipient,
            amount,
            deposit_id,
        });
    }

    /// The trie key an L2 account's state is stored under.
    ///
    /// Mirrors `sena_stf::keys::account`. A divergence would make every
    /// withdrawal prove the wrong slot.
    public fun account_slot(l2_address: address): vector<u8> {
        let buf = codec::begin(DOMAIN_ACCOUNT_KEY);
        codec::put_field(&mut buf, bcs_address_bytes(l2_address));
        codec::commit(buf)
    }

    fun bcs_address_bytes(addr: address): vector<u8> {
        std::bcs::to_bytes(&addr)
    }

    /// Pays a withdrawal recorded on the L2, against a finalized assertion.
    ///
    /// A withdrawal starts on the L2: a `Withdraw` transaction burns the
    /// amount there and writes a record -- recipient, asset, amount -- into a
    /// slot unique to its sender and nonce (`keys::withdrawal`). Once a
    /// finalized assertion's state holds that record, anyone may submit this
    /// call, and the record's recipient is paid. Checked, each load-bearing:
    ///
    /// 1. the assertion has finalized -- `finalized_root` aborts otherwise;
    /// 2. the proof shows the slot derived from `(l2_sender, l2_nonce)` holds
    ///    `record` under that root;
    /// 3. the record is for this bridge's asset;
    /// 4. this record has not been paid. Spent-ness is keyed by the slot, not
    ///    the assertion: the record stays in every later root, and keying by
    ///    assertion would pay it once per assertion.
    ///
    /// The amount and recipient come from the proven record, never from the
    /// caller, so who submits the claim does not matter.
    public entry fun claim(
        _caller: &signer,
        bridge_addr: address,
        assertion_id: vector<u8>,
        l2_sender: vector<u8>,
        l2_nonce: u64,
        record: vector<u8>,
        siblings: vector<vector<u8>>,
        terminal_key: vector<u8>,
        terminal_value_hash: vector<u8>,
    ) acquires Bridge {
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        let root = assertions::finalized_root(bridge.chain, assertion_id);

        let slot = osp::withdrawal_key(l2_sender, l2_nonce);
        let proof = trie::new_proof(siblings, trie::leaf_terminal(terminal_key, terminal_value_hash));
        trie::verify_inclusion(&proof, root, slot, trie::hash_value(record));
        assert!(!table::contains(&bridge.spent, slot), E_ALREADY_WITHDRAWN);

        let (ok, to, asset, amount) = osp::decode_withdrawal(record);
        assert!(ok && asset == bridge.l2_asset_id, E_WRONG_ASSET);
        assert!(amount > 0, E_NOTHING_TO_WITHDRAW);
        // L2 amounts are u128; a bridged amount must fit the asset's u64.
        assert!(amount <= 18446744073709551615, E_CUSTODY_SHORTFALL);
        let amount = (amount as u64);
        assert!(fungible_asset::balance(bridge.custody) >= amount, E_CUSTODY_SHORTFALL);

        table::add(&mut bridge.spent, slot, true);

        let recipient = from_bcs::to_address(to);
        let custody_signer = object::generate_signer_for_extending(&bridge.custody_extend);
        let assets = dispatchable_fungible_asset::withdraw(&custody_signer, bridge.custody, amount);
        let dest = primary_fungible_store::ensure_primary_store_exists(recipient, bridge.metadata);
        dispatchable_fungible_asset::deposit(dest, assets);

        event::emit(Withdrawn {
            recipient,
            amount,
            assertion: assertion_id,
            withdrawal_id: slot,
        });
    }

    /// Submits a transaction directly to L1 (REQ-FRAUD-028).
    ///
    /// A fraud proof system a sequencer can neutralise by refusing service is
    /// not a security guarantee, so users need a path that does not depend on
    /// the sequencer's cooperation.
    ///
    /// The entry's id is derived from the submitter and the payload, never
    /// chosen by the caller: a caller-chosen id could be taken first by
    /// someone else, blocking the user's forced transaction.
    public entry fun force_include(
        submitter: &signer,
        bridge_addr: address,
        payload: vector<u8>,
    ) acquires Bridge {
        let entry_id = forced_entry_id(signer::address_of(submitter), payload);
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        assert!(!table::contains(&bridge.forced, entry_id), E_ALREADY_SUBMITTED);
        event::emit(ForcedSubmitted { submitter: signer::address_of(submitter), entry_id });
        table::add(&mut bridge.forced, entry_id, ForcedEntry {
            submitter: signer::address_of(submitter),
            payload,
            submitted_at: timestamp::now_seconds(),
            included: false,
        });
    }

    /// The id a forced entry is recorded under.
    public fun forced_entry_id(submitter: address, payload: vector<u8>): vector<u8> {
        let buf = codec::begin(DOMAIN_FORCED);
        codec::put_field(&mut buf, bcs_address_bytes(submitter));
        codec::put_field(&mut buf, payload);
        codec::commit(buf)
    }

    /// Marks a forced entry as included. Only the bridge's own account may:
    /// anyone else marking entries included would switch forced inclusion off.
    public entry fun mark_included(operator: &signer, bridge_addr: address, entry_id: vector<u8>) acquires Bridge {
        assert!(signer::address_of(operator) == bridge_addr, E_NOT_OPERATOR);
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        assert!(table::contains(&bridge.forced, entry_id), E_NO_SUCH_ENTRY);
        table::borrow_mut(&mut bridge.forced, entry_id).included = true;
    }

    #[view]
    /// Returns whether a forced entry has passed its inclusion deadline.
    public fun is_overdue(bridge_addr: address, entry_id: vector<u8>): bool acquires Bridge {
        let bridge = borrow_global<Bridge>(bridge_addr);
        assert!(table::contains(&bridge.forced, entry_id), E_NO_SUCH_ENTRY);
        let entry = table::borrow(&bridge.forced, entry_id);
        !entry.included
            && timestamp::now_seconds() >= entry.submitted_at + FORCED_INCLUSION_TIMEOUT
    }

    #[view]
    public fun is_spent(bridge_addr: address, id: vector<u8>): bool acquires Bridge {
        table::contains(&borrow_global<Bridge>(bridge_addr).spent, id)
    }

    #[view]
    /// Total assets held in custody. Must equal the sum of L2 liabilities.
    public fun custody_store(bridge_addr: address): address acquires Bridge {
        object::object_address(&borrow_global<Bridge>(bridge_addr).custody)
    }

    #[view]
    public fun custody_balance(bridge_addr: address): u64 acquires Bridge {
        fungible_asset::balance(borrow_global<Bridge>(bridge_addr).custody)
    }

    #[view]
    public fun deposit_count(bridge_addr: address): u64 acquires Bridge {
        borrow_global<Bridge>(bridge_addr).deposit_count
    }

    public fun forced_inclusion_timeout(): u64 { FORCED_INCLUSION_TIMEOUT }

    #[test]
    fun timeout_is_a_day() {
        assert!(FORCED_INCLUSION_TIMEOUT == 86400, 0);
    }

}
