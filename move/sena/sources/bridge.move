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
/// # Who may withdraw
///
/// The claimant's Aptos address **is** the L2 address. A withdrawal proves the
/// balance at `keys::account(claimant)` and pays that same account. Letting a
/// claimant name an arbitrary L2 address would let anyone withdraw against any
/// balance they could produce a proof for, which is every balance, since proofs
/// are public.
module sena::bridge {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, FungibleStore, Metadata};
    use aptos_framework::object::{Self, Object, ExtendRef};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;

    use sena::assertions;
    use sena::codec;
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
    /// The account slot does not belong to the claimant.
    const E_SLOT_NOT_CLAIMANTS: u64 = 45;
    /// The deposit amount is zero.
    const E_ZERO_AMOUNT: u64 = 46;
    /// Custody holds less than the withdrawal requires.
    const E_CUSTODY_SHORTFALL: u64 = 47;

    /// How long the sequencer has to include a forced transaction before anyone
    /// may include it and the sequencer's bond becomes slashable (REQ-FRAUD-029).
    const FORCED_INCLUSION_TIMEOUT: u64 = 86400;

    /// Domain tag for the withdrawal identifier.
    const DOMAIN_WITHDRAWAL: vector<u8> = b"SENA:v1:withdrawal";
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
        /// Who deposited, and whose L2 account is credited.
        depositor: address,
        amount: u64,
        /// Sequence number; the L2 credits each exactly once.
        deposit_id: u64,
    }

    #[event]
    struct Withdrawn has drop, store {
        claimant: address,
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
        let constructor = object::create_object(admin_addr);
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

    /// Deposits the bridged asset, to be credited on the L2.
    ///
    /// Crediting happens on the L2 when the sequencer observes the emitted
    /// event. The `deposit_id` is what makes that exactly-once: a sequencer
    /// replaying events must not credit the same deposit twice.
    public entry fun deposit(
        depositor: &signer,
        bridge_addr: address,
        amount: u64,
    ) acquires Bridge {
        assert!(amount > 0, E_ZERO_AMOUNT);
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        let from = primary_fungible_store::ensure_primary_store_exists(
            signer::address_of(depositor), bridge.metadata
        );

        // Dispatchable withdraw so the issuer's hooks run -- a blocked or frozen
        // account must fail here rather than silently succeed.
        let assets = dispatchable_fungible_asset::withdraw(depositor, from, amount);
        dispatchable_fungible_asset::deposit(bridge.custody, assets);

        bridge.deposit_count = bridge.deposit_count + 1;
        event::emit(Deposited {
            depositor: signer::address_of(depositor),
            amount,
            deposit_id: bridge.deposit_count,
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

    /// Derives the identifier a withdrawal is recorded under.
    ///
    /// Computed from what the withdrawal *is* -- the assertion, the account and
    /// the asset -- rather than supplied by the caller. A caller-chosen
    /// identifier would let the same proof be presented repeatedly under
    /// different ids, which is a drained bridge rather than a bookkeeping
    /// inconvenience.
    ///
    /// One withdrawal per account per asset per finalized assertion. The whole
    /// proven balance leaves at once, so there is no partial-withdrawal
    /// accounting to get wrong.
    public fun withdrawal_id(
        assertion: vector<u8>,
        l2_address: address,
        l2_asset_id: u32,
    ): vector<u8> {
        let buf = codec::begin(DOMAIN_WITHDRAWAL);
        codec::put_field(&mut buf, assertion);
        codec::put_field(&mut buf, bcs_address_bytes(l2_address));
        let asset_field = vector::empty<u8>();
        codec::put_u32(&mut asset_field, l2_asset_id);
        codec::put_field(&mut buf, asset_field);
        codec::commit(buf)
    }

    /// Withdraws the balance proven against a finalized assertion.
    ///
    /// Four things are checked, and each is load-bearing:
    ///
    /// 1. the assertion has finalized -- `finalized_root` aborts otherwise, so a
    ///    pending or challenged root cannot be withdrawn against however
    ///    well-formed the proof;
    /// 2. the proof reconstructs to that root, making it a claim about SENA's
    ///    state rather than about nothing;
    /// 3. the slot proven is the claimant's own;
    /// 4. this withdrawal has not already been paid.
    public entry fun withdraw(
        claimant: &signer,
        bridge_addr: address,
        assertion_id: vector<u8>,
        account_value: vector<u8>,
        siblings: vector<vector<u8>>,
        terminal_is_leaf: bool,
        terminal_key: vector<u8>,
        terminal_value_hash: vector<u8>,
    ) acquires Bridge {
        let claimant_addr = signer::address_of(claimant);
        let bridge = borrow_global_mut<Bridge>(bridge_addr);

        // Aborts unless the assertion has finalized.
        let root = assertions::finalized_root(bridge.chain, assertion_id);

        // The slot is derived from the claimant, never accepted from them.
        let slot = account_slot(claimant_addr);
        if (terminal_is_leaf) {
            assert!(terminal_key == slot, E_SLOT_NOT_CLAIMANTS);
        };

        let terminal = if (terminal_is_leaf) {
            trie::leaf_terminal(terminal_key, terminal_value_hash)
        } else {
            trie::empty_terminal()
        };
        let proof = trie::new_proof(siblings, terminal);
        trie::verify_inclusion(&proof, root, slot, trie::hash_value(account_value));

        let id = withdrawal_id(assertion_id, claimant_addr, bridge.l2_asset_id);
        assert!(!table::contains(&bridge.spent, id), E_ALREADY_WITHDRAWN);

        // The proven account state decides the amount. Taking it as an argument
        // would make the proof decorative.
        let account = osp::decode_account(account_value);
        let balance = osp::account_balance(&account, bridge.l2_asset_id);
        assert!(balance > 0, E_NOTHING_TO_WITHDRAW);
        // L2 balances are u128; a bridged amount must fit the asset's u64.
        assert!(balance <= 18446744073709551615, E_CUSTODY_SHORTFALL);
        let amount = (balance as u64);
        assert!(fungible_asset::balance(bridge.custody) >= amount, E_CUSTODY_SHORTFALL);

        table::add(&mut bridge.spent, id, true);

        let custody_signer = object::generate_signer_for_extending(&bridge.custody_extend);
        let assets = dispatchable_fungible_asset::withdraw(
            &custody_signer, bridge.custody, amount
        );
        let to = primary_fungible_store::ensure_primary_store_exists(
            claimant_addr, bridge.metadata
        );
        dispatchable_fungible_asset::deposit(to, assets);

        event::emit(Withdrawn {
            claimant: claimant_addr,
            amount,
            assertion: assertion_id,
            withdrawal_id: id,
        });
    }

    /// Submits a transaction directly to L1 (REQ-FRAUD-028).
    ///
    /// A fraud proof system a sequencer can neutralise by refusing service is
    /// not a security guarantee, so users need a path that does not depend on
    /// the sequencer's cooperation.
    public entry fun force_include(
        submitter: &signer,
        bridge_addr: address,
        entry_id: vector<u8>,
        payload: vector<u8>,
    ) acquires Bridge {
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        table::add(&mut bridge.forced, entry_id, ForcedEntry {
            submitter: signer::address_of(submitter),
            payload,
            submitted_at: timestamp::now_seconds(),
            included: false,
        });
    }

    /// Marks a forced entry as included by the sequencer.
    public fun mark_included(bridge_addr: address, entry_id: vector<u8>) acquires Bridge {
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

    #[test]
    fun withdrawal_ids_are_bound_to_what_they_pay() {
        // The id must change with every field it commits to, or one proof pays
        // twice.
        let a = withdrawal_id(x"11", @0xA, 1);
        assert!(a != withdrawal_id(x"22", @0xA, 1), 0); // different assertion
        assert!(a != withdrawal_id(x"11", @0xB, 1), 1); // different account
        assert!(a != withdrawal_id(x"11", @0xA, 2), 2); // different asset
        assert!(a == withdrawal_id(x"11", @0xA, 1), 3); // deterministic
    }
}
