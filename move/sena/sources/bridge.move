/// The L1 bridge: custody, withdrawals, and forced inclusion.
///
/// The rule this module exists to enforce is one line long: a withdrawal is
/// honoured only against a state root whose assertion has **finalized**
/// (REQ-FRAUD-005). That is what makes the challenge window mean something to a
/// user's funds rather than being a number in a document.
module sena::bridge {
    use std::signer;
    use aptos_std::table::{Self, Table};
    use aptos_framework::timestamp;
    use sena::assertions;
    use sena::trie;

    /// This withdrawal has already been made.
    const E_ALREADY_WITHDRAWN: u64 = 40;
    /// The forced-inclusion entry does not exist.
    const E_NO_SUCH_ENTRY: u64 = 41;
    /// The sequencer's inclusion deadline has not passed yet.
    const E_STILL_IN_TIME: u64 = 42;

    /// How long the sequencer has to include a forced transaction before anyone
    /// may include it and the sequencer's bond becomes slashable
    /// (REQ-FRAUD-029).
    const FORCED_INCLUSION_TIMEOUT: u64 = 86400;

    struct Bridge has key {
        admin: address,
        /// Assertion chain this bridge trusts for finality.
        chain: address,
        /// Withdrawals already paid, keyed by their unique identifier.
        spent: Table<vector<u8>, bool>,
        /// Transactions submitted directly to L1 (REQ-FRAUD-028).
        forced: Table<vector<u8>, ForcedEntry>,
    }

    struct ForcedEntry has store, copy, drop {
        submitter: address,
        payload: vector<u8>,
        submitted_at: u64,
        included: bool,
    }

    public entry fun initialize(admin: &signer, chain: address) {
        move_to(admin, Bridge {
            admin: signer::address_of(admin),
            chain,
            spent: table::new<vector<u8>, bool>(),
            forced: table::new<vector<u8>, ForcedEntry>(),
        });
    }

    /// Withdraws against a finalized assertion.
    ///
    /// Three things are checked, and all three are load-bearing:
    ///
    /// 1. the assertion has finalized -- `finalized_root` aborts otherwise, so a
    ///    pending or challenged root cannot be withdrawn against however
    ///    well-formed the proof;
    /// 2. the proof reconstructs to that root, which is what makes it a claim
    ///    about SENA's state rather than about nothing;
    /// 3. the withdrawal has not already been paid.
    public entry fun withdraw(
        claimant: &signer,
        bridge_addr: address,
        assertion_id: vector<u8>,
        account_slot: vector<u8>,
        account_value: vector<u8>,
        siblings: vector<vector<u8>>,
        terminal_is_leaf: bool,
        terminal_key: vector<u8>,
        terminal_value_hash: vector<u8>,
        withdrawal_id: vector<u8>,
    ) acquires Bridge {
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        assert!(!table::contains(&bridge.spent, withdrawal_id), E_ALREADY_WITHDRAWN);

        // Aborts unless the assertion has finalized.
        let root = assertions::finalized_root(bridge.chain, assertion_id);

        let terminal = if (terminal_is_leaf) {
            trie::leaf_terminal(terminal_key, terminal_value_hash)
        } else {
            trie::empty_terminal()
        };
        let proof = trie::new_proof(siblings, terminal);
        trie::verify_inclusion(&proof, root, account_slot, trie::hash_value(account_value));

        table::add(&mut bridge.spent, withdrawal_id, true);
        let _ = signer::address_of(claimant);
    }

    /// Submits a transaction directly to L1 (REQ-FRAUD-028).
    ///
    /// A fraud proof system a sequencer can neutralise by refusing service is
    /// not a security guarantee, so users must have a path that does not depend
    /// on the sequencer's cooperation.
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

    #[view]
    /// Returns whether a forced entry has passed its inclusion deadline.
    ///
    /// Once it has, anyone may include it and the sequencer's bond becomes
    /// slashable for censorship (REQ-FRAUD-029).
    public fun is_overdue(bridge_addr: address, entry_id: vector<u8>): bool acquires Bridge {
        let bridge = borrow_global<Bridge>(bridge_addr);
        assert!(table::contains(&bridge.forced, entry_id), E_NO_SUCH_ENTRY);
        let entry = table::borrow(&bridge.forced, entry_id);
        !entry.included
            && timestamp::now_seconds() >= entry.submitted_at + FORCED_INCLUSION_TIMEOUT
    }

    /// Marks a forced entry as included by the sequencer.
    public fun mark_included(bridge_addr: address, entry_id: vector<u8>) acquires Bridge {
        let bridge = borrow_global_mut<Bridge>(bridge_addr);
        assert!(table::contains(&bridge.forced, entry_id), E_NO_SUCH_ENTRY);
        table::borrow_mut(&mut bridge.forced, entry_id).included = true;
    }

    #[view]
    public fun is_spent(bridge_addr: address, withdrawal_id: vector<u8>): bool acquires Bridge {
        table::contains(&borrow_global<Bridge>(bridge_addr).spent, withdrawal_id)
    }

    public fun forced_inclusion_timeout(): u64 { FORCED_INCLUSION_TIMEOUT }

    #[test]
    fun timeout_is_a_day() {
        assert!(FORCED_INCLUSION_TIMEOUT == 86400, 0);
    }
}
