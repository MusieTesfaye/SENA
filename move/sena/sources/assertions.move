/// The bonded assertion chain (REQ-FRAUD-001 to REQ-FRAUD-006).
///
/// An assertion is a claim, not a fact: posted with a bond, open to challenge
/// for a window, and only then final.
///
/// # What this module deliberately cannot do
///
/// There is no entry point to finalize a challenged assertion, dismiss a
/// challenge, or set the window below its floor -- not a guarded one, an absent
/// one. REQ-FRAUD-015 and REQ-GOV-007 survive a compromised governance council
/// only if the capability does not exist to be abused.
module sena::assertions {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::timestamp;
    use sena::codec;

    /// Caller is not the module's administrator.
    const E_NOT_ADMIN: u64 = 30;
    /// No such assertion.
    const E_UNKNOWN_ASSERTION: u64 = 31;
    /// The parent assertion is unknown.
    const E_UNKNOWN_PARENT: u64 = 32;
    /// Nothing may be built on a rejected assertion.
    const E_PARENT_REJECTED: u64 = 33;
    /// The pre-state root does not continue the parent's post-state root.
    const E_BROKEN_CHAIN: u64 = 34;
    /// The bond is below the minimum.
    const E_BOND_TOO_SMALL: u64 = 35;
    /// The assertion is not in a status permitting this operation.
    const E_WRONG_STATUS: u64 = 36;
    /// The challenge window has not elapsed.
    const E_WINDOW_OPEN: u64 = 37;
    /// The parent has not finalized.
    const E_PARENT_NOT_FINAL: u64 = 38;

    const STATUS_PENDING: u8 = 0;
    const STATUS_CHALLENGED: u8 = 1;
    const STATUS_FINALIZED: u8 = 2;
    const STATUS_REJECTED: u8 = 3;

    /// The floor on the challenge window, in seconds: 24 hours.
    ///
    /// A shorter window would make honest challenge contingent on a verifier
    /// being online and able to land an L1 transaction within hours, which is
    /// not safe under congestion. Governance may raise it and cannot lower it
    /// past here.
    const CHALLENGE_WINDOW_FLOOR: u64 = 86400;

    struct Assertion has store, copy, drop {
        parent: vector<u8>,
        proposer: address,
        pre_state_root: vector<u8>,
        post_state_root: vector<u8>,
        batch_commitment: vector<u8>,
        trace_length: u64,
        bond: u128,
        posted_at: u64,
        status: u8,
        open_challenges: u64,
    }

    struct Chain has key {
        admin: address,
        assertions: Table<vector<u8>, Assertion>,
        /// Ids in posting order, so descendants can be swept on rejection.
        order: vector<vector<u8>>,
        latest_finalized: vector<u8>,
        challenge_window: u64,
        minimum_bond: u128,
    }

    /// Computes an assertion's identifier.
    public fun assertion_id(
        parent: vector<u8>,
        proposer_tag: u64,
        pre_state_root: vector<u8>,
        post_state_root: vector<u8>,
        batch_commitment: vector<u8>,
        trace_length: u64,
        bond: u128,
    ): vector<u8> {
        let buf = codec::begin(codec::domain_assertion());
        codec::put_field(&mut buf, parent);
        let f = vector::empty<u8>();
        codec::put_u64(&mut f, proposer_tag);
        codec::put_field(&mut buf, f);
        codec::put_field(&mut buf, pre_state_root);
        codec::put_field(&mut buf, post_state_root);
        codec::put_field(&mut buf, batch_commitment);
        let g = vector::empty<u8>();
        codec::put_u64(&mut g, trace_length);
        codec::put_field(&mut buf, g);
        let h = vector::empty<u8>();
        codec::put_u128(&mut h, bond);
        codec::put_field(&mut buf, h);
        codec::commit(buf)
    }

    /// Initialises the chain at `genesis_root`.
    ///
    /// The window is clamped to the floor rather than rejected, so no
    /// configuration path can produce a chain with an unsafe window.
    public entry fun initialize(
        admin: &signer,
        genesis_root: vector<u8>,
        challenge_window: u64,
        minimum_bond: u128,
    ) {
        let window = if (challenge_window < CHALLENGE_WINDOW_FLOOR) {
            CHALLENGE_WINDOW_FLOOR
        } else {
            challenge_window
        };

        let zero = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut zero, 0); i = i + 1; };

        let genesis = Assertion {
            parent: zero,
            proposer: signer::address_of(admin),
            pre_state_root: zero,
            post_state_root: genesis_root,
            batch_commitment: zero,
            trace_length: 0,
            bond: 0,
            posted_at: 0,
            status: STATUS_FINALIZED,
            open_challenges: 0,
        };
        let id = assertion_id(zero, 0, zero, genesis_root, zero, 0, 0);

        let assertions = table::new<vector<u8>, Assertion>();
        table::add(&mut assertions, id, genesis);

        move_to(admin, Chain {
            admin: signer::address_of(admin),
            assertions,
            order: vector::singleton(id),
            latest_finalized: id,
            challenge_window: window,
            minimum_bond,
        });
    }

    /// Posts a bonded assertion.
    public fun post(
        chain_addr: address,
        proposer: address,
        parent: vector<u8>,
        pre_state_root: vector<u8>,
        post_state_root: vector<u8>,
        batch_commitment: vector<u8>,
        trace_length: u64,
        bond: u128,
    ): vector<u8> acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, parent), E_UNKNOWN_PARENT);

        let parent_record = table::borrow(&chain.assertions, parent);
        assert!(parent_record.status != STATUS_REJECTED, E_PARENT_REJECTED);
        assert!(parent_record.post_state_root == pre_state_root, E_BROKEN_CHAIN);
        assert!(bond >= chain.minimum_bond, E_BOND_TOO_SMALL);

        let id = assertion_id(
            parent, 0, pre_state_root, post_state_root, batch_commitment, trace_length, bond
        );
        table::add(&mut chain.assertions, id, Assertion {
            parent,
            proposer,
            pre_state_root,
            post_state_root,
            batch_commitment,
            trace_length,
            bond,
            posted_at: timestamp::now_seconds(),
            status: STATUS_PENDING,
            open_challenges: 0,
        });
        vector::push_back(&mut chain.order, id);
        id
    }

    /// Records that a challenge has opened.
    public fun open_challenge(chain_addr: address, id: vector<u8>) acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        let record = table::borrow_mut(&mut chain.assertions, id);
        assert!(
            record.status == STATUS_PENDING || record.status == STATUS_CHALLENGED,
            E_WRONG_STATUS
        );
        record.status = STATUS_CHALLENGED;
        record.open_challenges = record.open_challenges + 1;
    }

    /// Records a challenge resolved in the proposer's favour.
    ///
    /// The assertion returns to pending only once every challenge against it has
    /// resolved (REQ-FRAUD-006).
    public fun defender_won(chain_addr: address, id: vector<u8>) acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        let record = table::borrow_mut(&mut chain.assertions, id);
        assert!(record.status == STATUS_CHALLENGED, E_WRONG_STATUS);
        record.open_challenges = record.open_challenges - 1;
        if (record.open_challenges == 0) { record.status = STATUS_PENDING };
    }

    /// Rejects an assertion and every assertion built on it (REQ-FRAUD-019).
    ///
    /// Descendants cannot survive: they claim to continue from a state that was
    /// never reached.
    public fun challenger_won(chain_addr: address, id: vector<u8>) acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        {
            let record = table::borrow_mut(&mut chain.assertions, id);
            assert!(record.status == STATUS_CHALLENGED, E_WRONG_STATUS);
            record.status = STATUS_REJECTED;
            record.open_challenges = 0;
        };

        // Sweep forward in posting order. A child is always posted after its
        // parent, so one pass rejects the whole subtree.
        let i = 0;
        let len = vector::length(&chain.order);
        while (i < len) {
            let candidate = *vector::borrow(&chain.order, i);
            let parent = table::borrow(&chain.assertions, candidate).parent;
            if (table::contains(&chain.assertions, parent)) {
                let parent_status = table::borrow(&chain.assertions, parent).status;
                if (parent_status == STATUS_REJECTED) {
                    let record = table::borrow_mut(&mut chain.assertions, candidate);
                    record.status = STATUS_REJECTED;
                    record.open_challenges = 0;
                };
            };
            i = i + 1;
        };
    }

    /// Finalizes an assertion whose window has elapsed (REQ-FRAUD-004).
    public entry fun finalize(chain_addr: address, id: vector<u8>) acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);

        let (parent, posted_at, status) = {
            let r = table::borrow(&chain.assertions, id);
            (r.parent, r.posted_at, r.status)
        };
        assert!(status == STATUS_PENDING, E_WRONG_STATUS);

        // An assertion must not outrun its parent: finalizing out of order would
        // make a descendant of a still-disputable claim withdrawable.
        assert!(table::contains(&chain.assertions, parent), E_UNKNOWN_PARENT);
        assert!(
            table::borrow(&chain.assertions, parent).status == STATUS_FINALIZED,
            E_PARENT_NOT_FINAL
        );

        let elapsed = timestamp::now_seconds() - posted_at;
        assert!(elapsed >= chain.challenge_window, E_WINDOW_OPEN);

        table::borrow_mut(&mut chain.assertions, id).status = STATUS_FINALIZED;
        chain.latest_finalized = id;
    }

    #[view]
    public fun status(chain_addr: address, id: vector<u8>): u8 acquires Chain {
        let chain = borrow_global<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        table::borrow(&chain.assertions, id).status
    }

    #[view]
    public fun challenge_window(chain_addr: address): u64 acquires Chain {
        borrow_global<Chain>(chain_addr).challenge_window
    }

    /// Returns the post-state root of an assertion, if it has finalized.
    ///
    /// The bridge uses this: a withdrawal is only ever checked against a root
    /// that reached here (REQ-FRAUD-005).
    public fun finalized_root(chain_addr: address, id: vector<u8>): vector<u8> acquires Chain {
        let chain = borrow_global<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        let record = table::borrow(&chain.assertions, id);
        assert!(record.status == STATUS_FINALIZED, E_WRONG_STATUS);
        record.post_state_root
    }

    public fun status_pending(): u8 { STATUS_PENDING }
    public fun status_challenged(): u8 { STATUS_CHALLENGED }
    public fun status_finalized(): u8 { STATUS_FINALIZED }
    public fun status_rejected(): u8 { STATUS_REJECTED }
    public fun challenge_window_floor(): u64 { CHALLENGE_WINDOW_FLOOR }
}
