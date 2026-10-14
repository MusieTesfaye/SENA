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
    // Dispute outcomes may only be applied by the dispute module. Without this
    // `challenger_won` is reachable by any module, which means any caller could
    // reject a sound assertion -- the inverse of the attack fraud proofs exist
    // to stop.
    friend sena::disputes;

    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::dispatchable_fungible_asset;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, FungibleStore, Metadata};
    use aptos_framework::object::{Self, Object, ExtendRef};
    use aptos_framework::primary_fungible_store;
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
    /// The caller is not the party this operation belongs to.
    const E_NOT_PROPOSER: u64 = 39;
    /// The bond does not fit the bonded asset's u64 amount.
    const E_BOND_TOO_LARGE: u64 = 60;
    /// No challenge by that party is open against this assertion.
    const E_NO_SUCH_CHALLENGE: u64 = 61;
    /// This party already has a challenge open against this assertion.
    const E_ALREADY_CHALLENGING: u64 = 62;
    /// The proposer may not challenge their own assertion.
    const E_SELF_CHALLENGE: u64 = 63;
    /// The batch timestamp runs backwards from the parent's.
    const E_TIMESTAMP_REGRESSES: u64 = 64;
    /// The batch timestamp is ahead of L1 time.
    const E_TIMESTAMP_IN_FUTURE: u64 = 65;
    /// The batch is older than the chain allows a batch to be when posted.
    const E_BATCH_TOO_OLD: u64 = 66;
    /// The batch data is malformed: mismatched lengths, start positions that
    /// do not begin at zero and increase, or a trace inconsistent with them.
    const E_BAD_BATCH_DATA: u64 = 67;

    /// Share of a slashed bond paid to the winner, as a percentage.
    ///
    /// Deliberately below 100. A challenger who receives everything the proposer
    /// forfeits has an incentive to collude with -- or simply be -- the
    /// proposer, posting invalid assertions to harvest bonds in a wash. The
    /// remainder goes to the treasury (REQ-FRAUD-020).
    const SLASH_REWARD_PERCENT: u128 = 50;

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

    /// How far a batch timestamp may run ahead of L1 time, for clock skew.
    const MAX_FUTURE_DRIFT_SECS: u64 = 60;

    /// Bounds on how old a batch may be when its assertion is posted.
    ///
    /// The batch timestamp is what keyless ephemeral-key expiry is judged
    /// against. A sequencer free to post arbitrarily old timestamps could keep
    /// accepting an ephemeral key long after it expired; bounding the age
    /// bounds that window.
    const MIN_MAX_BATCH_AGE_SECS: u64 = 600;
    const MAX_MAX_BATCH_AGE_SECS: u64 = 86400;

    #[event]
    /// The batch data behind an assertion. This *is* the data availability
    /// layer: verifiers rebuild L2 state from these events alone.
    struct BatchPublished has drop, store {
        assertion: vector<u8>,
        timestamp: u64,
        tx_bytes: vector<vector<u8>>,
        tx_starts: vector<u64>,
    }

    /// A bonded challenge against an assertion.
    struct Challenge has store, copy, drop {
        challenger: address,
        bond: u128,
    }

    struct Assertion has store, copy, drop {
        parent: vector<u8>,
        proposer: address,
        pre_state_root: vector<u8>,
        post_state_root: vector<u8>,
        batch_commitment: vector<u8>,
        /// The batch header the commitment is computed from.
        timestamp: u64,
        tx_count: u64,
        tx_root: vector<u8>,
        trace_length: u64,
        bond: u128,
        posted_at: u64,
        status: u8,
        open_challenges: u64,
    }

    struct Chain has key {
        admin: address,
        assertions: Table<vector<u8>, Assertion>,
        /// Open challenges per assertion, with the bond each carries.
        challenges: Table<vector<u8>, vector<Challenge>>,
        /// Ids in posting order, so descendants can be swept on rejection.
        order: vector<vector<u8>>,
        latest_finalized: vector<u8>,
        challenge_window: u64,
        minimum_bond: u128,
        /// The asset bonds are posted in.
        bond_metadata: Object<Metadata>,
        /// Where bonds are held while at risk.
        escrow: Object<FungibleStore>,
        /// Lets the module sign for the escrow when paying out.
        escrow_extend: ExtendRef,
        /// Receives the share of a slashed bond not paid to the winner.
        treasury: address,
        /// The oldest a batch may be when its assertion is posted.
        max_batch_age: u64,
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
        bond_metadata: Object<Metadata>,
        treasury: address,
        max_batch_age: u64,
    ) {
        let window = if (challenge_window < CHALLENGE_WINDOW_FLOOR) {
            CHALLENGE_WINDOW_FLOOR
        } else {
            challenge_window
        };
        let max_batch_age = if (max_batch_age < MIN_MAX_BATCH_AGE_SECS) {
            MIN_MAX_BATCH_AGE_SECS
        } else if (max_batch_age > MAX_MAX_BATCH_AGE_SECS) {
            MAX_MAX_BATCH_AGE_SECS
        } else {
            max_batch_age
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
            timestamp: 0,
            tx_count: 0,
            tx_root: zero,
            trace_length: 0,
            bond: 0,
            posted_at: 0,
            status: STATUS_FINALIZED,
            open_challenges: 0,
        };
        let id = assertion_id(zero, 0, zero, genesis_root, zero, 0, 0);

        let assertions = table::new<vector<u8>, Assertion>();
        table::add(&mut assertions, id, genesis);

        // Escrow lives in its own object rather than the admin's primary store,
        // so the admin's own holdings can never be spent as somebody's bond.
        let constructor = object::create_object(signer::address_of(admin));
        let escrow_extend = object::generate_extend_ref(&constructor);
        let escrow = fungible_asset::create_store(&constructor, bond_metadata);

        move_to(admin, Chain {
            admin: signer::address_of(admin),
            assertions,
            challenges: table::new<vector<u8>, vector<Challenge>>(),
            order: vector::singleton(id),
            latest_finalized: id,
            challenge_window: window,
            minimum_bond,
            bond_metadata,
            escrow,
            escrow_extend,
            treasury,
            max_batch_age,
        });
    }

    /// Moves a bond from `payer` into escrow.
    ///
    /// Dispatchable so the bonded asset's own controls run: a frozen or blocked
    /// account must fail to bond rather than appear to.
    fun take_bond(chain: &Chain, payer: &signer, amount: u128) {
        assert!(amount <= 18446744073709551615, E_BOND_TOO_LARGE);
        let from = primary_fungible_store::ensure_primary_store_exists(
            signer::address_of(payer), chain.bond_metadata
        );
        let assets = dispatchable_fungible_asset::withdraw(payer, from, (amount as u64));
        dispatchable_fungible_asset::deposit(chain.escrow, assets);
    }

    /// Pays `amount` out of escrow to `recipient`.
    fun pay_from_escrow(chain: &Chain, recipient: address, amount: u128) {
        if (amount == 0) { return };
        let escrow_signer = object::generate_signer_for_extending(&chain.escrow_extend);
        let assets = dispatchable_fungible_asset::withdraw(
            &escrow_signer, chain.escrow, (amount as u64)
        );
        let to = primary_fungible_store::ensure_primary_store_exists(
            recipient, chain.bond_metadata
        );
        dispatchable_fungible_asset::deposit(to, assets);
    }

    /// Splits a forfeited bond between the winner and the treasury.
    fun distribute_slashed(chain: &Chain, winner: address, bond: u128) {
        let reward = bond * SLASH_REWARD_PERCENT / 100;
        pay_from_escrow(chain, winner, reward);
        pay_from_escrow(chain, chain.treasury, bond - reward);
    }

    /// Posts a bonded assertion.
    ///
    /// The proposer is derived from the signer rather than passed in. Taking it
    /// as a parameter would let anyone post an assertion attributed to someone
    /// else, putting a bond at risk that is not theirs.
    public entry fun post(
        proposer: &signer,
        chain_addr: address,
        parent: vector<u8>,
        pre_state_root: vector<u8>,
        post_state_root: vector<u8>,
        timestamp: u64,
        tx_bytes: vector<vector<u8>>,
        tx_starts: vector<u64>,
        trace_length: u64,
        bond: u128,
    ) acquires Chain {
        let tx_count = vector::length(&tx_bytes);
        check_batch_shape(&tx_starts, tx_count, trace_length, &pre_state_root, &post_state_root);
        let proposer_addr = signer::address_of(proposer);
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, parent), E_UNKNOWN_PARENT);

        let parent_record = table::borrow(&chain.assertions, parent);
        assert!(parent_record.status != STATUS_REJECTED, E_PARENT_REJECTED);
        assert!(parent_record.post_state_root == pre_state_root, E_BROKEN_CHAIN);
        assert!(bond >= chain.minimum_bond, E_BOND_TOO_SMALL);

        // The batch timestamp is batch data: keyless expiry is judged against
        // it. It may not run backwards, run ahead of L1, or be stale.
        let now = timestamp::now_seconds();
        assert!(timestamp >= parent_record.timestamp, E_TIMESTAMP_REGRESSES);
        assert!(timestamp <= now + MAX_FUTURE_DRIFT_SECS, E_TIMESTAMP_IN_FUTURE);
        assert!(now <= timestamp + chain.max_batch_age, E_BATCH_TOO_OLD);

        // The batch data is published here, on L1, and the root is computed
        // from it. A sequencer that could post a bare root could commit to
        // leaves no one can open, and steps covered by them could never be
        // adjudicated. Publishing the data makes every leaf provable.
        let tx_root = sena::batch::root_of(&tx_bytes, &tx_starts);
        let batch_commitment = sena::batch::header_commitment(timestamp, tx_count, tx_root);

        let id = assertion_id(
            parent, 0, pre_state_root, post_state_root, batch_commitment, trace_length, bond
        );

        // The bond moves before the assertion is recorded. An assertion on the
        // books without its bond in escrow would be a claim backed by nothing,
        // which is the state this whole change exists to end.
        take_bond(chain, proposer, bond);

        table::add(&mut chain.assertions, id, Assertion {
            parent,
            proposer: proposer_addr,
            pre_state_root,
            post_state_root,
            batch_commitment,
            timestamp,
            tx_count,
            tx_root,
            trace_length,
            bond,
            posted_at: now,
            status: STATUS_PENDING,
            open_challenges: 0,
        });
        vector::push_back(&mut chain.order, id);

        event::emit(BatchPublished { assertion: id, timestamp, tx_bytes, tx_starts });
    }

    /// Checks the shape of published batch data that L1 can check without
    /// compiling anything. What needs compilation -- that consecutive start
    /// positions match each transaction's instruction count -- is left to the
    /// batch-structure fraud proofs in `sena::disputes`.
    fun check_batch_shape(
        tx_starts: &vector<u64>,
        tx_count: u64,
        trace_length: u64,
        pre_state_root: &vector<u8>,
        post_state_root: &vector<u8>,
    ) {
        assert!(vector::length(tx_starts) == tx_count, E_BAD_BATCH_DATA);
        if (tx_count == 0) {
            // An empty batch changes nothing.
            assert!(trace_length == 0 && *pre_state_root == *post_state_root, E_BAD_BATCH_DATA);
            return
        };
        assert!(*vector::borrow(tx_starts, 0) == 0, E_BAD_BATCH_DATA);
        let i = 1;
        while (i < tx_count) {
            assert!(*vector::borrow(tx_starts, i) > *vector::borrow(tx_starts, i - 1), E_BAD_BATCH_DATA);
            i = i + 1;
        };
        assert!(trace_length > *vector::borrow(tx_starts, tx_count - 1), E_BAD_BATCH_DATA);
    }


    /// Records that a challenge has opened.
    ///
    /// Permissionless by design (REQ-FRAUD-011): any account may challenge. The
    /// signer is required so that opening a challenge is an authenticated act
    /// with an identifiable party, not so that it can be restricted.
    public entry fun open_challenge(
        challenger: &signer,
        chain_addr: address,
        id: vector<u8>,
        bond: u128,
    ) acquires Chain {
        let who = signer::address_of(challenger);
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        assert!(bond >= chain.minimum_bond, E_BOND_TOO_SMALL);

        let proposer = table::borrow(&chain.assertions, id).proposer;
        // A proposer challenging themselves could move their own bond between
        // their own pockets and waste a window doing it.
        assert!(who != proposer, E_SELF_CHALLENGE);

        if (table::contains(&chain.challenges, id)) {
            let existing = table::borrow(&chain.challenges, id);
            let i = 0;
            while (i < vector::length(existing)) {
                assert!(vector::borrow(existing, i).challenger != who, E_ALREADY_CHALLENGING);
                i = i + 1;
            };
        };

        take_bond(chain, challenger, bond);

        let record = table::borrow_mut(&mut chain.assertions, id);
        assert!(
            record.status == STATUS_PENDING || record.status == STATUS_CHALLENGED,
            E_WRONG_STATUS
        );
        record.status = STATUS_CHALLENGED;
        record.open_challenges = record.open_challenges + 1;

        if (!table::contains(&chain.challenges, id)) {
            table::add(&mut chain.challenges, id, vector::empty<Challenge>());
        };
        vector::push_back(
            table::borrow_mut(&mut chain.challenges, id),
            Challenge { challenger: who, bond },
        );
    }

    /// Removes a challenge, returning the bond it carried.
    fun take_challenge(chain: &mut Chain, id: vector<u8>, who: address): u128 {
        assert!(table::contains(&chain.challenges, id), E_NO_SUCH_CHALLENGE);
        let list = table::borrow_mut(&mut chain.challenges, id);
        let i = 0;
        while (i < vector::length(list)) {
            if (vector::borrow(list, i).challenger == who) {
                let c = vector::remove(list, i);
                return c.bond
            };
            i = i + 1;
        };
        abort E_NO_SUCH_CHALLENGE
    }

    /// Records a challenge resolved in the proposer's favour.
    ///
    /// The assertion returns to pending only once every challenge against it has
    /// resolved (REQ-FRAUD-006).
    /// Only the dispute module may call this: an outcome is the result of
    /// adjudication, not something a party can assert for itself.
    public(friend) fun defender_won(
        chain_addr: address,
        id: vector<u8>,
        loser: address,
    ) acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);

        let bond = take_challenge(chain, id, loser);
        let proposer = table::borrow(&chain.assertions, id).proposer;

        let record = table::borrow_mut(&mut chain.assertions, id);
        assert!(record.status == STATUS_CHALLENGED, E_WRONG_STATUS);
        record.open_challenges = record.open_challenges - 1;
        if (record.open_challenges == 0) { record.status = STATUS_PENDING };

        // A groundless challenge costs the challenger their bond, or delaying an
        // honest chain would be free (REQ-FRAUD-021).
        distribute_slashed(chain, proposer, bond);
    }

    /// Rejects an assertion and every assertion built on it (REQ-FRAUD-019).
    ///
    /// Descendants cannot survive: they claim to continue from a state that was
    /// never reached.
    /// Only the dispute module may call this. Left public, any caller could
    /// reject a sound assertion -- the inverse of the attack this system exists
    /// to prevent.
    public(friend) fun challenger_won(
        chain_addr: address,
        id: vector<u8>,
        winner: address,
    ) acquires Chain {
        let chain = borrow_global_mut<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);

        let challenger_bond = take_challenge(chain, id, winner);
        let proposer_bond = {
            let record = table::borrow_mut(&mut chain.assertions, id);
            assert!(record.status == STATUS_CHALLENGED, E_WRONG_STATUS);
            record.status = STATUS_REJECTED;
            record.open_challenges = 0;
            record.bond
        };

        // The winner gets their own bond back, then a share of the forfeited
        // one. The remainder goes to the treasury rather than the winner, so
        // posting fraud and challenging it yourself is not profitable.
        pay_from_escrow(chain, winner, challenger_bond);
        distribute_slashed(chain, winner, proposer_bond);
        // Anyone else who challenged it was right too: their bonds come back
        // rather than sitting in escrow behind an assertion that no longer
        // accepts outcomes.
        refund_challenges(chain, id);

        // Rejecting only the disputed assertion would leave its children
        // claiming to continue from a state that was never reached. Their
        // proposers built on an unfinalized claim and forfeit to the treasury;
        // their challengers are refunded.
        let i = 0;
        let len = vector::length(&chain.order);
        while (i < len) {
            let candidate = *vector::borrow(&chain.order, i);
            let (parent, status, bond) = {
                let r = table::borrow(&chain.assertions, candidate);
                (r.parent, r.status, r.bond)
            };
            if (status != STATUS_REJECTED && status != STATUS_FINALIZED
                && table::contains(&chain.assertions, parent)
                && table::borrow(&chain.assertions, parent).status == STATUS_REJECTED) {
                let record = table::borrow_mut(&mut chain.assertions, candidate);
                record.status = STATUS_REJECTED;
                record.open_challenges = 0;
                let treasury = chain.treasury;
                pay_from_escrow(chain, treasury, bond);
                refund_challenges(chain, candidate);
            };
            i = i + 1;
        };
    }

    /// Returns every open challenge's bond on `id` to its challenger.
    fun refund_challenges(chain: &mut Chain, id: vector<u8>) {
        if (!table::contains(&chain.challenges, id)) { return };
        let list = *table::borrow(&chain.challenges, id);
        *table::borrow_mut(&mut chain.challenges, id) = vector::empty<Challenge>();
        let i = 0;
        while (i < vector::length(&list)) {
            let c = *vector::borrow(&list, i);
            pay_from_escrow(chain, c.challenger, c.bond);
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

        let (proposer, bond) = {
            let record = table::borrow_mut(&mut chain.assertions, id);
            record.status = STATUS_FINALIZED;
            (record.proposer, record.bond)
        };
        chain.latest_finalized = id;

        // The bond was at risk only while the assertion could still be
        // overturned. Once finalized it cannot be, so it is returned.
        pay_from_escrow(chain, proposer, bond);
    }

    /// What the dispute module needs to know about an assertion, all of it
    /// read from the record rather than taken from a caller.
    public fun dispute_view(chain_addr: address, id: vector<u8>): (
        address, vector<u8>, vector<u8>, u64, u64, vector<u8>, u64, u8
    ) acquires Chain {
        let chain = borrow_global<Chain>(chain_addr);
        assert!(table::contains(&chain.assertions, id), E_UNKNOWN_ASSERTION);
        let r = table::borrow(&chain.assertions, id);
        (
            r.proposer, r.pre_state_root, r.post_state_root, r.timestamp, r.tx_count,
            r.tx_root, r.trace_length, r.status,
        )
    }

    /// Whether `who` has an open, bonded challenge against `id`.
    public fun has_open_challenge(chain_addr: address, id: vector<u8>, who: address): bool acquires Chain {
        let chain = borrow_global<Chain>(chain_addr);
        if (!table::contains(&chain.challenges, id)) { return false };
        let list = table::borrow(&chain.challenges, id);
        let i = 0;
        while (i < vector::length(list)) {
            if (vector::borrow(list, i).challenger == who) { return true };
            i = i + 1;
        };
        false
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
    public fun max_future_drift_secs(): u64 { MAX_FUTURE_DRIFT_SECS }
    public fun slash_reward_percent(): u128 { SLASH_REWARD_PERCENT }

    #[view]
    /// Total bonds currently at risk. Should equal the sum of live assertion
    /// and challenge bonds; a divergence means value leaked.
    public fun escrow_balance(chain_addr: address): u64 acquires Chain {
        fungible_asset::balance(borrow_global<Chain>(chain_addr).escrow)
    }
}
