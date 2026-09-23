/// The interactive bisection game (REQ-FRAUD-012 to REQ-FRAUD-015).
///
/// Two parties disputing a batch agree on its starting state and disagree on
/// its end. There is therefore a first step where they diverge. Each round the
/// defender divides the interval and publishes the state at each division; the
/// challenger names the first division it disputes; the interval shrinks. After
/// a logarithmic number of rounds it is one step wide, and `sena::osp` settles
/// it.
///
/// An honest party never has to make a false claim at any round, so an honest
/// party entering correctly cannot lose. That is the property the entire
/// security argument rests on.
module sena::disputes {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::timestamp;
    use sena::assertions;

    /// The dispute is over.
    const E_RESOLVED: u64 = 50;
    /// It is not this party's turn.
    const E_WRONG_TURN: u64 = 51;
    /// The move does not fit the current stage.
    const E_WRONG_STAGE: u64 = 52;
    /// The defender published the wrong number of commitments.
    const E_WRONG_DISSECTION: u64 = 53;
    /// The challenger selected a segment that does not exist.
    const E_SEGMENT_OUT_OF_RANGE: u64 = 54;
    /// No such dispute.
    const E_NO_SUCH_DISPUTE: u64 = 55;
    /// The caller is not a party to this dispute.
    const E_NOT_A_PARTY: u64 = 56;
    /// The registry has already been created.
    const E_ALREADY_INITIALIZED: u64 = 57;

    const PARTY_DEFENDER: u8 = 0;
    const PARTY_CHALLENGER: u8 = 1;

    const STAGE_BISECTING: u8 = 0;
    const STAGE_ONE_STEP: u8 = 1;
    const STAGE_RESOLVED: u8 = 2;

    /// Segments per round. Higher arity means fewer rounds -- less wall-clock
    /// time and less total L1 gas -- at the cost of larger individual moves.
    const ARITY: u64 = 8;

    /// How long a party has to make any single move.
    const MOVE_TIMEOUT: u64 = 21600;

    /// The share of the challenge window each party may consume.
    ///
    /// Four, so both parties together use at most half the window and a dispute
    /// always concludes while the window is still open. Derived from the window
    /// rather than fixed: a constant budget generous enough to be fair under
    /// congestion can exceed a window set near its floor, and a dispute that
    /// outlives its window lets fraud finalize while still under challenge.
    const CLOCK_BUDGET_DIVISOR: u64 = 4;

    struct Dispute has store, copy, drop {
        assertion: vector<u8>,
        defender: address,
        challenger: address,
        lo: u64,
        hi: u64,
        lo_commitment: vector<u8>,
        hi_commitment: vector<u8>,
        offered: vector<vector<u8>>,
        has_offer: bool,
        stage: u8,
        turn: u8,
        deadline: u64,
        defender_clock: u64,
        challenger_clock: u64,
        last_move_at: u64,
        winner: u8,
    }

    struct Registry has key {
        disputes: Table<vector<u8>, Dispute>,
        /// The assertion chain whose outcomes this registry applies.
        chain: address,
    }

    /// Creates the dispute registry.
    ///
    /// Without this nothing in the module works: every entry point borrows
    /// `Registry`, and a resource that is never moved to an account cannot be
    /// borrowed. Unit tests did not catch it because they call the functions
    /// directly rather than through a transaction.
    public entry fun initialize(admin: &signer, chain: address) {
        assert!(!exists<Registry>(signer::address_of(admin)), E_ALREADY_INITIALIZED);
        move_to(admin, Registry {
            disputes: table::new<vector<u8>, Dispute>(),
            chain,
        });
    }

    public fun clock_budget(challenge_window: u64): u64 {
        challenge_window / CLOCK_BUDGET_DIVISOR
    }

    /// Returns the segment boundaries of an interval.
    ///
    /// Derived by integer arithmetic from the interval and the arity, so both
    /// parties and this contract compute the same division without it having to
    /// be transmitted or agreed.
    public fun boundaries(lo: u64, hi: u64): vector<u64> {
        let span = hi - lo;
        let segments = if (ARITY < span) { ARITY } else { span };
        if (segments == 0) { segments = 1 };

        let out = vector::empty<u64>();
        let i = 0;
        while (i <= segments) {
            vector::push_back(&mut out, lo + (span * i) / segments);
            i = i + 1;
        };
        out
    }

    /// Opens a dispute over a whole trace.
    ///
    /// The challenger is the signer. Accepting it as a parameter would let one
    /// account enrol another as a party to a dispute it never entered.
    public entry fun open(
        challenger: &signer,
        registry_addr: address,
        id: vector<u8>,
        assertion: vector<u8>,
        defender: address,
        trace_length: u64,
        lo_commitment: vector<u8>,
        hi_commitment: vector<u8>,
        challenge_window: u64,
    ) acquires Registry {
        let budget = clock_budget(challenge_window);
        // A single move must never be given longer than the whole budget, or
        // one stall would exhaust it outright.
        let move_allowance = if (MOVE_TIMEOUT < budget) { MOVE_TIMEOUT } else { budget };
        let now = timestamp::now_seconds();

        let stage = if (trace_length == 1) { STAGE_ONE_STEP } else { STAGE_BISECTING };
        let turn = if (trace_length == 1) { PARTY_CHALLENGER } else { PARTY_DEFENDER };
        let challenger_addr = signer::address_of(challenger);

        let registry = borrow_global_mut<Registry>(registry_addr);
        table::add(&mut registry.disputes, id, Dispute {
            assertion,
            defender,
            challenger: challenger_addr,
            lo: 0,
            hi: trace_length,
            lo_commitment,
            hi_commitment,
            offered: vector::empty<vector<u8>>(),
            has_offer: false,
            stage,
            turn,
            deadline: now + move_allowance,
            defender_clock: budget,
            challenger_clock: budget,
            last_move_at: now,
            winner: 255,
        });
    }

    /// Returns which party an address is in this dispute, aborting if neither.
    ///
    /// The party is derived from the caller rather than taken as an argument.
    /// Trusting a parameter would let anyone move as either side, which makes
    /// the turn and clock checks decorative.
    fun party_of(d: &Dispute, who: address): u8 {
        if (who == d.defender) {
            PARTY_DEFENDER
        } else if (who == d.challenger) {
            PARTY_CHALLENGER
        } else {
            abort E_NOT_A_PARTY
        }
    }

    /// Charges the mover's clock and checks the turn.
    fun begin_move(d: &mut Dispute, party: u8) {
        assert!(d.stage != STAGE_RESOLVED, E_RESOLVED);
        assert!(d.turn == party, E_WRONG_TURN);

        let now = timestamp::now_seconds();
        if (now > d.deadline) {
            // Failing to move in time forfeits (REQ-FRAUD-014).
            d.stage = STAGE_RESOLVED;
            d.winner = if (party == PARTY_DEFENDER) { PARTY_CHALLENGER } else { PARTY_DEFENDER };
            abort E_RESOLVED
        };

        // A per-move deadline alone would let an adversary stretch a dispute by
        // always answering at the last permitted moment; the total budget is
        // what bounds it below the challenge window.
        let elapsed = now - d.last_move_at;
        if (party == PARTY_DEFENDER) {
            if (elapsed > d.defender_clock) {
                d.stage = STAGE_RESOLVED;
                d.winner = PARTY_CHALLENGER;
                abort E_RESOLVED
            };
            d.defender_clock = d.defender_clock - elapsed;
        } else {
            if (elapsed > d.challenger_clock) {
                d.stage = STAGE_RESOLVED;
                d.winner = PARTY_DEFENDER;
                abort E_RESOLVED
            };
            d.challenger_clock = d.challenger_clock - elapsed;
        };
    }

    fun pass_turn(d: &mut Dispute) {
        d.turn = if (d.turn == PARTY_DEFENDER) { PARTY_CHALLENGER } else { PARTY_DEFENDER };
        let now = timestamp::now_seconds();
        d.last_move_at = now;
        let budget = if (d.turn == PARTY_DEFENDER) { d.defender_clock } else { d.challenger_clock };
        let allowance = if (MOVE_TIMEOUT < budget) { MOVE_TIMEOUT } else { budget };
        d.deadline = now + allowance;
    }

    fun enter_one_step_if_narrow(d: &mut Dispute) {
        if (d.hi - d.lo == 1) {
            d.stage = STAGE_ONE_STEP;
            // The challenger produces the One-Step Proof, so the turn is theirs
            // regardless of who moved last.
            d.turn = PARTY_CHALLENGER;
        };
    }

    /// The defender divides the interval and publishes the interior states.
    public entry fun dissect(
        mover: &signer,
        registry_addr: address,
        id: vector<u8>,
        commitments: vector<vector<u8>>,
    ) acquires Registry {
        let who = signer::address_of(mover);
        let registry = borrow_global_mut<Registry>(registry_addr);
        assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
        let d = table::borrow_mut(&mut registry.disputes, id);

        assert!(party_of(d, who) == PARTY_DEFENDER, E_WRONG_TURN);
        begin_move(d, PARTY_DEFENDER);
        assert!(d.stage == STAGE_BISECTING, E_WRONG_STAGE);

        let expected = vector::length(&boundaries(d.lo, d.hi)) - 2;
        assert!(vector::length(&commitments) == expected, E_WRONG_DISSECTION);

        d.offered = commitments;
        d.has_offer = true;
        pass_turn(d);
    }

    /// The challenger names the first segment whose end it disputes.
    public entry fun select(
        mover: &signer,
        registry_addr: address,
        id: vector<u8>,
        index: u64,
    ) acquires Registry {
        let who = signer::address_of(mover);
        let registry = borrow_global_mut<Registry>(registry_addr);
        assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
        let d = table::borrow_mut(&mut registry.disputes, id);

        assert!(party_of(d, who) == PARTY_CHALLENGER, E_WRONG_TURN);
        begin_move(d, PARTY_CHALLENGER);
        assert!(d.stage == STAGE_BISECTING && d.has_offer, E_WRONG_STAGE);

        let bounds = boundaries(d.lo, d.hi);
        let segments = vector::length(&bounds) - 1;
        assert!(index < segments, E_SEGMENT_OUT_OF_RANGE);

        // Commitments at every boundary: lo (agreed), the offered interior
        // points, and hi (the defender's disputed claim).
        let all = vector::singleton(d.lo_commitment);
        vector::append(&mut all, d.offered);
        vector::push_back(&mut all, d.hi_commitment);

        d.lo = *vector::borrow(&bounds, index);
        d.hi = *vector::borrow(&bounds, index + 1);
        d.lo_commitment = *vector::borrow(&all, index);
        d.hi_commitment = *vector::borrow(&all, index + 1);

        d.offered = vector::empty<vector<u8>>();
        d.has_offer = false;
        pass_turn(d);
        enter_one_step_if_narrow(d);
    }

    /// Records the outcome of one-step adjudication and applies it.
    ///
    /// Recording the winner without applying it would leave the assertion chain
    /// unaware of the result -- a fraudulent assertion could lose its dispute
    /// and still finalize. This is the link between adjudication and status.
    fun resolve_internal(
        registry_addr: address,
        id: vector<u8>,
        winner: u8,
    ) acquires Registry {
        let (chain, assertion) = {
            let registry = borrow_global_mut<Registry>(registry_addr);
            assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
            let d = table::borrow_mut(&mut registry.disputes, id);
            assert!(d.stage != STAGE_RESOLVED, E_RESOLVED);
            d.stage = STAGE_RESOLVED;
            d.winner = winner;
            (registry.chain, d.assertion)
        };

        if (winner == PARTY_CHALLENGER) {
            assertions::challenger_won(chain, assertion);
        } else {
            assertions::defender_won(chain, assertion);
        };
    }

    /// Resolves a dispute whose party failed to move before its deadline.
    ///
    /// Permissionless: a party that has stopped responding will not report
    /// itself, so anyone must be able to claim the timeout (REQ-FRAUD-014).
    public entry fun claim_timeout(
        _caller: &signer,
        registry_addr: address,
        id: vector<u8>,
    ) acquires Registry {
        let winner = {
            let registry = borrow_global<Registry>(registry_addr);
            assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
            let d = table::borrow(&registry.disputes, id);
            assert!(d.stage != STAGE_RESOLVED, E_RESOLVED);
            assert!(timestamp::now_seconds() > d.deadline, E_WRONG_STAGE);
            if (d.turn == PARTY_DEFENDER) { PARTY_CHALLENGER } else { PARTY_DEFENDER }
        };
        resolve_internal(registry_addr, id, winner);
    }

    #[view]
    public fun disputed_step(registry_addr: address, id: vector<u8>): u64 acquires Registry {
        let registry = borrow_global<Registry>(registry_addr);
        assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
        let d = table::borrow(&registry.disputes, id);
        assert!(d.stage == STAGE_ONE_STEP, E_WRONG_STAGE);
        d.lo
    }

    public fun party_defender(): u8 { PARTY_DEFENDER }
    public fun party_challenger(): u8 { PARTY_CHALLENGER }
    public fun arity(): u64 { ARITY }

    #[test]
    fun boundaries_divide_evenly() {
        let b = boundaries(0, 48);
        assert!(vector::length(&b) == 9, 0);
        assert!(*vector::borrow(&b, 0) == 0, 1);
        assert!(*vector::borrow(&b, 8) == 48, 2);
        assert!(*vector::borrow(&b, 1) == 6, 3);
    }

    #[test]
    fun a_short_interval_uses_fewer_segments() {
        // Fewer steps than the arity: segments must not be empty.
        let b = boundaries(0, 3);
        assert!(vector::length(&b) == 4, 0);
        assert!(*vector::borrow(&b, 3) == 3, 1);
    }

    #[test]
    fun a_single_step_interval_is_one_segment() {
        let b = boundaries(5, 6);
        assert!(vector::length(&b) == 2, 0);
        assert!(*vector::borrow(&b, 0) == 5, 1);
        assert!(*vector::borrow(&b, 1) == 6, 2);
    }

    #[test]
    fun both_clocks_fit_inside_the_window() {
        // At every window the chain accepts, a dispute concludes while the
        // window is still open.
        let floor = 86400;
        assert!(2 * clock_budget(floor) < floor, 0);
        assert!(2 * clock_budget(604800) < 604800, 1);
    }
}
