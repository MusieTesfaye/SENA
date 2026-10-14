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
    use std::bcs;
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::timestamp;
    use sena::assertions;
    use sena::batch;
    use sena::compiler;
    use sena::keyless;
    use sena::osp;
    use sena::trie;

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
    /// The caller holds no open challenge against the assertion.
    const E_NOT_CHALLENGING: u64 = 58;
    /// The assertion is not under challenge.
    const E_NOT_CHALLENGED: u64 = 59;
    /// The move came after the mover's deadline; claim the timeout instead.
    const E_DEADLINE_PASSED: u64 = 60;
    /// A batch leaf did not prove against the assertion's batch root.
    const E_BAD_LEAF: u64 = 61;
    /// The leaf does not cover the disputed step.
    const E_LEAF_DOES_NOT_COVER_STEP: u64 = 62;
    /// The structural fraud proof does not show any fraud.
    const E_NOT_FRAUD: u64 = 63;
    /// A trace of zero steps has nothing to bisect.
    const E_EMPTY_TRACE: u64 = 64;

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
        /// The keyless parameter set L2 runs with (`sena::keyless` setup id).
        /// Fixed here, once: a verification key that could be changed under a
        /// live chain would let whoever changed it decide keyless disputes.
        keyless_setup: u8,
    }

    /// Creates the dispute registry.
    ///
    /// `keyless_setup` must name the same parameter set as the L2 genesis
    /// (`keyless.setup`), or L1 would judge honest keyless transactions
    /// invalid.
    public entry fun initialize(admin: &signer, chain: address, keyless_setup: u8) {
        assert!(!exists<Registry>(signer::address_of(admin)), E_ALREADY_INITIALIZED);
        keyless::assert_known_setup(keyless_setup);
        move_to(admin, Registry {
            disputes: table::new<vector<u8>, Dispute>(),
            chain,
            keyless_setup,
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

    /// The id of the dispute a challenger plays over an assertion. One per
    /// (assertion, challenger), so a challenger cannot open several games and
    /// keep only the one it wins.
    public fun dispute_id(assertion: vector<u8>, challenger: address): vector<u8> {
        let id = assertion;
        vector::append(&mut id, bcs::to_bytes(&challenger));
        id
    }

    /// Opens a bisection game over an assertion the caller has challenged.
    ///
    /// Everything about the game is read from the assertion record: the
    /// defender is its proposer, the endpoints are its pre- and post-state at
    /// positions 0 and `trace_length`, and the clocks follow the chain's
    /// window. Taking any of it from the caller would let a challenger name a
    /// defender who never answers, win by timeout, and reject a sound
    /// assertion.
    public entry fun open(
        challenger: &signer,
        registry_addr: address,
        assertion: vector<u8>,
    ) acquires Registry {
        let who = signer::address_of(challenger);
        let chain_addr = borrow_global<Registry>(registry_addr).chain;
        let (proposer, pre_root, post_root, _, _, _, trace_length, status) =
            assertions::dispute_view(chain_addr, assertion);
        assert!(status == assertions::status_challenged(), E_NOT_CHALLENGED);
        assert!(assertions::has_open_challenge(chain_addr, assertion, who), E_NOT_CHALLENGING);
        assert!(trace_length > 0, E_EMPTY_TRACE);

        let budget = clock_budget(assertions::challenge_window(chain_addr));
        // A single move must never be given longer than the whole budget, or
        // one stall would exhaust it outright.
        let move_allowance = if (MOVE_TIMEOUT < budget) { MOVE_TIMEOUT } else { budget };
        let now = timestamp::now_seconds();
        let stage = if (trace_length == 1) { STAGE_ONE_STEP } else { STAGE_BISECTING };
        let turn = if (trace_length == 1) { PARTY_CHALLENGER } else { PARTY_DEFENDER };

        let registry = borrow_global_mut<Registry>(registry_addr);
        table::add(&mut registry.disputes, dispute_id(assertion, who), Dispute {
            assertion,
            defender: proposer,
            challenger: who,
            lo: 0,
            hi: trace_length,
            lo_commitment: osp::commit_machine_state(&osp::machine_state(pre_root, 0)),
            hi_commitment: osp::commit_machine_state(&osp::machine_state(post_root, trace_length)),
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
    ///
    /// A late move is refused, not recorded as a forfeit: an abort would revert
    /// any record of it anyway. The other party claims the forfeit with
    /// `claim_timeout` (REQ-FRAUD-014).
    fun begin_move(d: &mut Dispute, party: u8) {
        assert!(d.stage != STAGE_RESOLVED, E_RESOLVED);
        assert!(d.turn == party, E_WRONG_TURN);

        let now = timestamp::now_seconds();
        assert!(now <= d.deadline, E_DEADLINE_PASSED);

        // A per-move deadline alone would let an adversary stretch a dispute by
        // always answering at the last permitted moment; the total budget is
        // what bounds it below the challenge window.
        let elapsed = now - d.last_move_at;
        if (party == PARTY_DEFENDER) {
            assert!(elapsed <= d.defender_clock, E_DEADLINE_PASSED);
            d.defender_clock = d.defender_clock - elapsed;
        } else {
            assert!(elapsed <= d.challenger_clock, E_DEADLINE_PASSED);
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

    /// Settles a dispute that has narrowed to one step (REQ-FRAUD-017).
    ///
    /// The challenger proves which transaction covers step `lo` -- its bytes
    /// as a leaf of the batch the assertion published -- and supplies a
    /// witness for the slot it touches. L1 compiles the transaction itself to
    /// find the instruction, executes it against the agreed pre-state, and
    /// compares the result with the defender's claim.
    ///
    /// A transaction that does not compile at all means the batch is invalid,
    /// and the challenger wins. A leaf that does not prove, does not cover the
    /// step, or a witness that does not match the agreed state aborts: those are
    /// the prover's errors, and the clock keeps running.
    public entry fun one_step(
        mover: &signer,
        registry_addr: address,
        id: vector<u8>,
        leaf_index: u64,
        start_pc: u64,
        tx_bytes: vector<u8>,
        leaf_siblings: vector<vector<u8>>,
        pre_state_root: vector<u8>,
        slot: vector<u8>,
        present: bool,
        value: vector<u8>,
        trie_siblings: vector<vector<u8>>,
        terminal_is_leaf: bool,
        terminal_key: vector<u8>,
        terminal_value_hash: vector<u8>,
    ) acquires Registry {
        let who = signer::address_of(mover);
        let (chain_addr, keyless_setup) = {
            let r = borrow_global<Registry>(registry_addr);
            (r.chain, r.keyless_setup)
        };
        let (pc, lo_commitment, hi_commitment, assertion) = {
            let registry = borrow_global_mut<Registry>(registry_addr);
            assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
            let d = table::borrow_mut(&mut registry.disputes, id);
            assert!(party_of(d, who) == PARTY_CHALLENGER, E_WRONG_TURN);
            begin_move(d, PARTY_CHALLENGER);
            assert!(d.stage == STAGE_ONE_STEP, E_WRONG_STAGE);
            (d.lo, d.lo_commitment, d.hi_commitment, d.assertion)
        };

        let (_, _, _, batch_time, tx_count, tx_root, _, _) =
            assertions::dispute_view(chain_addr, assertion);
        assert!(
            batch::proves(tx_root, tx_count, leaf_index, start_pc, tx_bytes, &leaf_siblings),
            E_BAD_LEAF
        );

        let (compiles, program) = compiler::compile(tx_bytes, batch_time, keyless_setup);
        let winner = if (!compiles) {
            PARTY_CHALLENGER
        } else {
            assert!(
                start_pc <= pc && pc < start_pc + vector::length(&program),
                E_LEAF_DOES_NOT_COVER_STEP
            );
            let instruction = vector::borrow(&program, pc - start_pc);
            let terminal = if (terminal_is_leaf) {
                trie::leaf_terminal(terminal_key, terminal_value_hash)
            } else {
                trie::empty_terminal()
            };
            let proof = trie::new_proof(trie_siblings, terminal);
            let outcome = osp::adjudicate(
                &osp::machine_state(pre_state_root, pc),
                lo_commitment,
                hi_commitment,
                instruction,
                slot,
                present,
                value,
                &proof,
            );
            if (outcome == osp::challenger_wins()) { PARTY_CHALLENGER } else { PARTY_DEFENDER }
        };
        resolve_internal(registry_addr, id, winner);
    }

    // --- Batch-structure fraud proofs ----------------------------------------
    //
    // Bisection assumes every step is covered by exactly one transaction. A
    // batch that breaks that -- a transaction that does not compile, start
    // positions that skip or overlap steps, a trace longer or shorter than its
    // transactions -- is fraud of its own, proven directly from the published
    // data without a bisection game. Each proof requires an open challenge and
    // rejects the assertion when it holds.

    fun leaf_program(
        tx_root: vector<u8>,
        tx_count: u64,
        batch_time: u64,
        keyless_setup: u8,
        index: u64,
        start_pc: u64,
        tx_bytes: vector<u8>,
        siblings: &vector<vector<u8>>,
    ): (bool, u64) {
        assert!(batch::proves(tx_root, tx_count, index, start_pc, tx_bytes, siblings), E_BAD_LEAF);
        let (ok, program) = compiler::compile(tx_bytes, batch_time, keyless_setup);
        (ok, vector::length(&program))
    }

    fun apply_structural_win(registry_addr: address, chain_addr: address, assertion: vector<u8>, who: address) {
        assert!(assertions::has_open_challenge(chain_addr, assertion, who), E_NOT_CHALLENGING);
        assertions::challenger_won(chain_addr, assertion, who);
        // A bisection game the same challenger had open is now moot.
        let id = dispute_id(assertion, who);
        let registry = borrow_global_mut<Registry>(registry_addr);
        if (table::contains(&registry.disputes, id)) {
            let d = table::borrow_mut(&mut registry.disputes, id);
            d.stage = STAGE_RESOLVED;
            d.winner = PARTY_CHALLENGER;
        };
    }

    /// Proves that a published transaction does not compile.
    public entry fun prove_uncompilable(
        challenger: &signer,
        registry_addr: address,
        assertion: vector<u8>,
        index: u64,
        start_pc: u64,
        tx_bytes: vector<u8>,
        siblings: vector<vector<u8>>,
    ) acquires Registry {
        let who = signer::address_of(challenger);
        let (chain_addr, keyless_setup) = {
            let r = borrow_global<Registry>(registry_addr);
            (r.chain, r.keyless_setup)
        };
        let (_, _, _, batch_time, tx_count, tx_root, _, _) = assertions::dispute_view(chain_addr, assertion);
        let (ok, _) = leaf_program(tx_root, tx_count, batch_time, keyless_setup, index, start_pc, tx_bytes, &siblings);
        assert!(!ok, E_NOT_FRAUD);
        apply_structural_win(registry_addr, chain_addr, assertion, who);
    }

    /// Proves that transaction `index + 1` does not start where transaction
    /// `index` ends.
    public entry fun prove_start_gap(
        challenger: &signer,
        registry_addr: address,
        assertion: vector<u8>,
        index: u64,
        start_a: u64,
        tx_a: vector<u8>,
        siblings_a: vector<vector<u8>>,
        start_b: u64,
        tx_b: vector<u8>,
        siblings_b: vector<vector<u8>>,
    ) acquires Registry {
        let who = signer::address_of(challenger);
        let (chain_addr, keyless_setup) = {
            let r = borrow_global<Registry>(registry_addr);
            (r.chain, r.keyless_setup)
        };
        let (_, _, _, batch_time, tx_count, tx_root, _, _) = assertions::dispute_view(chain_addr, assertion);
        let (ok_a, len_a) = leaf_program(tx_root, tx_count, batch_time, keyless_setup, index, start_a, tx_a, &siblings_a);
        assert!(
            batch::proves(tx_root, tx_count, index + 1, start_b, tx_b, &siblings_b),
            E_BAD_LEAF
        );
        // An uncompilable transaction is fraud in itself.
        assert!(!ok_a || start_b != start_a + len_a, E_NOT_FRAUD);
        apply_structural_win(registry_addr, chain_addr, assertion, who);
    }

    /// Proves that the last transaction does not end where the trace does.
    public entry fun prove_trace_length(
        challenger: &signer,
        registry_addr: address,
        assertion: vector<u8>,
        start_pc: u64,
        tx_bytes: vector<u8>,
        siblings: vector<vector<u8>>,
    ) acquires Registry {
        let who = signer::address_of(challenger);
        let (chain_addr, keyless_setup) = {
            let r = borrow_global<Registry>(registry_addr);
            (r.chain, r.keyless_setup)
        };
        let (_, _, _, batch_time, tx_count, tx_root, trace_length, _) = assertions::dispute_view(chain_addr, assertion);
        assert!(tx_count > 0, E_NOT_FRAUD);
        let (ok, len) = leaf_program(
            tx_root, tx_count, batch_time, keyless_setup, tx_count - 1, start_pc, tx_bytes, &siblings
        );
        assert!(!ok || start_pc + len != trace_length, E_NOT_FRAUD);
        apply_structural_win(registry_addr, chain_addr, assertion, who);
    }

    /// Records the outcome of a game and applies it.
    ///
    /// Recording the winner without applying it would leave the assertion chain
    /// unaware of the result -- a fraudulent assertion could lose its dispute
    /// and still finalize. If the assertion has meanwhile been rejected by
    /// another challenger, the outcome is moot: every challenge bond on it was
    /// already refunded.
    fun resolve_internal(
        registry_addr: address,
        id: vector<u8>,
        winner: u8,
    ) acquires Registry {
        let (chain, assertion, challenger) = {
            let registry = borrow_global_mut<Registry>(registry_addr);
            assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
            let d = table::borrow_mut(&mut registry.disputes, id);
            assert!(d.stage != STAGE_RESOLVED, E_RESOLVED);
            d.stage = STAGE_RESOLVED;
            d.winner = winner;
            (registry.chain, d.assertion, d.challenger)
        };

        let (_, _, _, _, _, _, _, status) = assertions::dispute_view(chain, assertion);
        if (status == assertions::status_rejected()) { return };

        if (winner == PARTY_CHALLENGER) {
            assertions::challenger_won(chain, assertion, challenger);
        } else {
            assertions::defender_won(chain, assertion, challenger);
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
            let now = timestamp::now_seconds();
            let clock = if (d.turn == PARTY_DEFENDER) { d.defender_clock } else { d.challenger_clock };
            assert!(now > d.deadline || now - d.last_move_at > clock, E_WRONG_STAGE);
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

    #[view]
    public fun winner(registry_addr: address, id: vector<u8>): u8 acquires Registry {
        let registry = borrow_global<Registry>(registry_addr);
        assert!(table::contains(&registry.disputes, id), E_NO_SUCH_DISPUTE);
        let d = table::borrow(&registry.disputes, id);
        assert!(d.stage == STAGE_RESOLVED, E_WRONG_STAGE);
        d.winner
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
