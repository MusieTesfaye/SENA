/// The one-step verifier: where a dispute is actually decided.
///
/// Bisection has narrowed the disagreement to a single step. Both parties agree
/// on the state going in; they disagree on the state coming out. This module
/// executes that one step and sees who was right (REQ-FRAUD-017).
///
/// It is the highest-value target in the system. If its semantics diverge from
/// `sena-stf`, it decides disputes wrongly -- slashing an honest sequencer or
/// vindicating a fraudulent one -- so every rule here mirrors `transition()` in
/// `crates/sena-stf/src/execute.rs`, and the account codec mirrors
/// `crates/sena-stf/src/account.rs`.
module sena::osp {
    use std::vector;
    use sena::codec;
    use sena::trie;

    /// The witness described a slot the instruction does not touch.
    const E_WITNESS_SLOT_MISMATCH: u64 = 20;
    /// The account's nonce did not match the transaction's.
    const E_NONCE_MISMATCH: u64 = 21;
    /// The account cannot cover the debit.
    const E_INSUFFICIENT: u64 = 22;
    /// A credit would exceed the representable range.
    const E_OVERFLOW: u64 = 23;
    /// The identifier is already bound to another address.
    const E_IDENTIFIER_TAKEN: u64 = 24;
    /// The identifier is not held by the address releasing it.
    const E_IDENTIFIER_NOT_HELD: u64 = 25;
    /// The instruction kind is not adjudicable by this module yet.
    const E_UNSUPPORTED_INSTRUCTION: u64 = 26;
    /// The proof did not describe the state both parties agreed on.
    const E_PRE_STATE_MISMATCH: u64 = 27;

    // Instruction discriminants, matching the Rust `Instruction` enum order.
    const OP_CONSUME_NONCE: u8 = 0;
    const OP_DEBIT: u8 = 1;
    const OP_CREDIT: u8 = 2;
    const OP_BIND_IDENTIFIER: u8 = 3;
    const OP_UNBIND_IDENTIFIER: u8 = 4;

    const TAG_BOUND: u8 = 0;
    const TAG_VACANT: u8 = 1;

    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    /// One decoded account balance entry.
    struct Balance has copy, drop, store {
        asset: u32,
        amount: u128,
    }

    /// An account as stored in the trie.
    struct Account has copy, drop, store {
        nonce: u64,
        balances: vector<Balance>,
    }

    /// The instruction under dispute, as L1 derives it from batch data.
    ///
    /// The challenger does not supply this. If they could name the instruction
    /// at the disputed index they would simply choose one that fails.
    struct Instruction has copy, drop, store {
        op: u8,
        /// Account or identifier the step touches, as a 32-byte value.
        subject: vector<u8>,
        asset: u32,
        amount: u128,
        nonce: u64,
    }

    /// The machine state between two steps.
    struct MachineState has copy, drop, store {
        state_root: vector<u8>,
        pc: u64,
    }

    public fun machine_state(state_root: vector<u8>, pc: u64): MachineState {
        MachineState { state_root, pc }
    }

    /// Commits to a machine state.
    ///
    /// Both the root and the program counter are committed: committing only the
    /// root would let a party claim the same state at a different trace
    /// position, which is the ambiguity bisection exists to remove.
    public fun commit_machine_state(s: &MachineState): vector<u8> {
        let buf = codec::begin(codec::domain_machine_state());
        codec::put_field(&mut buf, s.state_root);
        let pc_field = vector::empty<u8>();
        codec::put_u64(&mut pc_field, s.pc);
        codec::put_field(&mut buf, pc_field);
        codec::commit(buf)
    }

    // --- Account codec -------------------------------------------------------

    /// Decodes a stored account, rejecting non-canonical encodings.
    ///
    /// Entries must be in strictly ascending asset order with no zero balances.
    /// Tolerating either would give one account state two valid encodings, and
    /// the trie commits to bytes rather than to meaning.
    public fun decode_account(bytes: vector<u8>): Account {
        let r = codec::reader(bytes);
        let nonce = codec::take_u64(&mut r);
        let count = codec::take_u32(&mut r);

        let balances = vector::empty<Balance>();
        let i: u32 = 0;
        let previous: u64 = 0;
        let seen = false;
        while (i < count) {
            let asset = codec::take_u32(&mut r);
            let amount = codec::take_u128(&mut r);
            assert!(amount > 0, codec::error_not_canonical());
            if (seen) {
                assert!((asset as u64) > previous, codec::error_not_canonical());
            };
            previous = (asset as u64);
            seen = true;
            vector::push_back(&mut balances, Balance { asset, amount });
            i = i + 1;
        };
        codec::finish(&r);
        Account { nonce, balances }
    }

    /// Encodes an account, pruning zero balances.
    public fun encode_account(a: &Account): vector<u8> {
        let buf = vector::empty<u8>();
        codec::put_u64(&mut buf, a.nonce);

        let kept = vector::empty<Balance>();
        let i = 0;
        while (i < vector::length(&a.balances)) {
            let b = *vector::borrow(&a.balances, i);
            if (b.amount > 0) { vector::push_back(&mut kept, b) };
            i = i + 1;
        };

        codec::put_u32(&mut buf, (vector::length(&kept) as u32));
        let j = 0;
        while (j < vector::length(&kept)) {
            let b = *vector::borrow(&kept, j);
            codec::put_u32(&mut buf, b.asset);
            codec::put_u128(&mut buf, b.amount);
            j = j + 1;
        };
        buf
    }

    /// An account that has never been touched: zero nonce, no balances.
    ///
    /// Crediting a fresh address is how every account comes into existence, so
    /// an empty slot is not an error.
    public fun empty_account(): Account {
        Account { nonce: 0, balances: vector::empty<Balance>() }
    }

    /// Returns an account's balance in an asset.
    ///
    /// Public so the bridge can read a proven account's balance rather than
    /// taking the withdrawal amount as an argument, which would make the proof
    /// decorative.
    public fun account_balance(a: &Account, asset: u32): u128 {
        balance_of(a, asset)
    }

    fun balance_of(a: &Account, asset: u32): u128 {
        let i = 0;
        while (i < vector::length(&a.balances)) {
            let b = vector::borrow(&a.balances, i);
            if (b.asset == asset) { return b.amount };
            i = i + 1;
        };
        0
    }

    /// Sets a balance, keeping entries in ascending asset order.
    fun set_balance(a: &mut Account, asset: u32, amount: u128) {
        let i = 0;
        let len = vector::length(&a.balances);
        while (i < len) {
            let b = vector::borrow(&a.balances, i);
            if (b.asset == asset) {
                if (amount == 0) {
                    vector::remove(&mut a.balances, i);
                } else {
                    vector::borrow_mut(&mut a.balances, i).amount = amount;
                };
                return
            };
            if (b.asset > asset) { break };
            i = i + 1;
        };
        if (amount > 0) {
            vector::insert(&mut a.balances, i, Balance { asset, amount });
        };
    }

    // --- Step semantics ------------------------------------------------------

    /// Applies one instruction to a slot's contents, returning the new contents.
    ///
    /// Mirrors `sena_stf::transition`. `present` distinguishes an empty slot
    /// from a slot holding empty bytes.
    public fun transition(
        instruction: &Instruction,
        present: bool,
        current: vector<u8>,
    ): vector<u8> {
        if (instruction.op == OP_CONSUME_NONCE) {
            let a = if (present) { decode_account(current) } else { empty_account() };
            assert!(a.nonce == instruction.nonce, E_NONCE_MISMATCH);
            // Checked: a wrap would silently re-enable every used nonce.
            assert!(a.nonce < 18446744073709551615, E_OVERFLOW);
            a.nonce = a.nonce + 1;
            encode_account(&a)
        } else if (instruction.op == OP_DEBIT) {
            let a = if (present) { decode_account(current) } else { empty_account() };
            if (instruction.amount > 0) {
                let held = balance_of(&a, instruction.asset);
                assert!(held >= instruction.amount, E_INSUFFICIENT);
                set_balance(&mut a, instruction.asset, held - instruction.amount);
            };
            encode_account(&a)
        } else if (instruction.op == OP_CREDIT) {
            let a = if (present) { decode_account(current) } else { empty_account() };
            if (instruction.amount > 0) {
                let held = balance_of(&a, instruction.asset);
                assert!(MAX_U128 - held >= instruction.amount, E_OVERFLOW);
                set_balance(&mut a, instruction.asset, held + instruction.amount);
            };
            encode_account(&a)
        } else if (instruction.op == OP_BIND_IDENTIFIER) {
            if (present) {
                let r = codec::reader(current);
                let tag = codec::take_u8(&mut r);
                if (tag == TAG_BOUND) {
                    let holder = codec::take_bytes(&mut r, 32);
                    codec::finish(&r);
                    // Re-binding to the same address is idempotent; taking
                    // someone else's identifier is not permitted.
                    assert!(holder == instruction.subject, E_IDENTIFIER_TAKEN);
                } else {
                    assert!(tag == TAG_VACANT, codec::error_unknown_variant());
                    codec::finish(&r);
                };
            };
            let out = vector::empty<u8>();
            vector::push_back(&mut out, TAG_BOUND);
            vector::append(&mut out, instruction.subject);
            out
        } else if (instruction.op == OP_UNBIND_IDENTIFIER) {
            assert!(present, E_IDENTIFIER_NOT_HELD);
            let r = codec::reader(current);
            let tag = codec::take_u8(&mut r);
            assert!(tag == TAG_BOUND, E_IDENTIFIER_NOT_HELD);
            let holder = codec::take_bytes(&mut r, 32);
            codec::finish(&r);
            assert!(holder == instruction.subject, E_IDENTIFIER_NOT_HELD);
            // Overwritten with a vacant marker rather than removed: removal can
            // require collapsing a branch, whose shape the proof does not
            // describe.
            let out = vector::empty<u8>();
            vector::push_back(&mut out, TAG_VACANT);
            out
        } else {
            // VerifyGasAsset and VerifyCouncil are not yet adjudicable here.
            // They are rejected outright rather than approximated, because a
            // verifier that guesses is worse than one that declines.
            abort E_UNSUPPORTED_INSTRUCTION
        }
    }

    /// Verifies one step and returns the machine state honest execution produces.
    ///
    /// The witness is checked before it is trusted: it must describe the slot
    /// the instruction touches, and its claimed contents must prove against the
    /// pre-state root.
    public fun verify_step(
        pre: &MachineState,
        instruction: &Instruction,
        slot: vector<u8>,
        expected_slot: vector<u8>,
        present: bool,
        value: vector<u8>,
        proof: &trie::Proof,
    ): MachineState {
        assert!(slot == expected_slot, E_WITNESS_SLOT_MISMATCH);

        if (present) {
            trie::verify_inclusion(proof, pre.state_root, slot, trie::hash_value(value));
        } else {
            trie::verify_non_inclusion(proof, pre.state_root, slot);
        };

        let updated = transition(instruction, present, value);
        let post_root = trie::compute_updated_root(proof, slot, trie::hash_value(updated));
        MachineState { state_root: post_root, pc: pre.pc + 1 }
    }

    /// Settles a dispute narrowed to one step.
    ///
    /// Returns true if the defender's claim survives.
    ///
    /// A failure to execute is *not* automatically fraud: the witness comes from
    /// the challenger. A witness that does not prove against the agreed
    /// pre-state aborts inside `verify_step` and loses the challenger the
    /// dispute; a witness that proves and is then followed by a step that
    /// cannot execute is fraud. The caller distinguishes the two by which abort
    /// code is raised.
    public fun adjudicate(
        pre: &MachineState,
        agreed_pre_commitment: vector<u8>,
        claimed_post_commitment: vector<u8>,
        instruction: &Instruction,
        slot: vector<u8>,
        expected_slot: vector<u8>,
        present: bool,
        value: vector<u8>,
        proof: &trie::Proof,
    ): bool {
        assert!(commit_machine_state(pre) == agreed_pre_commitment, E_PRE_STATE_MISMATCH);
        let post = verify_step(pre, instruction, slot, expected_slot, present, value, proof);
        commit_machine_state(&post) == claimed_post_commitment
    }

    public fun instruction(
        op: u8,
        subject: vector<u8>,
        asset: u32,
        amount: u128,
        nonce: u64,
    ): Instruction {
        Instruction { op, subject, asset, amount, nonce }
    }

    public fun op_consume_nonce(): u8 { OP_CONSUME_NONCE }
    public fun op_debit(): u8 { OP_DEBIT }
    public fun op_credit(): u8 { OP_CREDIT }
    public fun op_bind_identifier(): u8 { OP_BIND_IDENTIFIER }
    public fun op_unbind_identifier(): u8 { OP_UNBIND_IDENTIFIER }

    // --- Conformance tests ---------------------------------------------------

    #[test]
    fun empty_account_encoding_matches_rust() {
        assert!(encode_account(&empty_account()) == x"000000000000000000000000", 0);
    }

    #[test]
    fun funded_account_encoding_matches_rust() {
        // account{nonce: 5, asset 1 -> 1000, asset 7 -> 42}
        let a = empty_account();
        a.nonce = 5;
        set_balance(&mut a, 1, 1000);
        set_balance(&mut a, 7, 42);
        assert!(
            encode_account(&a)
                == x"00000000000000050000000200000001000000000000000000000000000003e8000000070000000000000000000000000000002a",
            0
        );
    }

    #[test]
    fun account_decoding_round_trips() {
        let bytes = x"00000000000000050000000200000001000000000000000000000000000003e8000000070000000000000000000000000000002a";
        let a = decode_account(bytes);
        assert!(a.nonce == 5, 0);
        assert!(balance_of(&a, 1) == 1000, 1);
        assert!(balance_of(&a, 7) == 42, 2);
        assert!(encode_account(&a) == bytes, 3);
    }

    #[test]
    // The abort originates where the `assert!` is, which is this module --
    // borrowing the error code from `codec` does not move the abort there.
    #[expected_failure(abort_code = 4, location = Self)]
    fun out_of_order_balances_are_rejected() {
        // asset 9 before asset 1: a second encoding of one account state.
        decode_account(x"00000000000000000000000200000009000000000000000000000000000000010000000100000000000000000000000000000001");
    }

    #[test]
    fun machine_commitment_matches_rust() {
        let root = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut root, 0x55); i = i + 1; };
        let s = machine_state(root, 7);
        assert!(
            commit_machine_state(&s)
                == x"76acaa5e43222dde525837b3bdcd9495097c4a5ed4a0b11c98a23b02c5508569",
            0
        );
    }

    #[test]
    fun commitment_distinguishes_trace_position() {
        let root = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut root, 0x55); i = i + 1; };
        let a = machine_state(root, 4);
        let b = machine_state(root, 5);
        assert!(commit_machine_state(&a) != commit_machine_state(&b), 0);
    }

    #[test]
    fun crediting_a_fresh_account_creates_it() {
        let instr = instruction(OP_CREDIT, vector::empty(), 1, 500, 0);
        let out = transition(&instr, false, vector::empty());
        let a = decode_account(out);
        assert!(a.nonce == 0, 0);
        assert!(balance_of(&a, 1) == 500, 1);
    }

    #[test]
    fun spending_to_zero_equals_never_having_held() {
        let credit = instruction(OP_CREDIT, vector::empty(), 1, 100, 0);
        let funded = transition(&credit, false, vector::empty());
        let debit = instruction(OP_DEBIT, vector::empty(), 1, 100, 0);
        let spent = transition(&debit, true, funded);
        assert!(spent == encode_account(&empty_account()), 0);
    }

    #[test]
    #[expected_failure(abort_code = E_INSUFFICIENT)]
    fun debiting_beyond_the_balance_aborts() {
        let credit = instruction(OP_CREDIT, vector::empty(), 1, 100, 0);
        let funded = transition(&credit, false, vector::empty());
        let debit = instruction(OP_DEBIT, vector::empty(), 1, 1000000, 0);
        transition(&debit, true, funded);
    }

    #[test]
    #[expected_failure(abort_code = E_NONCE_MISMATCH)]
    fun a_replayed_nonce_aborts() {
        let bump = instruction(OP_CONSUME_NONCE, vector::empty(), 0, 0, 0);
        let after = transition(&bump, false, vector::empty());
        // Replaying nonce 0 against an account now at nonce 1.
        transition(&bump, true, after);
    }

    #[test]
    #[expected_failure(abort_code = E_IDENTIFIER_TAKEN)]
    fun an_identifier_cannot_be_taken_from_its_holder() {
        let alice = vector::empty<u8>();
        let mallory = vector::empty<u8>();
        let i = 0;
        while (i < 32) {
            vector::push_back(&mut alice, 0x01);
            vector::push_back(&mut mallory, 0x02);
            i = i + 1;
        };
        let bind_alice = instruction(OP_BIND_IDENTIFIER, alice, 0, 0, 0);
        let bound = transition(&bind_alice, false, vector::empty());
        let bind_mallory = instruction(OP_BIND_IDENTIFIER, mallory, 0, 0, 0);
        transition(&bind_mallory, true, bound);
    }

    #[test]
    fun releasing_an_identifier_leaves_a_vacant_marker() {
        let alice = vector::empty<u8>();
        let i = 0;
        while (i < 32) { vector::push_back(&mut alice, 0x01); i = i + 1; };
        let bind = instruction(OP_BIND_IDENTIFIER, alice, 0, 0, 0);
        let bound = transition(&bind, false, vector::empty());
        let unbind = instruction(OP_UNBIND_IDENTIFIER, alice, 0, 0, 0);
        let released = transition(&unbind, true, bound);
        assert!(vector::length(&released) == 1, 0);
        assert!(*vector::borrow(&released, 0) == TAG_VACANT, 1);
    }

    #[test]
    #[expected_failure(abort_code = E_UNSUPPORTED_INSTRUCTION)]
    fun an_unsupported_instruction_is_refused_rather_than_guessed() {
        let instr = instruction(99, vector::empty(), 0, 0, 0);
        transition(&instr, false, vector::empty());
    }
}
