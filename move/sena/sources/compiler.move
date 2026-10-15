/// Compiles a published transaction into instructions, as `sena_stf::compile`
/// does.
///
/// A dispute narrows to one step index; L1 must know which instruction sits
/// there without trusting either party to say. It decodes the transaction from
/// the batch data, authenticates it, and compiles it here. Compilation is a
/// pure function of the transaction and the batch header (timestamp, base fee,
/// tip recipient) plus the keyless setup, which is what makes this possible.
///
/// The fee follows Celo's fee abstraction (see `sena::gas`): the gas the
/// transaction uses is metered from its program, the base fee is converted
/// into the fee asset at the declared rate, `gas_limit ×` the effective price
/// is held before the payload runs, and the unused part is refunded, the tip
/// paid to the sequencer and the base fee to the fee vault afterwards.
///
/// `compile` returns `(false, _)` for a transaction the node would refuse. An
/// honest sequencer never publishes one, so its presence in a batch is fraud.
module sena::compiler {
    use std::option;
    use std::vector;
    use sena::gas;
    use sena::keyless;
    use sena::osp::{Self, Instruction};
    use sena::txcodec::{Self, Payload, Tx};

    const MAX_U64: u64 = 18446744073709551615;

    /// `execute::FEE_VAULT`: 32 bytes of 0xFE.
    const FEE_VAULT: vector<u8> = x"fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";

    fun authenticate(tx: &Tx, timestamp: u64, keyless_setup: u8, keyless_verdict: option::Option<bool>): bool {
        let digest = txcodec::signing_digest(tx);
        if (txcodec::is_ed25519(tx)) {
            // An Ed25519 account's address is its public key.
            let pk = txcodec::ed25519_public_key(tx);
            if (pk != txcodec::sender(tx)) { return false };
            keyless::verify_ed25519_strict(&pk, &txcodec::ed25519_signature(tx), &digest)
        } else {
            let sig = txcodec::keyless_signature(tx);
            if (option::is_none(&sig)) { return false };
            // A verdict computed in advance by `sena::keyless_jobs` for exactly
            // these bytes, this time and this setup; otherwise compute it now.
            if (option::is_some(&keyless_verdict)) { return *option::borrow(&keyless_verdict) };
            keyless::verify(keyless_setup, option::borrow(&sig), &txcodec::sender(tx), &digest, timestamp)
        }
    }

    /// Compiles transaction bytes. `(false, _)` if they do not decode, do not
    /// authenticate, or describe a transaction the node would refuse.
    public fun compile(
        tx_bytes: vector<u8>,
        timestamp: u64,
        base_fee: u128,
        fee_recipient: vector<u8>,
        keyless_setup: u8,
    ): (bool, vector<Instruction>) {
        compile_inner(tx_bytes, timestamp, base_fee, fee_recipient, keyless_setup, option::none())
    }

    /// `compile`, with a keyless transaction's authorisation verdict supplied
    /// by `sena::keyless_jobs` (whose job id binds it to these bytes, this
    /// timestamp and this setup) instead of recomputed in this transaction.
    public fun compile_with_keyless_verdict(
        tx_bytes: vector<u8>,
        timestamp: u64,
        base_fee: u128,
        fee_recipient: vector<u8>,
        keyless_setup: u8,
        verdict: bool,
    ): (bool, vector<Instruction>) {
        compile_inner(tx_bytes, timestamp, base_fee, fee_recipient, keyless_setup, option::some(verdict))
    }

    /// Whether the bytes decode to a keyless transaction.
    public fun is_keyless(tx_bytes: vector<u8>): bool {
        let decoded = txcodec::decode(tx_bytes);
        option::is_some(&decoded) && !txcodec::is_ed25519(option::borrow(&decoded))
    }

    /// The payload's instructions (`compile_payload`), or `(false, _)` for a
    /// payload the node refuses to compile.
    fun compile_payload(p: &Payload, sender: vector<u8>): (bool, vector<Instruction>) {
        let none = vector::empty<Instruction>();
        let out = vector::empty<Instruction>();
        if (txcodec::is_transfer(p)) {
            let to = txcodec::to(p);
            if (to == sender) { return (false, none) };
            vector::push_back(&mut out, osp::debit(sender, txcodec::asset(p), txcodec::amount(p)));
            vector::push_back(&mut out, osp::credit(to, txcodec::asset(p), txcodec::amount(p)));
        } else if (txcodec::is_bind(p)) {
            vector::push_back(&mut out, osp::bind_identifier(txcodec::identifier(p), sender));
        } else if (txcodec::is_unbind(p)) {
            vector::push_back(&mut out, osp::unbind_identifier(txcodec::identifier(p), sender));
        } else if (txcodec::is_distribute_fees(p)) {
            // `compile_distribution`: check the split, take the amount from
            // the vault, pay each beneficiary its share; the rest is burned.
            let split = txcodec::split(p);
            if (txcodec::amount(p) == 0 || !gas::split_is_valid(split)) { return (false, none) };
            let (ok, addresses, values) = gas::shares_of(split, txcodec::amount(p));
            if (!ok) { return (false, none) };
            vector::push_back(&mut out, osp::verify_fee_split(split));
            vector::push_back(&mut out, osp::debit(FEE_VAULT, txcodec::asset(p), txcodec::amount(p)));
            let i = 0;
            while (i < vector::length(&values)) {
                let value = *vector::borrow(&values, i);
                if (value > 0) {
                    vector::push_back(&mut out, osp::credit(*vector::borrow(&addresses, i), txcodec::asset(p), value));
                };
                i = i + 1;
            };
        } else {
            // Governance. `GovernanceUpdate::check_permitted` first.
            if (txcodec::is_set_parameter(p) && !osp::is_governable(&txcodec::text(p))) {
                return (false, none)
            };
            if (txcodec::is_set_gas_asset(p) && txcodec::rate_or_value(p) == 0) {
                return (false, none)
            };
            if (txcodec::is_set_fee_market(p) && (txcodec::rate_or_value(p) == 0 || txcodec::gas(p) == 0)) {
                return (false, none)
            };
            if (txcodec::is_set_fee_split(p) && !gas::split_is_valid(txcodec::split(p))) {
                return (false, none)
            };
            vector::push_back(&mut out, osp::verify_council(
                txcodec::epoch(p),
                txcodec::governance_digest(p),
                txcodec::signer_indices(p),
                txcodec::signatures(p),
                txcodec::is_disable_gas_asset(p),
            ));
            if (txcodec::is_set_gas_asset(p)) {
                vector::push_back(&mut out, osp::set_gas_asset(
                    txcodec::record_asset(p), txcodec::text(p), txcodec::rate_or_value(p), txcodec::gas(p),
                    txcodec::flag(p)
                ));
            } else if (txcodec::is_set_parameter(p)) {
                vector::push_back(&mut out, osp::set_parameter(txcodec::text(p), txcodec::rate_or_value(p)));
            } else if (txcodec::is_set_jwk(p)) {
                vector::push_back(&mut out, osp::set_jwk(txcodec::iss_hash(p), txcodec::jwk_hash(p), txcodec::flag(p)));
            } else if (txcodec::is_set_fee_market(p)) {
                vector::push_back(&mut out, osp::set_fee_market(txcodec::rate_or_value(p), txcodec::gas(p)));
            } else if (txcodec::is_set_fee_split(p)) {
                vector::push_back(&mut out, osp::set_fee_split(txcodec::split(p)));
            } else {
                vector::push_back(&mut out, osp::disable_gas_asset(txcodec::record_asset(p)));
            };
        };
        (true, out)
    }

    /// `gas::gas_used`: intrinsic gas, the asset's declared intrinsic gas, the
    /// authenticator's, and the payload's. `(false, _)` on overflow.
    fun gas_used(tx: &Tx, payload: &vector<Instruction>): (bool, u64) {
        let total = gas::intrinsic_gas();
        let declared = txcodec::fee_intrinsic_gas(tx);
        if (declared > MAX_U64 - total) { return (false, 0) };
        total = total + declared;
        if (!txcodec::is_ed25519(tx)) {
            if (gas::keyless_gas() > MAX_U64 - total) { return (false, 0) };
            total = total + gas::keyless_gas();
        };
        let i = 0;
        while (i < vector::length(payload)) {
            let g = osp::instruction_gas(vector::borrow(payload, i));
            if (g > MAX_U64 - total) { return (false, 0) };
            total = total + g;
            i = i + 1;
        };
        (true, total)
    }

    fun compile_inner(
        tx_bytes: vector<u8>,
        timestamp: u64,
        base_fee: u128,
        fee_recipient: vector<u8>,
        keyless_setup: u8,
        keyless_verdict: option::Option<bool>,
    ): (bool, vector<Instruction>) {
        let none = vector::empty<Instruction>();
        let decoded = txcodec::decode(tx_bytes);
        if (option::is_none(&decoded)) { return (false, none) };
        let tx = option::extract(&mut decoded);

        if (!authenticate(&tx, timestamp, keyless_setup, keyless_verdict)) { return (false, none) };

        let sender = txcodec::sender(&tx);
        let (payload_ok, payload) = compile_payload(txcodec::payload(&tx), sender);
        if (!payload_ok) { return (false, none) };
        let (gas_ok, used) = gas_used(&tx, &payload);
        if (!gas_ok) { return (false, none) };
        let (fee_ok, hold, refund, tip, base) = gas::settle(
            txcodec::gas_limit(&tx),
            used,
            txcodec::max_fee_per_gas(&tx),
            txcodec::max_priority_fee_per_gas(&tx),
            base_fee,
            txcodec::fee_rate(&tx),
        );
        if (!fee_ok) { return (false, none) };

        let asset = txcodec::fee_asset(&tx);
        let out = vector::empty<Instruction>();
        let sig = txcodec::keyless_signature(&tx);
        if (option::is_some(&sig)) {
            let s = option::borrow(&sig);
            vector::push_back(&mut out, osp::verify_jwk(keyless::iss_hash(s), keyless::jwk_hash(s)));
        };
        vector::push_back(&mut out, osp::consume_nonce(sender, txcodec::nonce(&tx)));
        vector::push_back(&mut out, osp::verify_gas_asset(
            asset, txcodec::fee_rate(&tx), txcodec::fee_intrinsic_gas(&tx)
        ));
        vector::push_back(&mut out, osp::charge_base_fee(timestamp, base_fee, used));
        vector::push_back(&mut out, osp::debit(sender, asset, hold));
        vector::append(&mut out, payload);
        // Celo's creditGasFees, which never credits a zero amount.
        if (refund > 0) { vector::push_back(&mut out, osp::credit(sender, asset, refund)) };
        if (tip > 0) { vector::push_back(&mut out, osp::credit(fee_recipient, asset, tip)) };
        if (base > 0) { vector::push_back(&mut out, osp::credit(FEE_VAULT, asset, base)) };
        (true, out)
    }
}
