/// Compiles a published transaction into instructions, as `sena_stf::compile`
/// does.
///
/// A dispute narrows to one step index; L1 must know which instruction sits
/// there without trusting either party to say. It decodes the transaction from
/// the batch data, authenticates it, and compiles it here. Compilation is a
/// pure function of the transaction and the batch header (timestamp, base fee,
/// tip recipient) plus the keyless setup, which is what makes this possible.
///
/// `chain_id` is the chain the contracts were initialised for: a transaction
/// signed for another SENA network does not compile here, as in the node.
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
    use sena::deposits;
    use sena::gas;
    use sena::keyless;
    use sena::osp::{Self, Instruction};
    use sena::txcodec::{Self, Payload, Tx};

    const MAX_U64: u64 = 18446744073709551615;

    /// `execute::FEE_VAULT`: 32 bytes of 0xFE.
    const FEE_VAULT: vector<u8> = x"fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";

    /// `execute::DEPOSIT_SENDER`: 32 bytes of 0xD0.
    const DEPOSIT_SENDER: vector<u8> = x"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

    /// `compile_deposit`: the canonical deposit transaction for a deposit the
    /// chain's L1 log holds exactly as claimed, compiled to advancing the
    /// deposit cursor and crediting the recipient. Read from L1 state, not L2:
    /// the log is append-only, so every party sees the same entry.
    fun compile_deposit(tx: &Tx, chain: address): (bool, vector<Instruction>) {
        let none = vector::empty<Instruction>();
        let p = txcodec::payload(tx);
        if (!txcodec::is_deposit(p)) { return (false, none) };
        let canonical = txcodec::sender(tx) == DEPOSIT_SENDER
            && txcodec::nonce(tx) == 0
            && txcodec::fee_asset(tx) == 0
            && txcodec::fee_rate(tx) == 0
            && txcodec::fee_intrinsic_gas(tx) == 0
            && txcodec::gas_limit(tx) == 0
            && txcodec::max_fee_per_gas(tx) == 0
            && txcodec::max_priority_fee_per_gas(tx) == 0
            && txcodec::is_ed25519(tx)
            && txcodec::ed25519_public_key(tx) == zeros(32)
            && txcodec::ed25519_signature(tx) == zeros(64);
        if (!canonical || txcodec::amount(p) == 0) { return (false, none) };
        let id = txcodec::deposit_id(p);
        if (!deposits::matches(chain, id, txcodec::to(p), txcodec::asset(p), txcodec::amount(p))) {
            return (false, none)
        };
        let out = vector::empty<Instruction>();
        vector::push_back(&mut out, osp::consume_deposit(id));
        vector::push_back(&mut out, osp::credit(txcodec::to(p), txcodec::asset(p), txcodec::amount(p)));
        (true, out)
    }

    fun zeros(n: u64): vector<u8> {
        let v = vector::empty<u8>();
        while (vector::length(&v) < n) { vector::push_back(&mut v, 0) };
        v
    }

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
    ///
    /// `chain` is the assertion chain whose L1 deposit log a deposit
    /// transaction is checked against.
    public fun compile(
        tx_bytes: vector<u8>,
        timestamp: u64,
        base_fee: u128,
        fee_recipient: vector<u8>,
        keyless_setup: u8,
        chain_id: u64,
        chain: address,
    ): (bool, vector<Instruction>) {
        compile_inner(tx_bytes, timestamp, base_fee, fee_recipient, keyless_setup, chain_id, option::none(), chain)
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
        chain_id: u64,
        verdict: bool,
        chain: address,
    ): (bool, vector<Instruction>) {
        compile_inner(tx_bytes, timestamp, base_fee, fee_recipient, keyless_setup, chain_id, option::some(verdict), chain)
    }

    /// Whether the bytes decode to a keyless transaction.
    public fun is_keyless(tx_bytes: vector<u8>): bool {
        let decoded = txcodec::decode(tx_bytes);
        option::is_some(&decoded) && !txcodec::is_ed25519(option::borrow(&decoded))
    }

    /// The payload's instructions (`compile_payload`), or `(false, _)` for a
    /// payload the node refuses to compile.
    fun compile_payload(
        p: &Payload, sender: vector<u8>, chain_id: u64, nonce: u64, timestamp: u64
    ): (bool, vector<Instruction>) {
        let none = vector::empty<Instruction>();
        let out = vector::empty<Instruction>();
        if (txcodec::is_transfer(p)) {
            let to = txcodec::to(p);
            if (to == sender) { return (false, none) };
            vector::push_back(&mut out, osp::debit(sender, txcodec::asset(p), txcodec::amount(p)));
            vector::push_back(&mut out, osp::credit(to, txcodec::asset(p), txcodec::amount(p)));
        } else if (txcodec::is_register_attestation(p)) {
            // The attested account consents by submitting it, or the issuer
            // vouches by submitting it itself.
            let issuer = txcodec::issuer(p);
            if (sender != txcodec::account(p) && sender != issuer) { return (false, none) };
            // Stateless, so checked here, as the sender's own signature is: the
            // issuer's Ed25519 key is its address.
            if (!keyless::verify_ed25519_strict(
                &issuer,
                &txcodec::attestation_signature(p),
                &txcodec::attestation_digest(p, chain_id),
            )) { return (false, none) };
            vector::push_back(&mut out, osp::set_attestation(
                txcodec::identifier(p), issuer, txcodec::account(p), txcodec::issued_on(p)
            ));
        } else if (txcodec::is_revoke_attestation(p)) {
            vector::push_back(&mut out, osp::revoke_attestation(
                txcodec::identifier(p), txcodec::issuer(p), sender
            ));
        } else if (txcodec::is_deposit(p)) {
            // Only the deposit transaction itself may carry one.
            return (false, none)
        } else if (txcodec::is_escrow_send(p)) {
            // `compile_escrow`, send: debit and open, unexpired at batch time.
            let expires_at = txcodec::epoch(p);
            if (txcodec::amount(p) == 0 || expires_at <= timestamp) { return (false, none) };
            vector::push_back(&mut out, osp::debit(sender, txcodec::asset(p), txcodec::amount(p)));
            vector::push_back(&mut out, osp::create_escrow(sender, nonce, osp::encode_escrow(
                false, txcodec::identifier(p), txcodec::issuer(p), txcodec::asset(p), txcodec::amount(p), expires_at
            )));
        } else if (txcodec::is_escrow_claim(p) || txcodec::is_escrow_refund(p)) {
            // `compile_escrow`, claim or refund.
            let refund = txcodec::is_escrow_refund(p);
            let record = txcodec::split(p);
            let (_, released, identifier, issuer, asset, amount, _) = osp::decode_escrow(record);
            if (released || amount == 0 || (refund && txcodec::to(p) != sender)) { return (false, none) };
            if (!refund) {
                vector::push_back(&mut out, osp::verify_attestation(identifier, issuer, sender));
            };
            vector::push_back(&mut out, osp::release_escrow(txcodec::to(p), txcodec::epoch(p), record, timestamp, refund));
            vector::push_back(&mut out, osp::credit(sender, asset, amount));
        } else if (txcodec::is_withdraw(p)) {
            // Burned here, recorded for `bridge::claim` on L1.
            if (txcodec::amount(p) == 0) { return (false, none) };
            vector::push_back(&mut out, osp::debit(sender, txcodec::asset(p), txcodec::amount(p)));
            vector::push_back(&mut out, osp::record_withdrawal(
                sender, nonce, txcodec::to(p), txcodec::asset(p), txcodec::amount(p)
            ));
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
                txcodec::governance_digest(p, chain_id),
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
        chain_id: u64,
        keyless_verdict: option::Option<bool>,
        chain: address,
    ): (bool, vector<Instruction>) {
        let none = vector::empty<Instruction>();
        let decoded = txcodec::decode(tx_bytes);
        if (option::is_none(&decoded)) { return (false, none) };
        let tx = option::extract(&mut decoded);
        if (txcodec::chain_id(&tx) != chain_id) { return (false, none) };

        // A deposit is valid by the L1 log, not a signature, and pays no fee.
        if (txcodec::is_deposit(txcodec::payload(&tx)) || txcodec::sender(&tx) == DEPOSIT_SENDER) {
            return compile_deposit(&tx, chain)
        };

        if (!authenticate(&tx, timestamp, keyless_setup, keyless_verdict)) { return (false, none) };

        let sender = txcodec::sender(&tx);
        let (payload_ok, payload) = compile_payload(
            txcodec::payload(&tx), sender, chain_id, txcodec::nonce(&tx), timestamp
        );
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
        // The fee is held before the payload runs, except for a claim, which
        // pays from the escrow it claims (`compile`, in Rust).
        if (txcodec::is_escrow_claim(txcodec::payload(&tx))) {
            vector::append(&mut out, payload);
            vector::push_back(&mut out, osp::debit(sender, asset, hold));
        } else {
            vector::push_back(&mut out, osp::debit(sender, asset, hold));
            vector::append(&mut out, payload);
        };
        // Celo's creditGasFees, which never credits a zero amount.
        if (refund > 0) { vector::push_back(&mut out, osp::credit(sender, asset, refund)) };
        if (tip > 0) { vector::push_back(&mut out, osp::credit(fee_recipient, asset, tip)) };
        if (base > 0) { vector::push_back(&mut out, osp::credit(FEE_VAULT, asset, base)) };
        (true, out)
    }
}
