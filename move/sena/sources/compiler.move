/// Compiles a published transaction into instructions, as `sena_stf::compile`
/// does.
///
/// A dispute narrows to one step index; L1 must know which instruction sits
/// there without trusting either party to say. It decodes the transaction from
/// the batch data, authenticates it, and compiles it here. Compilation is a
/// pure function of the transaction and the batch context (timestamp, keyless
/// setup), which is what makes this possible.
///
/// `compile` returns `(false, _)` for a transaction the node would refuse. An
/// honest sequencer never publishes one, so its presence in a batch is fraud.
module sena::compiler {
    use std::option;
    use std::vector;
    use sena::keyless;
    use sena::osp::{Self, Instruction};
    use sena::txcodec::{Self, Tx};

    /// `gas::BASE_GAS_NATIVE`.
    const BASE_GAS_NATIVE: u128 = 1000;
    /// `gas::RATE_SCALE`.
    const RATE_SCALE: u128 = 1000000;
    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    /// `execute::FEE_VAULT`: 32 bytes of 0xFE.
    const FEE_VAULT: vector<u8> = x"fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";

    /// The fee in a gas asset, rounded up (`gas::convert`). `(false, _)` for a
    /// zero rate or on overflow.
    public fun fee_for(rate: u128): (bool, u128) {
        if (rate == 0) { return (false, 0) };
        if (rate > MAX_U128 / BASE_GAS_NATIVE) { return (false, 0) };
        let scaled = BASE_GAS_NATIVE * rate;
        if (scaled > MAX_U128 - (RATE_SCALE - 1)) { return (false, 0) };
        (true, (scaled + RATE_SCALE - 1) / RATE_SCALE)
    }

    fun authenticate(tx: &Tx, timestamp: u64, keyless_setup: u8): bool {
        let digest = txcodec::signing_digest(tx);
        if (txcodec::is_ed25519(tx)) {
            // An Ed25519 account's address is its public key.
            let pk = txcodec::ed25519_public_key(tx);
            if (pk != txcodec::sender(tx)) { return false };
            keyless::verify_ed25519_strict(&pk, &txcodec::ed25519_signature(tx), &digest)
        } else {
            let sig = txcodec::keyless_signature(tx);
            if (option::is_none(&sig)) { return false };
            keyless::verify(keyless_setup, option::borrow(&sig), &txcodec::sender(tx), &digest, timestamp)
        }
    }

    /// Compiles transaction bytes. `(false, _)` if they do not decode, do not
    /// authenticate, or describe a transaction the node would refuse.
    public fun compile(tx_bytes: vector<u8>, timestamp: u64, keyless_setup: u8): (bool, vector<Instruction>) {
        let none = vector::empty<Instruction>();
        let decoded = txcodec::decode(tx_bytes);
        if (option::is_none(&decoded)) { return (false, none) };
        let tx = option::extract(&mut decoded);

        if (!authenticate(&tx, timestamp, keyless_setup)) { return (false, none) };

        let (fee_ok, fee) = fee_for(txcodec::fee_rate(&tx));
        if (!fee_ok || txcodec::max_fee(&tx) < fee) { return (false, none) };

        let sender = txcodec::sender(&tx);
        let fee_asset = txcodec::fee_asset(&tx);
        let out = vector::empty<Instruction>();
        let sig = txcodec::keyless_signature(&tx);
        if (option::is_some(&sig)) {
            let s = option::borrow(&sig);
            vector::push_back(&mut out, osp::verify_jwk(keyless::iss_hash(s), keyless::jwk_hash(s)));
        };
        vector::push_back(&mut out, osp::consume_nonce(sender, txcodec::nonce(&tx)));
        vector::push_back(&mut out, osp::verify_gas_asset(fee_asset, txcodec::fee_rate(&tx)));
        vector::push_back(&mut out, osp::debit(sender, fee_asset, fee));
        vector::push_back(&mut out, osp::credit(FEE_VAULT, fee_asset, fee));

        let p = txcodec::payload(&tx);
        if (txcodec::is_transfer(p)) {
            let to = txcodec::to(p);
            if (to == sender) { return (false, none) };
            vector::push_back(&mut out, osp::debit(sender, txcodec::asset(p), txcodec::amount(p)));
            vector::push_back(&mut out, osp::credit(to, txcodec::asset(p), txcodec::amount(p)));
        } else if (txcodec::is_bind(p)) {
            vector::push_back(&mut out, osp::bind_identifier(txcodec::identifier(p), sender));
        } else if (txcodec::is_unbind(p)) {
            vector::push_back(&mut out, osp::unbind_identifier(txcodec::identifier(p), sender));
        } else {
            // Governance. `GovernanceUpdate::check_permitted` first.
            if (txcodec::is_set_parameter(p) && !osp::is_governable(&txcodec::text(p))) {
                return (false, none)
            };
            if (txcodec::is_set_gas_asset(p) && txcodec::rate_or_value(p) == 0) {
                return (false, none)
            };
            vector::push_back(&mut out, osp::verify_council(
                txcodec::epoch(p),
                txcodec::governance_digest(p),
                txcodec::signer_indices(p),
                txcodec::signatures(p),
            ));
            if (txcodec::is_set_gas_asset(p)) {
                vector::push_back(&mut out, osp::set_gas_asset(
                    txcodec::record_asset(p), txcodec::text(p), txcodec::rate_or_value(p), txcodec::flag(p)
                ));
            } else if (txcodec::is_set_parameter(p)) {
                vector::push_back(&mut out, osp::set_parameter(txcodec::text(p), txcodec::rate_or_value(p)));
            } else {
                vector::push_back(&mut out, osp::set_jwk(txcodec::iss_hash(p), txcodec::jwk_hash(p), txcodec::flag(p)));
            };
        };
        (true, out)
    }

    #[test]
    fun fees_round_up_and_refuse_zero() {
        let (ok, fee) = fee_for(RATE_SCALE);
        assert!(ok && fee == BASE_GAS_NATIVE, 0);
        let (ok, fee) = fee_for(1);
        assert!(ok && fee == 1, 1); // 1000 * 1 / 1e6 rounds up to 1, never 0
        let (ok, _) = fee_for(0);
        assert!(!ok, 2);
        let (ok, _) = fee_for(MAX_U128);
        assert!(!ok, 3);
    }
}
