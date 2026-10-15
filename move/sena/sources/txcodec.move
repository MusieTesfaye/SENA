/// Decoding of published transactions, mirroring `sena_stf::wire`.
///
/// When a dispute needs to know what a transaction does, the bytes come from
/// the batch data the sequencer published. This module reads them exactly as
/// the Rust node does -- big-endian integers, `u32`-length-prefixed strings,
/// one-byte discriminants -- and refuses everything else, so a sequencer cannot
/// publish bytes that L1 and the verifiers read differently.
///
/// Decoding never aborts. A leaf that does not decode is a batch that should
/// not exist, and the caller needs that as an answer.
module sena::txcodec {
    use std::option;
    use std::string;
    use std::vector;
    use sena::codec;
    use sena::keyless;

    /// `wire::MAX_TRANSACTION_BYTES`.
    const MAX_TRANSACTION_BYTES: u64 = 8192;
    /// `wire::MAX_COUNCIL_SIGNATURES`.
    const MAX_COUNCIL_SIGNATURES: u64 = 32;

    const AUTH_ED25519: u8 = 0;
    const AUTH_KEYLESS: u8 = 1;

    const PAYLOAD_TRANSFER: u8 = 0;
    const PAYLOAD_BIND_IDENTIFIER: u8 = 1;
    const PAYLOAD_UNBIND_IDENTIFIER: u8 = 2;
    const PAYLOAD_GOVERNANCE: u8 = 3;
    const PAYLOAD_DISTRIBUTE_FEES: u8 = 4;

    const UPDATE_SET_GAS_ASSET: u8 = 0;
    const UPDATE_SET_PARAMETER: u8 = 1;
    const UPDATE_SET_JWK: u8 = 2;
    const UPDATE_SET_FEE_MARKET: u8 = 3;
    const UPDATE_SET_FEE_SPLIT: u8 = 4;
    const UPDATE_DISABLE_GAS_ASSET: u8 = 5;

    /// `gas::MAX_FEE_BENEFICIARIES`.
    const MAX_FEE_BENEFICIARIES: u64 = 8;

    const DOMAIN_TRANSACTION: vector<u8> = b"SENA:v1:transaction";
    const DOMAIN_GOVERNANCE_UPDATE: vector<u8> = b"SENA:v1:governance-update";

    /// A decoded transaction.
    struct Tx has copy, drop {
        sender: vector<u8>,
        nonce: u64,
        fee_asset: u32,
        fee_rate: u128,
        fee_intrinsic_gas: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        /// The payload's canonical bytes, which the signing digest commits to.
        payload_bytes: vector<u8>,
        payload: Payload,
        auth_kind: u8,
        ed25519_public_key: vector<u8>,
        ed25519_signature: vector<u8>,
        keyless: option::Option<keyless::Signature>,
        /// Length of the whole encoding.
        encoded_len: u64,
    }

    /// A decoded payload: a superset of fields, read according to `kind`.
    struct Payload has copy, drop {
        kind: u8,
        to: vector<u8>,
        asset: u32,
        amount: u128,
        channel: u8,
        identifier: vector<u8>,
        epoch: u64,
        /// The governance update's canonical bytes, which the council signs.
        update_bytes: vector<u8>,
        update_kind: u8,
        record_asset: u32,
        text: vector<u8>,
        rate_or_value: u128,
        /// SetGasAsset: the intrinsic gas. SetFeeMarket: the target.
        gas: u64,
        flag: bool,
        /// DistributeFees/SetFeeSplit: the split's canonical bytes.
        split: vector<u8>,
        iss_hash: vector<u8>,
        jwk_hash: vector<u8>,
        signer_indices: vector<u32>,
        signatures: vector<vector<u8>>,
    }

    // --- A non-aborting cursor -----------------------------------------------

    struct Cursor has drop {
        bytes: vector<u8>,
        at: u64,
        ok: bool,
    }

    fun cursor(bytes: vector<u8>): Cursor { Cursor { bytes, at: 0, ok: true } }

    fun have(c: &mut Cursor, n: u64): bool {
        if (!c.ok || c.at + n > vector::length(&c.bytes)) { c.ok = false; return false };
        true
    }

    fun take_u8(c: &mut Cursor): u8 {
        if (!have(c, 1)) { return 0 };
        let b = *vector::borrow(&c.bytes, c.at);
        c.at = c.at + 1;
        b
    }

    fun take_be(c: &mut Cursor, n: u64): u128 {
        if (!have(c, n)) { return 0 };
        let v: u128 = 0;
        let i = 0;
        while (i < n) {
            v = (v << 8) | (*vector::borrow(&c.bytes, c.at + i) as u128);
            i = i + 1;
        };
        c.at = c.at + n;
        v
    }

    fun take_u32(c: &mut Cursor): u32 { (take_be(c, 4) as u32) }
    fun take_u64(c: &mut Cursor): u64 { (take_be(c, 8) as u64) }

    fun take_u128(c: &mut Cursor): u128 {
        let hi = take_be(c, 8);
        let lo = take_be(c, 8);
        (hi << 64) | lo
    }

    fun take_bytes(c: &mut Cursor, n: u64): vector<u8> {
        let out = vector::empty<u8>();
        if (!have(c, n)) { return out };
        let i = 0;
        while (i < n) {
            vector::push_back(&mut out, *vector::borrow(&c.bytes, c.at + i));
            i = i + 1;
        };
        c.at = c.at + n;
        out
    }

    fun take_field(c: &mut Cursor): vector<u8> {
        let n = (take_u32(c) as u64);
        take_bytes(c, n)
    }

    /// A length-prefixed UTF-8 string, as `Reader::string` reads it.
    fun take_string(c: &mut Cursor): vector<u8> {
        let s = take_field(c);
        if (c.ok && option::is_none(&string::try_utf8(s))) { c.ok = false };
        s
    }

    fun take_bool(c: &mut Cursor): bool {
        let b = take_u8(c);
        if (b > 1) { c.ok = false };
        b == 1
    }

    fun done(c: &Cursor): bool { c.ok && c.at == vector::length(&c.bytes) }

    // --- Decoding ------------------------------------------------------------

    fun empty_payload(kind: u8): Payload {
        Payload {
            kind,
            to: vector::empty(),
            asset: 0,
            amount: 0,
            channel: 0,
            identifier: vector::empty(),
            epoch: 0,
            update_bytes: vector::empty(),
            update_kind: 0,
            record_asset: 0,
            text: vector::empty(),
            rate_or_value: 0,
            gas: 0,
            flag: false,
            split: vector::empty(),
            iss_hash: vector::empty(),
            jwk_hash: vector::empty(),
            signer_indices: vector::empty(),
            signatures: vector::empty(),
        }
    }

    /// Decodes a governance update into `p`; false if malformed.
    fun decode_update(bytes: vector<u8>, p: &mut Payload): bool {
        let c = cursor(bytes);
        let kind = take_u8(&mut c);
        p.update_kind = kind;
        if (kind == UPDATE_SET_GAS_ASSET) {
            let record = take_field(&mut c);
            let r = cursor(record);
            p.record_asset = take_u32(&mut r);
            p.text = take_string(&mut r);
            p.rate_or_value = take_u128(&mut r);
            p.gas = take_u64(&mut r);
            p.flag = take_bool(&mut r);
            if (!done(&r)) { return false };
        } else if (kind == UPDATE_SET_PARAMETER) {
            p.text = take_string(&mut c);
            p.rate_or_value = take_u128(&mut c);
        } else if (kind == UPDATE_SET_JWK) {
            p.iss_hash = take_bytes(&mut c, 32);
            p.jwk_hash = take_bytes(&mut c, 32);
            p.flag = take_bool(&mut c);
        } else if (kind == UPDATE_SET_FEE_MARKET) {
            p.rate_or_value = take_u128(&mut c);
            p.gas = take_u64(&mut c);
        } else if (kind == UPDATE_SET_FEE_SPLIT) {
            p.split = take_field(&mut c);
            if (!c.ok || !split_is_well_formed(p.split)) { return false };
        } else if (kind == UPDATE_DISABLE_GAS_ASSET) {
            p.record_asset = take_u32(&mut c);
        } else {
            return false
        };
        done(&c)
    }

    /// Whether `bytes` is a fee split's encoding (`FeeSplit::decode`): at most
    /// `MAX_FEE_BENEFICIARIES` (address, share) pairs and a burn share. Every
    /// field is fixed-width, so any encoding that parses is the canonical one.
    fun split_is_well_formed(bytes: vector<u8>): bool {
        let c = cursor(bytes);
        let count = (take_u32(&mut c) as u64);
        if (count > MAX_FEE_BENEFICIARIES) { return false };
        let i = 0;
        while (i < count) {
            take_bytes(&mut c, 32);
            take_u32(&mut c);
            i = i + 1;
        };
        take_u32(&mut c);
        done(&c)
    }

    fun decode_payload(bytes: vector<u8>): option::Option<Payload> {
        let c = cursor(bytes);
        let kind = take_u8(&mut c);
        let p = empty_payload(kind);
        if (kind == PAYLOAD_TRANSFER) {
            p.to = take_bytes(&mut c, 32);
            p.asset = take_u32(&mut c);
            p.amount = take_u128(&mut c);
        } else if (kind == PAYLOAD_BIND_IDENTIFIER) {
            p.channel = take_u8(&mut c);
            if (p.channel > 2) { return option::none() };
            p.identifier = take_bytes(&mut c, 32);
        } else if (kind == PAYLOAD_UNBIND_IDENTIFIER) {
            p.identifier = take_bytes(&mut c, 32);
        } else if (kind == PAYLOAD_GOVERNANCE) {
            p.epoch = take_u64(&mut c);
            p.update_bytes = take_field(&mut c);
            if (!c.ok || !decode_update(p.update_bytes, &mut p)) { return option::none() };
            let count = (take_u32(&mut c) as u64);
            if (count > MAX_COUNCIL_SIGNATURES) { return option::none() };
            let i = 0;
            while (i < count) {
                vector::push_back(&mut p.signer_indices, take_u32(&mut c));
                let sig = take_field(&mut c);
                if (vector::length(&sig) != 64) { return option::none() };
                vector::push_back(&mut p.signatures, sig);
                i = i + 1;
            };
        } else if (kind == PAYLOAD_DISTRIBUTE_FEES) {
            p.asset = take_u32(&mut c);
            p.amount = take_u128(&mut c);
            p.split = take_field(&mut c);
            if (!c.ok || !split_is_well_formed(p.split)) { return option::none() };
        } else {
            return option::none()
        };
        if (!done(&c)) { return option::none() };
        option::some(p)
    }

    /// Decodes a canonically encoded transaction, or `none`.
    public fun decode(bytes: vector<u8>): option::Option<Tx> {
        let encoded_len = vector::length(&bytes);
        if (encoded_len > MAX_TRANSACTION_BYTES) { return option::none() };
        let c = cursor(bytes);
        let sender = take_bytes(&mut c, 32);
        let nonce = take_u64(&mut c);
        let fee_asset = take_u32(&mut c);
        let fee_rate = take_u128(&mut c);
        let fee_intrinsic_gas = take_u64(&mut c);
        let gas_limit = take_u64(&mut c);
        let max_fee_per_gas = take_u128(&mut c);
        let max_priority_fee_per_gas = take_u128(&mut c);
        let payload_bytes = take_field(&mut c);
        if (!c.ok) { return option::none() };
        let payload = decode_payload(payload_bytes);
        if (option::is_none(&payload)) { return option::none() };

        let auth_kind = take_u8(&mut c);
        let ed25519_public_key = vector::empty<u8>();
        let ed25519_signature = vector::empty<u8>();
        let keyless_sig = option::none<keyless::Signature>();
        if (auth_kind == AUTH_ED25519) {
            ed25519_public_key = take_bytes(&mut c, 32);
            ed25519_signature = take_bytes(&mut c, 64);
        } else if (auth_kind == AUTH_KEYLESS) {
            let iss_hash = take_bytes(&mut c, 32);
            let idc = take_bytes(&mut c, 32);
            let epk = take_bytes(&mut c, 32);
            let esig = take_bytes(&mut c, 64);
            let exp_date = take_u64(&mut c);
            let exp_horizon = take_u64(&mut c);
            let header = take_bytes(&mut c, 32);
            let jwk = take_bytes(&mut c, 32);
            let has_extra = take_bool(&mut c);
            let extra = if (has_extra) { take_bytes(&mut c, 32) } else { vector::empty() };
            let proof = take_bytes(&mut c, 128);
            keyless_sig = option::some(keyless::new_signature(
                iss_hash, idc, epk, esig, exp_date, exp_horizon, header, jwk, has_extra, extra, proof
            ));
        } else {
            return option::none()
        };
        if (!done(&c)) { return option::none() };

        option::some(Tx {
            sender,
            nonce,
            fee_asset,
            fee_rate,
            fee_intrinsic_gas,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            payload_bytes,
            payload: option::extract(&mut payload),
            auth_kind,
            ed25519_public_key,
            ed25519_signature,
            keyless: keyless_sig,
            encoded_len,
        })
    }

    /// The digest every authenticator signs (`Transaction::signing_digest`).
    public fun signing_digest(tx: &Tx): vector<u8> {
        let buf = codec::begin(DOMAIN_TRANSACTION);
        codec::put_field(&mut buf, tx.sender);
        codec::put_field_u64(&mut buf, tx.nonce);
        codec::put_field_u64(&mut buf, (tx.fee_asset as u64));
        codec::put_field_u128(&mut buf, tx.fee_rate);
        codec::put_field_u64(&mut buf, tx.fee_intrinsic_gas);
        codec::put_field_u64(&mut buf, tx.gas_limit);
        codec::put_field_u128(&mut buf, tx.max_fee_per_gas);
        codec::put_field_u128(&mut buf, tx.max_priority_fee_per_gas);
        codec::put_field(&mut buf, tx.payload_bytes);
        codec::commit(buf)
    }

    /// The digest the council signs for a governance payload
    /// (`GovernanceUpdate::signing_digest`).
    public fun governance_digest(p: &Payload): vector<u8> {
        let buf = codec::begin(DOMAIN_GOVERNANCE_UPDATE);
        codec::put_field_u64(&mut buf, p.epoch);
        codec::put_field(&mut buf, p.update_bytes);
        codec::commit(buf)
    }

    // --- Accessors -----------------------------------------------------------

    public fun sender(tx: &Tx): vector<u8> { tx.sender }
    public fun nonce(tx: &Tx): u64 { tx.nonce }
    public fun fee_asset(tx: &Tx): u32 { tx.fee_asset }
    public fun fee_rate(tx: &Tx): u128 { tx.fee_rate }
    public fun fee_intrinsic_gas(tx: &Tx): u64 { tx.fee_intrinsic_gas }
    public fun gas_limit(tx: &Tx): u64 { tx.gas_limit }
    public fun max_fee_per_gas(tx: &Tx): u128 { tx.max_fee_per_gas }
    public fun max_priority_fee_per_gas(tx: &Tx): u128 { tx.max_priority_fee_per_gas }
    public fun payload(tx: &Tx): &Payload { &tx.payload }
    public fun is_ed25519(tx: &Tx): bool { tx.auth_kind == AUTH_ED25519 }
    public fun ed25519_public_key(tx: &Tx): vector<u8> { tx.ed25519_public_key }
    public fun ed25519_signature(tx: &Tx): vector<u8> { tx.ed25519_signature }
    public fun keyless_signature(tx: &Tx): option::Option<keyless::Signature> { tx.keyless }
    public fun encoded_len(tx: &Tx): u64 { tx.encoded_len }

    public fun kind(p: &Payload): u8 { p.kind }
    public fun is_transfer(p: &Payload): bool { p.kind == PAYLOAD_TRANSFER }
    public fun is_bind(p: &Payload): bool { p.kind == PAYLOAD_BIND_IDENTIFIER }
    public fun is_unbind(p: &Payload): bool { p.kind == PAYLOAD_UNBIND_IDENTIFIER }
    public fun is_governance(p: &Payload): bool { p.kind == PAYLOAD_GOVERNANCE }
    public fun is_distribute_fees(p: &Payload): bool { p.kind == PAYLOAD_DISTRIBUTE_FEES }
    public fun to(p: &Payload): vector<u8> { p.to }
    public fun asset(p: &Payload): u32 { p.asset }
    public fun amount(p: &Payload): u128 { p.amount }
    public fun identifier(p: &Payload): vector<u8> { p.identifier }
    public fun epoch(p: &Payload): u64 { p.epoch }
    public fun update_kind(p: &Payload): u8 { p.update_kind }
    public fun is_set_gas_asset(p: &Payload): bool { p.update_kind == UPDATE_SET_GAS_ASSET }
    public fun is_set_parameter(p: &Payload): bool { p.update_kind == UPDATE_SET_PARAMETER }
    public fun is_set_jwk(p: &Payload): bool { p.update_kind == UPDATE_SET_JWK }
    public fun is_set_fee_market(p: &Payload): bool { p.update_kind == UPDATE_SET_FEE_MARKET }
    public fun is_set_fee_split(p: &Payload): bool { p.update_kind == UPDATE_SET_FEE_SPLIT }
    public fun is_disable_gas_asset(p: &Payload): bool { p.update_kind == UPDATE_DISABLE_GAS_ASSET }
    public fun record_asset(p: &Payload): u32 { p.record_asset }
    public fun text(p: &Payload): vector<u8> { p.text }
    public fun rate_or_value(p: &Payload): u128 { p.rate_or_value }
    public fun flag(p: &Payload): bool { p.flag }
    public fun gas(p: &Payload): u64 { p.gas }
    public fun split(p: &Payload): vector<u8> { p.split }
    public fun iss_hash(p: &Payload): vector<u8> { p.iss_hash }
    public fun jwk_hash(p: &Payload): vector<u8> { p.jwk_hash }
    public fun signer_indices(p: &Payload): vector<u32> { p.signer_indices }
    public fun signatures(p: &Payload): vector<vector<u8>> { p.signatures }
}
