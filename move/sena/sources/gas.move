/// Fees, as `sena_stf::gas` computes them: the fee market's EIP-1559 step,
/// settlement of a transaction's hold into refund, tip and base fee, and the
/// fee split.
///
/// Everything here is arithmetic the Rust node does too, and a dispute can
/// turn on any of it, so it must agree to the unit -- including where it
/// refuses. Move aborts on overflow where Rust returns an error, so every
/// multiplication is checked first and reported as `(false, ..)` instead.
module sena::gas {
    use std::vector;
    use sena::codec;

    /// `gas::RATE_SCALE`.
    const RATE_SCALE: u128 = 1000000;
    /// `gas::PRICE_SCALE`.
    const PRICE_SCALE: u128 = 1000000000000;
    /// `gas::INTRINSIC_GAS`.
    const INTRINSIC_GAS: u64 = 21000;
    /// `gas::KEYLESS_GAS`.
    const KEYLESS_GAS: u64 = 100000;
    /// `gas::MAX_GAS_LIMIT`.
    const MAX_GAS_LIMIT: u64 = 30000000;
    /// `gas::ELASTICITY`.
    const ELASTICITY: u64 = 2;
    /// `gas::BASE_FEE_CHANGE_DENOMINATOR`.
    const BASE_FEE_CHANGE_DENOMINATOR: u128 = 8;
    /// `gas::DEFAULT_BASE_FEE_FLOOR`.
    const DEFAULT_BASE_FEE_FLOOR: u128 = 25000000000;
    /// `gas::DEFAULT_GAS_TARGET`.
    const DEFAULT_GAS_TARGET: u64 = 5000000;
    /// `gas::SHARE_SCALE`.
    const SHARE_SCALE: u64 = 1000000;
    /// `gas::MAX_FEE_BENEFICIARIES`.
    const MAX_FEE_BENEFICIARIES: u64 = 8;

    const MAX_U64: u64 = 18446744073709551615;
    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    public fun intrinsic_gas(): u64 { INTRINSIC_GAS }
    public fun keyless_gas(): u64 { KEYLESS_GAS }

    /// `a * b`, or `(false, 0)` if it would overflow.
    fun mul(a: u128, b: u128): (bool, u128) {
        if (b != 0 && a > MAX_U128 / b) { return (false, 0) };
        (true, a * b)
    }

    // --- The fee market ------------------------------------------------------

    /// `gas::FeeMarket`.
    struct FeeMarket has copy, drop {
        base_fee: u128,
        floor: u128,
        target: u64,
        window_ts: u64,
        window_gas: u64,
    }

    /// The market a chain without a record has (`FeeMarket::genesis` at the
    /// defaults).
    public fun genesis_market(): FeeMarket {
        FeeMarket {
            base_fee: DEFAULT_BASE_FEE_FLOOR,
            floor: DEFAULT_BASE_FEE_FLOOR,
            target: DEFAULT_GAS_TARGET,
            window_ts: 0,
            window_gas: 0,
        }
    }

    /// The market a slot holds; an empty slot is the genesis market.
    public fun market_in(present: bool, bytes: vector<u8>): FeeMarket {
        if (!present) { return genesis_market() };
        let r = codec::reader(bytes);
        let m = FeeMarket {
            base_fee: codec::take_u128(&mut r),
            floor: codec::take_u128(&mut r),
            target: codec::take_u64(&mut r),
            window_ts: codec::take_u64(&mut r),
            window_gas: codec::take_u64(&mut r),
        };
        codec::finish(&r);
        m
    }

    public fun encode_market(m: &FeeMarket): vector<u8> {
        let out = vector::empty<u8>();
        codec::put_u128(&mut out, m.base_fee);
        codec::put_u128(&mut out, m.floor);
        codec::put_u64(&mut out, m.target);
        codec::put_u64(&mut out, m.window_ts);
        codec::put_u64(&mut out, m.window_gas);
        out
    }

    public fun base_fee(m: &FeeMarket): u128 { m.base_fee }
    public fun window_gas(m: &FeeMarket): u64 { m.window_gas }

    /// `FeeMarket::window_limit`: `target × ELASTICITY`, saturating.
    public fun window_limit(m: &FeeMarket): u64 {
        if (m.target > MAX_U64 / ELASTICITY) { MAX_U64 } else { m.target * ELASTICITY }
    }

    /// Adds `gas` to the window; false if that would pass its limit.
    public fun charge(m: &mut FeeMarket, gas: u64): bool {
        if (gas > MAX_U64 - m.window_gas) { return false };
        let total = m.window_gas + gas;
        if (total > window_limit(m)) { return false };
        m.window_gas = total;
        true
    }

    /// The `SetFeeMarket` transition: a new floor and target, keeping the
    /// window, with the base fee raised to the floor if below it.
    public fun set_parameters(m: &mut FeeMarket, floor: u128, target: u64) {
        if (m.base_fee < floor) { m.base_fee = floor };
        m.floor = floor;
        m.target = target;
    }

    /// `next_base_fee`: one EIP-1559 step after a window that used `gas`.
    public fun next_base_fee(base: u128, gas: u64, target: u64, floor: u128): (bool, u128) {
        let g = (gas as u128);
        let t = (target as u128);
        let next = if (t == 0 || g > t) {
            let excess = if (t == 0) { g } else { g - t };
            let (ok, product) = mul(base, excess);
            if (!ok) { return (false, 0) };
            let divisor = if (t == 0) { 1 } else { t };
            let delta = product / divisor / BASE_FEE_CHANGE_DENOMINATOR;
            if (delta == 0) { delta = 1 };
            if (base > MAX_U128 - delta) { return (false, 0) };
            base + delta
        } else {
            let (ok, product) = mul(base, t - g);
            if (!ok) { return (false, 0) };
            base - product / t / BASE_FEE_CHANGE_DENOMINATOR
        };
        (true, if (next < floor) { floor } else { next })
    }

    /// `FeeMarket::at`: the market as a batch stamped `timestamp` sees it.
    public fun market_at(m: &FeeMarket, timestamp: u64): (bool, FeeMarket) {
        if (timestamp < m.window_ts) { return (false, *m) };
        if (timestamp == m.window_ts) { return (true, *m) };
        let (ok, next) = next_base_fee(m.base_fee, m.window_gas, m.target, m.floor);
        if (!ok) { return (false, *m) };
        (true, FeeMarket {
            base_fee: next,
            floor: m.floor,
            target: m.target,
            window_ts: timestamp,
            window_gas: 0,
        })
    }

    // --- Settlement ----------------------------------------------------------

    /// `native_to_asset`: `native × rate / RATE_SCALE`, rounding down.
    public fun native_to_asset(amount: u128, rate: u128): (bool, u128) {
        if (rate == 0) { return (false, 0) };
        let (ok, product) = mul(amount, rate);
        if (!ok) { return (false, 0) };
        (true, product / RATE_SCALE)
    }

    /// `gas × price / PRICE_SCALE`, or `(false, 0)` on overflow.
    fun total(gas: u64, price: u128): (bool, u128) {
        let (ok, product) = mul((gas as u128), price);
        if (!ok) { return (false, 0) };
        (true, product / PRICE_SCALE)
    }

    /// `settle`: `(ok, hold, refund, tip, base)`, with every rounding
    /// remainder in `base` so the three parts sum to the hold exactly.
    public fun settle(
        gas_limit: u64,
        gas_used: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        base_fee: u128,
        rate: u128,
    ): (bool, u128, u128, u128, u128) {
        if (gas_limit > MAX_GAS_LIMIT || gas_used > gas_limit) { return (false, 0, 0, 0, 0) };
        let (ok, base_per_gas) = native_to_asset(base_fee, rate);
        if (!ok || max_fee_per_gas < base_per_gas) { return (false, 0, 0, 0, 0) };
        let headroom = max_fee_per_gas - base_per_gas;
        let tip_per_gas = if (max_priority_fee_per_gas < headroom) { max_priority_fee_per_gas } else { headroom };
        let price = base_per_gas + tip_per_gas;
        let (ok_hold, hold) = total(gas_limit, price);
        if (!ok_hold || hold == 0) { return (false, 0, 0, 0, 0) };
        let (ok_refund, refund) = total(gas_limit - gas_used, price);
        let (ok_tip, tip) = total(gas_used, tip_per_gas);
        let (ok_base, base) = total(gas_used, base_per_gas);
        if (!ok_refund || !ok_tip || !ok_base) { return (false, 0, 0, 0, 0) };
        let remainder = hold - refund - tip - base;
        (true, hold, refund, tip, base + remainder)
    }

    // --- The fee split -------------------------------------------------------

    /// The split's beneficiaries, shares and burn (`FeeSplit::decode`).
    fun parse_split(bytes: vector<u8>): (vector<vector<u8>>, vector<u64>, u64) {
        let r = codec::reader(bytes);
        let count = (codec::take_u32(&mut r) as u64);
        assert!(count <= MAX_FEE_BENEFICIARIES, codec::error_unknown_variant());
        let addresses = vector::empty<vector<u8>>();
        let shares = vector::empty<u64>();
        let i = 0;
        while (i < count) {
            vector::push_back(&mut addresses, codec::take_bytes(&mut r, 32));
            vector::push_back(&mut shares, (codec::take_u32(&mut r) as u64));
            i = i + 1;
        };
        let burn = (codec::take_u32(&mut r) as u64);
        codec::finish(&r);
        (addresses, shares, burn)
    }

    /// `FeeSplit::check`: distinct beneficiaries with non-zero shares, all
    /// shares summing to exactly `SHARE_SCALE`.
    public fun split_is_valid(bytes: vector<u8>): bool {
        let (addresses, shares, burn) = parse_split(bytes);
        let total = burn;
        let n = vector::length(&addresses);
        let i = 0;
        while (i < n) {
            let share = *vector::borrow(&shares, i);
            if (share == 0) { return false };
            let a = vector::borrow(&addresses, i);
            let j = 0;
            while (j < i) {
                if (vector::borrow(&addresses, j) == a) { return false };
                j = j + 1;
            };
            total = total + share;
            i = i + 1;
        };
        total == SHARE_SCALE
    }

    /// `FeeSplit::shares_of`: what each beneficiary receives from `amount`,
    /// rounded down, as `(ok, addresses, amounts)`.
    public fun shares_of(bytes: vector<u8>, amount: u128): (bool, vector<vector<u8>>, vector<u128>) {
        let (addresses, shares, _) = parse_split(bytes);
        let values = vector::empty<u128>();
        let n = vector::length(&shares);
        let i = 0;
        while (i < n) {
            let (ok, product) = mul(amount, (*vector::borrow(&shares, i) as u128));
            if (!ok) { return (false, vector::empty(), vector::empty()) };
            vector::push_back(&mut values, product / (SHARE_SCALE as u128));
            i = i + 1;
        };
        (true, addresses, values)
    }

    #[test]
    fun the_base_fee_moves_by_an_eighth() {
        let (_, up) = next_base_fee(1000, 20, 10, 100);
        let (_, down) = next_base_fee(1000, 0, 10, 100);
        let (_, held) = next_base_fee(1000, 10, 10, 100);
        let (_, floored) = next_base_fee(110, 0, 10, 100);
        assert!(up == 1125 && down == 875 && held == 1000 && floored == 100, 0);
        let (ok, _) = next_base_fee(MAX_U128, 20, 10, 0);
        assert!(!ok, 1);
    }

    #[test]
    fun settlement_pays_out_the_hold() {
        // As `gas::tests::rounding_remainders_go_to_the_base_fee`.
        let (ok, hold, refund, tip, base) =
            settle(3, 1, 1500000000000, 700000000000, 400000000000, RATE_SCALE);
        assert!(ok && hold == 3 && refund == 2 && tip == 0 && base == 1, 0);
        let (ok, _, _, _, _) = settle(10, 10, MAX_U128, MAX_U128, 1, RATE_SCALE);
        assert!(!ok, 1);
    }
}
