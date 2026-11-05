/// The L1 deposit log: every deposit into a chain's bridges, in order.
///
/// The L2 credits deposits from this log, and nowhere else. A deposit is
/// credited on the L2 by a deposit transaction (`Payload::Deposit`) whose
/// fields must equal the entry here; `sena::compiler` checks that when it
/// compiles a disputed transaction, so a sequencer that credits a deposit
/// nobody made -- or a different amount, asset or recipient -- has published
/// an uncompilable transaction, which is fraud. The L2's deposit cursor
/// (`ConsumeDeposit`) makes each entry credit once, in id order.
///
/// Events are not enough for this: Move cannot read them, so a dispute could
/// not check a credit against one. The log is a table, append-only, keyed by a
/// chain-wide id that counts from one.
///
/// # Who may write
///
/// Only `sena::bridge`, and only for a bridge the chain's owner registered
/// under the L2 asset id it custodies. `bridge::initialize` is permissionless,
/// so without registration anyone could stand up a bridge over a worthless
/// token, name a real asset's L2 id, and mint that asset on the L2.
module sena::deposits {
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};

    friend sena::bridge;

    /// The bridge is not registered with this chain.
    const E_UNREGISTERED_BRIDGE: u64 = 60;
    /// The bridge is registered under a different L2 asset.
    const E_WRONG_ASSET: u64 = 61;
    /// The bridge is already registered.
    const E_ALREADY_REGISTERED: u64 = 62;
    /// An L2 recipient is a 32-byte address.
    const E_BAD_RECIPIENT: u64 = 63;
    /// Another bridge already custodies this L2 asset.
    const E_ASSET_TAKEN: u64 = 64;

    struct Record has copy, drop, store {
        recipient: vector<u8>,
        asset: u32,
        amount: u64,
    }

    /// Lives at the chain's address.
    struct Log has key {
        /// Registered bridges, and the L2 asset each custodies.
        bridges: Table<address, u32>,
        /// Which bridge custodies each L2 asset: one per asset, so the L2
        /// balance of an asset is backed by exactly one custody store.
        asset_bridge: Table<u32, address>,
        /// Deposits by id.
        records: Table<u64, Record>,
        /// The last id assigned.
        count: u64,
    }

    fun ensure_log(chain: &signer) {
        if (!exists<Log>(signer::address_of(chain))) {
            move_to(chain, Log {
                bridges: table::new(),
                asset_bridge: table::new(),
                records: table::new(),
                count: 0,
            });
        }
    }

    /// Registers `bridge` as the custodian of `l2_asset_id` for the chain
    /// `chain` owns. Only the chain's own account can do this.
    public entry fun register_bridge(chain: &signer, bridge: address, l2_asset_id: u32) acquires Log {
        ensure_log(chain);
        let log = borrow_global_mut<Log>(signer::address_of(chain));
        assert!(!table::contains(&log.bridges, bridge), E_ALREADY_REGISTERED);
        assert!(!table::contains(&log.asset_bridge, l2_asset_id), E_ASSET_TAKEN);
        table::add(&mut log.bridges, bridge, l2_asset_id);
        table::add(&mut log.asset_bridge, l2_asset_id, bridge);
    }

    /// Appends a deposit by a registered bridge; returns its id.
    public(friend) fun append(
        chain: address,
        bridge: address,
        recipient: vector<u8>,
        asset: u32,
        amount: u64,
    ): u64 acquires Log {
        assert!(exists<Log>(chain), E_UNREGISTERED_BRIDGE);
        assert!(vector::length(&recipient) == 32, E_BAD_RECIPIENT);
        let log = borrow_global_mut<Log>(chain);
        assert!(table::contains(&log.bridges, bridge), E_UNREGISTERED_BRIDGE);
        assert!(*table::borrow(&log.bridges, bridge) == asset, E_WRONG_ASSET);
        log.count = log.count + 1;
        table::add(&mut log.records, log.count, Record { recipient, asset, amount });
        log.count
    }

    /// Whether deposit `id` of `chain` is exactly this credit.
    public fun matches(chain: address, id: u64, recipient: vector<u8>, asset: u32, amount: u128): bool acquires Log {
        let (found, r, a, m) = record(chain, id);
        found && r == recipient && a == asset && (m as u128) == amount
    }

    #[view]
    /// Deposit `id` of `chain`: `(found, recipient, asset, amount)`.
    public fun record(chain: address, id: u64): (bool, vector<u8>, u32, u64) acquires Log {
        if (!exists<Log>(chain)) { return (false, vector::empty(), 0, 0) };
        let log = borrow_global<Log>(chain);
        if (!table::contains(&log.records, id)) { return (false, vector::empty(), 0, 0) };
        let r = table::borrow(&log.records, id);
        (true, r.recipient, r.asset, r.amount)
    }

    #[view]
    /// The number of deposits `chain` has recorded; the last id.
    public fun count(chain: address): u64 acquires Log {
        if (!exists<Log>(chain)) { 0 } else { borrow_global<Log>(chain).count }
    }

    #[view]
    /// The L2 asset `bridge` is registered under for `chain`: `(registered, asset)`.
    public fun bridge_asset(chain: address, bridge: address): (bool, u32) acquires Log {
        if (!exists<Log>(chain)) { return (false, 0) };
        let log = borrow_global<Log>(chain);
        if (!table::contains(&log.bridges, bridge)) { return (false, 0) };
        (true, *table::borrow(&log.bridges, bridge))
    }

    #[test_only]
    public fun append_for_test(chain: address, bridge: address, recipient: vector<u8>, asset: u32, amount: u64): u64 acquires Log {
        append(chain, bridge, recipient, asset, amount)
    }

    #[test(chain = @0xC4A1)]
    fun deposits_are_numbered_and_matched_exactly(chain: &signer) acquires Log {
        let c = signer::address_of(chain);
        register_bridge(chain, @0xB1, 1);
        let to = x"0101010101010101010101010101010101010101010101010101010101010101";
        assert!(append(c, @0xB1, to, 1, 500) == 1, 0);
        assert!(append(c, @0xB1, to, 1, 7) == 2, 1);
        assert!(count(c) == 2, 2);
        assert!(matches(c, 1, to, 1, 500), 3);
        assert!(!matches(c, 1, to, 1, 501), 4);      // wrong amount
        assert!(!matches(c, 1, to, 2, 500), 5);      // wrong asset
        assert!(!matches(c, 1, x"02", 1, 500), 6);   // wrong recipient
        assert!(!matches(c, 3, to, 1, 500), 7);      // not yet made
        assert!(!matches(@0xDEAD, 1, to, 1, 500), 8); // other chain
    }

    #[test(chain = @0xC4A1)]
    #[expected_failure(abort_code = E_UNREGISTERED_BRIDGE, location = Self)]
    fun an_unregistered_bridge_cannot_append(chain: &signer) acquires Log {
        register_bridge(chain, @0xB1, 1);
        append(signer::address_of(chain), @0xB2, x"0101010101010101010101010101010101010101010101010101010101010101", 1, 5);
    }

    #[test(chain = @0xC4A1)]
    #[expected_failure(abort_code = E_WRONG_ASSET, location = Self)]
    fun a_bridge_cannot_credit_another_asset(chain: &signer) acquires Log {
        register_bridge(chain, @0xB1, 1);
        append(signer::address_of(chain), @0xB1, x"0101010101010101010101010101010101010101010101010101010101010101", 2, 5);
    }

    #[test(chain = @0xC4A1)]
    #[expected_failure(abort_code = E_ASSET_TAKEN, location = Self)]
    fun one_bridge_per_asset(chain: &signer) acquires Log {
        register_bridge(chain, @0xB1, 1);
        register_bridge(chain, @0xB2, 1);
    }
}
