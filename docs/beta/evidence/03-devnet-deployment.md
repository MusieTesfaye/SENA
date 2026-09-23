# Evidence — Aptos devnet deployment and assertion lifecycle

**Date:** 2026-09-23
**Network:** Aptos devnet
**Account:** `0xe0d32e3206d4cf64b4ed64bc8dae05107dfb4a356acb8306e9ccf6d06a4803f3`
**Toolchain:** Aptos CLI `7.9.0`; framework pinned to `46d871fa1feb61ffafb73353a0755e8cc3aaed9d`
**Source revision:** see the commit that added this file

> **Devnet resets periodically.** These transaction hashes are real and were
> executed, but the explorer links will stop resolving after the next devnet
> reset. Re-run against testnet for durable evidence.

## What this demonstrates

The safety properties are enforced by **Aptos**, not by the Rust node. Both
negative results below are Move aborts from the deployed package, committed
on chain:

- An assertion inside its challenge window **cannot** be finalized.
- A challenged assertion **cannot** be finalized, however long it has existed.

That is the core of the optimistic security claim, running on a real network.

## Transactions

| Step | Transaction | Result |
|---|---|---|
| Publish package (6 modules, 37,054 bytes) | [`0x499b92fd…`](https://explorer.aptoslabs.com/txn/0x499b92fd1bedbd5852358a56d2ccd32e919accbb1e4c6134b950e491d70e02f0?network=devnet) | Success, 184,594 gas |
| `disputes::initialize` | `0x8ab8fedda4fec3f6c73ec35b82379c6874b806494d021acc1f37e13feca216f4` | Success |
| `assertions::initialize` (7-day window, bond 1e6) | `0x4d43d6bbe16caceccdac144a4cfccec941ce231529214ccfbb6c1335c33b5239` | Success |
| `assertions::post` (bonded assertion) | `0xf47b481e77435bef94c8dc709ac1f70363c9cb6de8985e317e38d47d7ebb6d22` | Success |
| `assertions::finalize` — inside the window | — | **Aborted `E_WINDOW_OPEN` (0x25)** |
| `assertions::open_challenge` | `0xd49322527f0ac33f06342ffe205b117059afbd79aa4325225a6b5af28a05ae91` | Success |
| `assertions::finalize` — while challenged | — | **Aborted `E_WRONG_STATUS` (0x24)** |

## State observed

| Point | `assertions::status` | Meaning |
|---|---|---|
| After `post` | `0` | Pending |
| After `open_challenge` | `1` | Challenged |

## Identifiers

Genesis assertion:
```
0x179bd02565111c952b47ab3dbebcdac5f4d243bc4c571750f03153c0abb748ad
```

Posted assertion (parent = genesis, pre `0x11…`, post `0x22…`, batch `0x33…`,
trace length 10, bond 1,000,000):
```
0xce0d3b1c376fa25a83486fc2540d290ded9e70322cd365928d769ae46b9efb07
```

Both were computed independently from the canonical encoding and accepted by the
deployed contract, which is a cross-check that the Move and Rust assertion
hashing agree on a real value.

## Reproducing

```sh
aptos init --network devnet --assume-yes
ADDR=<your account>

aptos move publish --package-dir move/sena --named-addresses sena=$ADDR --assume-yes

aptos move run --function-id ${ADDR}::assertions::initialize \
  --args hex:0x1111111111111111111111111111111111111111111111111111111111111111 \
         u64:604800 u128:1000000 \
  --max-gas 100000 --gas-unit-price 100 --assume-yes

aptos move run --function-id ${ADDR}::disputes::initialize \
  --args address:$ADDR --max-gas 100000 --gas-unit-price 100 --assume-yes
```

`--max-gas` and `--gas-unit-price` are supplied explicitly because the devnet
gas-simulation endpoint timed out repeatedly from this connection. Passing them
skips the simulate call.

## What this does **not** demonstrate

- **No bonds moved.** `bond` is a number in a struct; no coin is escrowed or
  slashed. Publishing an assertion costs gas and nothing else.
- **No dispute was played to completion.** Bisection and one-step adjudication
  were not exercised on chain — only that a challenge blocks finalization.
- **No batch data was published to L1.** A verifier still gets it from the
  sequencer's RPC.
- **Four instructions remain unadjudicable.** `VerifyGasAsset`,
  `VerifyCouncil`, `SetGasAsset` and `SetParameter` abort, so a dispute over a
  gas-rate or governance step has no L1 resolution path.
- **Nothing is audited.**
