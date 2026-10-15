# Evidence: fees in several stablecoins

**Date:** 2026-10-15
**What:** fees paid in four whitelisted stablecoins on a live node, and a
forged fee in a non-par stablecoin disputed to rejection on an Aptos localnet.

| Asset | Id | Rate (per native unit) | Intrinsic gas | Fees |
|---|---|---|---|---|
| USDC | 1 | 1.000 | 10,000 | enabled |
| USDT | 2 | 1.000 | 10,000 | enabled |
| EURC | 3 | 0.925 | 15,000 | enabled |
| DAI | 4 | 1.000 | 10,000 | **disabled** |

The names are labels in a test genesis. On Aptos testnet only Circle USDC is
the issuer's own; the "USDT" and "USD1" listed there are third-party demo
tokens, and none of these accounts holds one, so the bridge was not tried with
a second asset. It takes any fungible asset, one bridge per asset.

## 1. A live node, every balance checked: `scripts/stablecoins-test.py`

A sequencer with the four assets above, Alice holding 100.000000 of each, and
seven transfers sent through `sena-node send`. The expected amounts are
computed by the script, independently of the node, from [`FEES.md`](../../FEES.md).
**32 passed, 0 failed.**

| Transfer | Fee paid in | Gas | Tip | Base fee | Outcome |
|---|---|---|---|---|---|
| 5 USDC | USDC | 41,000 | 41 | 1,025 | confirmed |
| 7 USDT | USDT | 41,000 | 41 | 1,025 | confirmed |
| 3 EURC | EURC | 46,000 | 46 | 1,063 | confirmed |
| 1 USDT | **EURC** | 46,000 | 46 | 1,063 | confirmed |
| 2 DAI | DAI | | | | **refused**: disabled for fees |
| 2 DAI | USDC | 41,000 | 41 | 1,025 | confirmed: disabling only stops fee payment; DAI can still be sent |
| 1 USDC | asset 9 | | | | **refused**: not whitelisted |

EURC's base fee is 0.025 × 0.925 = 0.023125 per gas, and its own intrinsic gas
makes a transfer 5,000 gas dearer. Balances afterwards, in each asset's
smallest unit:

| | USDC | USDT | EURC | DAI |
|---|---|---|---|---|
| Alice | 94,997,868 | 91,998,934 | 96,997,782 | 98,000,000 |
| Bob | 5,000,000 | 8,000,000 | 3,000,000 | 2,000,000 |
| Sequencer (tips) | 82 | 41 | 92 | 0 |
| Fee vault (base fees) | 2,050 | 1,025 | 2,126 | 0 |
| **Total** | 100,000,000 | 100,000,000 | 100,000,000 | 100,000,000 |

No asset was created or destroyed, and each fee went to the asset it was paid
in.

The two refusals in this run come from the node's quote: `sena_gasPrice`
returns no quote for a disabled or unlisted asset. The node also refuses at
admission when a wallet skips the quote. The test
`only_an_enabled_fee_asset_declared_as_whitelisted_is_admitted`
(`crates/sena-node/tests/node.rs`) submits over RPC four fees that must be
turned away:
- one in a disabled asset;
- one in an unlisted asset;
- one in EURC declared at par;
- one in EURC declared with the wrong intrinsic gas.

## 2. Aptos rules on a non-par fee: `scripts/localnet-dispute.sh fee`

A batch of two transfers, both paying their fees in EURC with a tip, in which
the sequencer credits itself **46,000** EURC instead of the 46 the tip comes
to. A challenger disputes it on an Aptos localnet (CLI 7.9.0) through real
transactions. The bisection lands on the tip credit. To rule, Aptos recompiles
the transaction from its published bytes, checking EURC's rate and intrinsic
gas against state and settling the fee at EURC's base fee.

```
gas used per transaction:
      1651  assertions::initialize
       911  disputes::initialize
      1070  assertions::post
       950  assertions::open_challenge
       536  disputes::open
        99  disputes::dissect
         7  disputes::select
         7  disputes::dissect
         7  disputes::select
        49  disputes::one_step
assertion status: 3 (3 = rejected)
OK: the forged sequencer's EURC tip (46000 instead of 46) was rejected on chain
```

On the same localnet, the original keyless dispute (`scripts/localnet-dispute.sh`)
still ends rejected.

## 3. The rest of the agreement

The Move suite (`aptos move test`, 78 passing) replays the node's fee steps
for every compile vector (`the_fee_steps_match_the_node_on_every_case`). That
includes `other_asset_rate`, an asset at rate 1.5 with its own intrinsic gas,
and the guardian's `DisableGasAsset` and `VerifyGasAsset` transitions for a
disabled asset.
