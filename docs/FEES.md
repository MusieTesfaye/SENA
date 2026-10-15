# Fees

SENA charges fees the way Celo does — metered gas, an EIP-1559 base fee,
payment in any whitelisted stablecoin — adapted to a chain with **no native
token**. Every rule below is executed by the node *and* re-executed by the
Aptos contracts when a dispute reaches it, so none of it is a matter of
trusting the sequencer.

Code: [`crates/sena-stf/src/gas.rs`](../crates/sena-stf/src/gas.rs) (Rust) and
[`move/sena/sources/gas.move`](../move/sena/sources/gas.move) (Aptos).
Generated conformance vectors keep the two in agreement to the unit.

## What a transaction says

| Field | Meaning | Celo equivalent |
|---|---|---|
| `fee_asset` | The stablecoin the fee is paid in | `feeCurrency` |
| `fee_rate` | That asset's whitelisted rate, as the sender believes it | (read from the directory) |
| `fee_intrinsic_gas` | That asset's intrinsic gas, as the sender believes it | directory's intrinsic gas |
| `gas_limit` | The most gas it may use | `gas` |
| `max_fee_per_gas` | Most it pays per gas, base fee and tip together | `maxFeePerGas` |
| `max_priority_fee_per_gas` | Most tip per gas | `maxPriorityFeePerGas` |

Prices are in `1 / PRICE_SCALE` (10⁻¹²) of a unit of the fee asset — the job
Celo's `FeeCurrencyAdapter` does for six-decimal tokens like USDC, whose
smallest unit is too coarse to price one gas. Only totals are rounded.

The rate and intrinsic gas are *declared* rather than looked up, because
compilation must stay a pure function of the transaction and the batch
header (so Aptos can recompile a disputed transaction). A `VerifyGasAsset`
step checks both against state inside the trace; a wrong declaration makes
the batch provably invalid. Wallets read them, and the current base fee, from
`sena_gasPrice` (Celo's `eth_gasPrice` with a `feeCurrency`).

## Gas

`gas_used = 21,000 + asset intrinsic gas + authenticator + Σ instruction gas`

| Item | Gas |
|---|---|
| Every transaction (Ethereum's intrinsic gas) | 21,000 |
| Fee asset's own intrinsic gas (USDC at genesis) | 10,000 |
| Keyless authenticator (Groth16 + Poseidon) | 100,000 |
| Debit, Credit, Unbind | 5,000 each |
| Bind identifier, any governance write | 20,000 |
| Council verification | 10,000 + 3,000 per signature |
| Fee split check | 2,000 |

Compilation is static, so `gas_used` is known before anything runs. A
transaction whose `gas_limit` is below it is refused at admission instead of
being executed and charged for failing. A plain USDC transfer uses 41,000 gas.

The instruction weights are a first calibration, not benchmarked against
node or L1 cost.

## The base fee

A `FeeMarket` record in state holds the base fee, a governed **floor** and
**target**, and the current window. A window is one batch timestamp (one
second). When a batch's timestamp is past the window, the base fee takes one
EIP-1559 step from the last window's gas use:

```
above target: base + max(base × (gas − target) / target / 8, 1)
below target: base − base × (target − gas) / target / 8
never below the floor
```

A window may use up to twice its target; a transaction that would push it
past that is refused. Several idle seconds count as one step down, not one
per second — the floor bounds the fall anyway.

The base fee is priced in **native units** (micro-dollars, since SENA has no
native token) and converted into the fee asset at its rate, rounding down:
`base_in_asset = base_fee × rate / RATE_SCALE` (Celo's
`ConvertCeloToCurrency`). The sequencer states the batch's base fee in the
batch header, published on Aptos; a `ChargeBaseFee` step checks it against
the market and adds the transaction's gas to the window.

Genesis: floor 0.025 micro-dollars per gas, target 5,000,000 gas per second.
At the floor a USDC transfer costs **1,025 units — about a tenth of a cent**.

## Settlement

```
tip per gas = min(max_priority_fee_per_gas, max_fee_per_gas − base_in_asset)
price       = base_in_asset + tip per gas          (refused if max fee < base)
hold        = gas_limit × price                    (refused if it rounds to 0)
refund      = (gas_limit − gas_used) × price
tip         = gas_used × tip per gas
base        = gas_used × base_in_asset + whatever rounding left of the hold
```

Before the payload runs, `hold` is debited from the sender (Celo's
`debitGasFees`). After it, `refund` goes back to the sender, `tip` to the
sequencer named in the batch header, and `base` to the fee vault (Celo's
`creditGasFees`). Zero amounts are not credited. The three always sum to the
hold exactly.

## Where collected fees go

Base fees accumulate in the fee vault, an address no key controls. A
governed **fee split** (Celo's `FeeHandler`) names up to eight beneficiaries
with shares in parts per million and a burned share. Anyone may submit
`DistributeFees { asset, amount, split }`: the split is checked against state,
`amount` leaves the vault, each beneficiary is credited its share rounded
down, and the rest — burn and rounding — is credited to no one. Burning a
bridged asset on L2 leaves its backing locked in L1 custody for good.

## Governance and the circuit breaker

The council sets each asset's rate, intrinsic gas and enabled flag
(`SetGasAsset`), the fee market's floor and target (`SetFeeMarket`), and the
fee split (`SetFeeSplit`).

A **guardian threshold**, smaller than the council's, may *only disable* a fee
asset (`DisableGasAsset`) — the fast path of a circuit breaker, like Mento's
watchdogs. Re-enabling needs the full council. SENA has no price oracle, so
the breaker is tripped by people, not by a depeg detector; an automatic one
needs an oracle such as Chainlink's Aptos feeds.

## The sequencer's limits

Per fee asset, the sequencer can cap the share of a window's gas transactions
paying in it may use, in permille (Celo's `celo.feecurrency.limits`). Batches
are cut to what is left of the window and to 48 KiB of data, and always as a
prefix of the queue, since later transactions may depend on earlier ones.

## What is not copied from Celo

- **No native token.** Celo's base fee is denominated in CELO; SENA's in a
  unit of account converted at governed rates. A token could be added later
  as one more fee asset.
- **Rates are governed, not oracle-fed.** Celo reads `SortedOracles` before
  each block.
- **Mento is not copied.** SENA uses Circle's USDC rather than issuing its own
  stablecoin.
- **No failed-transaction charging.** Celo charges a reverted transaction for
  its gas; SENA refuses transactions that would not execute, because a batch
  executes completely or is invalid.
