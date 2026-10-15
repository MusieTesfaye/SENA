# SENA end to end

This guide takes SENA from source to a chain settling on Aptos: build it,
run an L2, send a stablecoin transfer and pay its fee in USDC, publish the
contracts, post blocks to Aptos, verify them independently, play a fraud
dispute to rejection, and deploy to testnet. Every command and every output
below comes from a real run.

If you only want to see it work, the [scripts](#9-the-scripts) do each part in
one command. This guide shows what they do, step by step.

**Contents**

1. [How it fits together](#1-how-it-fits-together)
2. [Prerequisites](#2-prerequisites)
3. [Run an L2](#3-run-an-l2)
4. [Pay fees in stablecoins](#4-pay-fees-in-stablecoins)
5. [Settle on Aptos](#5-settle-on-aptos)
6. [Fraud and disputes](#6-fraud-and-disputes)
7. [Keyless accounts](#7-keyless-accounts)
8. [Governance](#8-governance)
9. [The scripts](#9-the-scripts)
10. [Testnet](#10-testnet)
11. [The bridge](#11-the-bridge)
12. [Running it for real](#12-running-it-for-real)
13. [Reference](#13-reference)
14. [What does not work yet](#14-what-does-not-work-yet)

---

## 1. How it fits together

```
 wallet ──signed tx──▶ sequencer ──block──▶ relayer ──assertions::post──▶ ┌──────────────┐
 (Ed25519 or         (sena-node run)       (sena-node relay)              │  Aptos L1    │
  keyless)                 │                                              │              │
                           │ JSON-RPC                                     │  assertions  │
                           ▼                                              │  disputes    │
                       verifiers ◀── batch data, from L1 events ────────  │  bridge      │
                     (sena-node watch) ──open_challenge / dissect / ───▶  │  osp, gas…   │
                                         one_step                         └──────────────┘
```

- The **sequencer** orders transactions, executes them, and seals blocks
  every two seconds. A block is soft-confirmed at once and final only after
  its assertion survives the challenge window on Aptos.
- The **relayer** posts each block to Aptos as a **bonded assertion**,
  together with the block's transactions (the *batch data*): Aptos computes
  the batch root itself, so nobody can commit to data they will not reveal.
  It defends assertions in disputes and finalizes them once their window
  passes.
- A **watcher** trusts only Aptos and its own copy of the genesis file. It
  reads every assertion and its batch data from L1, re-executes it, and
  challenges anything wrong.
- A challenge is settled by **bisection**: the two sides narrow their
  disagreement to a single step, and Aptos executes that step itself —
  recompiling the disputed transaction from the published bytes, verifying
  its signature or keyless proof, and checking its effect on a Merkle proof
  of the state. The loser forfeits its bond.

The guarantee: an invalid state root cannot finalize while one honest
watcher is running.

## 2. Prerequisites

| Tool | Version | For |
|---|---|---|
| Rust | 1.85 or newer | everything |
| Aptos CLI | **7.9.0** (CI); 9.0–9.6 also pass the Move tests | contracts, localnet, testnet |
| Python 3 | any | the dispute and lifecycle scripts |

```sh
git clone https://github.com/MusieTesfaye/SENA.git
cd SENA
cargo build --release
export PATH="$PWD/target/release:$PATH"   # for sena-node
```

Check it:

```sh
cargo test --workspace                                        # 318 tests
aptos move test --package-dir move/sena --named-addresses sena=0xCAFE   # 78 tests
```

Why 7.9.0: prebuilt Aptos CLIs from 7.14.2 on abort on CPUs without AVX2,
and `Move.toml` pins the framework to the 7.9.0 tree. Newer CLIs compile
the package fine where they run.

## 3. Run an L2

### Keys

```sh
sena-node keygen > alice.txt
sena-node keygen > bob.txt
sena-node keygen > sequencer.txt
cat alice.txt
```

```
secret  4965226fe65dd9afd1cf08d14019cb7ff31773bafff855abc9e6ca0fd06534c7
public  760cbd5fb9d879ac58fe6a7201d910d0c2b9e9b1647a5e9784a18142691e60af
address 0x760cbd5fb9d879ac58fe6a7201d910d0c2b9e9b1647a5e9784a18142691e60af
```

An Ed25519 account's address *is* its public key. `keygen` is for testing:
it is not a wallet.

```sh
ALICE=$(awk '/^address/{print $2}' alice.txt); SECRET=$(awk '/^secret/{print $2}' alice.txt)
BOB=$(awk '/^address/{print $2}' bob.txt); SEQ=$(awk '/^address/{print $2}' sequencer.txt)
```

### Genesis

```sh
sena-node genesis --data-dir ./devnet --dev --fund "$ALICE:100000000"
```

```
genesis written to ./devnet/genesis.json
  chain            sena-devnet-1
  challenge window 86400s
  allocations      1
  state root       239189842d65840fd9d370ef8b8903da9b96cfced72cf2e91c5fda36badff9d1
```

That funds Alice with 100 USDC (asset 1, six decimals). **Two operators with
the same genesis file get the same state root** — compare it before trusting
anyone's chain. The file it writes:

```json
{
  "chain_id": "sena-devnet-1",
  "challenge_window_secs": 86400,
  "minimum_bond": "1000000",
  "network_salt": "sena-devnet-1-salt",
  "gas_assets": [
    { "asset": 1, "symbol": "USDC", "rate": "1000000", "intrinsic_gas": 10000, "enabled": true }
  ],
  "allocations": [
    { "address": "0x760c…60af", "asset": 1, "amount": "100000000" }
  ],
  "council": null,
  "keyless": null,
  "fee_market": null,
  "fee_split": null
}
```

The optional sections are covered in [governance](#8-governance),
[keyless](#7-keyless-accounts) and [fees](#4-pay-fees-in-stablecoins); see the
[genesis reference](#genesis-json).

### Run

```sh
sena-node run --data-dir ./devnet --listen 127.0.0.1:8545 --fee-recipient "$SEQ"
```

```
keyless accounts disabled (no `keyless` section in genesis)
starting a new chain from genesis
tips go to 0x9a1dc36491d0ad27d9d732b9f8eb3f0dad9c3cfac7427020c1da157e1512f6b5
sena-node listening on http://127.0.0.1:8545
```

`--fee-recipient` is the sequencer's own L2 account, where tips are paid;
without it they go to the fee vault. The node persists to the data
directory; restarted, it replays its saved blocks from genesis and refuses
to start if they do not reproduce its saved state:

```
resuming: replaying 1 saved blocks
```

### Send

```sh
RPC=http://127.0.0.1:8545
sena-node send --rpc $RPC --secret $SECRET --to $BOB --amount 5000000 --nonce 0 --tip 1000000000
```

```
gas 41000 at up to 50000000000 per gas (25000000000 base) in asset 1
{
  "confirmation": { "status": "pending" },
  "hash": "bc66d8a4c5e8add26dfc937c6ddefa7d6c5c76258d56ea2fd07e6bb28709156e",
  "result": "submitted"
}
```

`send` asked the node for a gas quote, set the gas limit to exactly the
41,000 gas a transfer uses, allowed the base fee to double, and offered a tip
of 0.001 units per gas (`--tip` is in 10⁻¹² units). Then:

```sh
sena-node query --rpc $RPC confirmation bc66d8a4…156e
```

```json
{ "height": 1, "result": "confirmation", "status": "soft_confirmed" }
```

**Submitted is not confirmed, and confirmed is not final.** `soft_confirmed`
means the sequencer included it; `finalized` comes only when the covering
assertion survives its window on Aptos (part 5).

```sh
sena-node query --rpc $RPC info
sena-node query --rpc $RPC account $ALICE
sena-node query --rpc $RPC block 1
sena-node query --rpc $RPC proof $ALICE       # a Merkle proof of the account
```

Or straight over HTTP — every method is listed in the [RPC reference](#json-rpc):

```sh
curl -s -X POST -H 'Content-Type: application/json' -d '{"method":"sena_getChainInfo"}' $RPC
```

## 4. Pay fees in stablecoins

Fees work like Celo's fee abstraction, without a native token. The full
model is in [`FEES.md`](FEES.md); this is what the transfer above paid.

**The quote** (`sena_gasPrice`, Celo's `eth_gasPrice` with a `feeCurrency`):

```sh
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"method":"sena_gasPrice","params":{"asset":1}}' $RPC
```

```json
{"result":"gasPrice","asset":1,"rate":"1000000","intrinsic_gas":10000,
 "base_fee_native":"25000000000","base_fee_per_gas":"25000000000",
 "suggested_max_fee_per_gas":"50000000000"}
```

**What the transaction declared** (from `query block 1`):

```
fee_asset 1 · fee_rate 1000000 · fee_intrinsic_gas 10000 · gas_limit 41000
max_fee_per_gas 50000000000 · max_priority_fee_per_gas 1000000000
```

**What it paid:**

| | Units of USDC | |
|---|---|---|
| Gas used | 41,000 | 21,000 intrinsic + 10,000 USDC's own + 2 × 5,000 (debit, credit) |
| Effective price | 0.026 / gas | base 0.025 + tip 0.001 (the 0.05 cap is not charged) |
| Held up front | 1,066 | 41,000 × 0.026 |
| Refunded | 0 | the limit was exactly the gas used |
| Tip → sequencer | **41** | 41,000 × 0.001 |
| Base fee → fee vault | **1,025** | 41,000 × 0.025 — about a tenth of a cent |

Balances afterwards — the books balance to the unit:

| Account | USDC |
|---|---|
| Alice | 94,998,934 = 100,000,000 − 5,000,000 − 41 − 1,025 |
| Bob | 5,000,000 |
| Sequencer | 41 |
| Fee vault (`0xfefe…fefe`) | 1,025 |

The block header records the batch's base fee and tip recipient:

```
height 1 · base_fee 25000000000 · fee_recipient 0x9a1d…f6b5 · trace_length 8
```

Eight steps: consume the nonce, verify the fee asset (rate and intrinsic
gas), charge the base fee against the fee market, hold the fee, debit Alice,
credit Bob, credit the tip, credit the base fee. Each one can be disputed on
Aptos.

**The base fee follows demand**: each one-second window aims at 5,000,000 gas;
a busier window raises the next one's base fee by up to 1/8, a quieter one
lowers it, never below the floor. A wallet that leaves room (as `send` does,
at twice the base fee) keeps working while it rises.

## 5. Settle on Aptos

This part uses a local Aptos node; [part 10](#10-testnet) does the same on
testnet.

### A localnet and two accounts

```sh
aptos node run-localnet --force-restart --assume-yes &     # REST :8080, faucet :8081

for p in proposer watcher; do
  aptos init --network local --profile $p --assume-yes < /dev/null
  aptos account fund-with-faucet --profile $p --amount 2000000000
done
acct() { aptos config show-profiles --profile $1 | python3 -c "import json,sys;print('0x'+json.load(sys.stdin)['Result']['$1']['account'])"; }
P=$(acct proposer); V=$(acct watcher)
```

The proposer runs the relayer; the watcher is an independent party. Aptos CLI
profiles live in `./.aptos` — keep it out of version control.

### Publish and initialise the contracts

The package is larger than one Aptos transaction, so it goes up in chunks:

```sh
aptos move publish --package-dir move/sena --named-addresses sena=$P \
  --chunked-publish --large-packages-module-address 0x7 \
  --profile proposer --max-gas 2000000 --assume-yes
```

```sh
aptos move run --function-id $P::assertions::initialize \
  --args hex:0x239189842d65840fd9d370ef8b8903da9b96cfced72cf2e91c5fda36badff9d1 \
         u64:86400 u128:1000000 address:0xa address:$P u64:3600 \
  --profile proposer --max-gas 200000 --assume-yes

aptos move run --function-id $P::disputes::initialize --args address:$P u8:0 \
  --profile proposer --max-gas 200000 --assume-yes
```

`assertions::initialize` takes, in order:

1. the **L2 genesis state root** — it must be the one `sena-node genesis`
   printed;
2. the challenge window in seconds (24 hours is the floor);
3. the minimum bond;
4. the bond asset (`0xa` is APT as a fungible asset);
5. the treasury, which receives what the winner of a dispute does not;
6. the most a batch timestamp may lag L1, in seconds.

`disputes::initialize` takes the keyless setup: 0 disabled, 1 Aptos mainnet
ceremony, 2 the insecure devnet key.

Always pass `--max-gas`: without it the CLI simulates first, and the
simulation endpoint can time out.

### Relay

With the L2 node running:

```sh
sena-node relay --rpc $RPC --aptos-url http://127.0.0.1:8080/v1 \
  --contract $P --profile proposer --account $P --state relayer.json --poll-interval 5
```

```
relaying to 0x57b6…41cf as 0x57b6…41cf
StepReport { posted: [1], dissected: [], timeouts_claimed: 0, finalized: [], rejected: [] }
```

Each round it answers any open dispute first (a missed deadline costs a
bond), then posts new blocks with their batch data and bond, then finalizes
what is past its window. Rounds with nothing to do print nothing. Progress is
saved after every change; restarted, it resumes — and it never re-posts an
assertion already on L1.

### Watch

From anywhere, with only the genesis file:

```sh
sena-node watch --data-dir ./devnet --aptos-url http://127.0.0.1:8080/v1 \
  --contract $P --profile watcher --account $V --state watcher.json --poll-interval 5
```

```
watching 0x57b6…41cf from assertion 1
WatchReport { verified: 1, challenged: [], moves: 0, concluded: 0 }
```

It checked that L1's genesis is its genesis, read assertion 1 and its batch
data from the `BatchPublished` event, re-executed it — with the base fee and
tip recipient the header declared — and reached the same root. Had it not,
it would have challenged (part 6).

### Finality

After the challenge window (24 hours here) the relayer finalizes the
assertion, and `query confirmation` reports `finalized`. Withdrawals can be
made only against finalized state.

## 6. Fraud and disputes

```sh
scripts/localnet-dispute.sh
```

plays a complete fraud dispute through real transactions. The batch has
three transactions; the second is a **keyless** transfer carrying Aptos's
real Groth16 proof, and the proposer credits it a thousandfold.

```
gas used per transaction:
      1072  assertions::post
       950  assertions::open_challenge
       536  disputes::open
        99  disputes::dissect
         7  disputes::select
         7  disputes::dissect
         7  disputes::select
       709  keyless_jobs::start
       352  keyless_jobs::advance
       145  keyless_jobs::advance       (×4)
       289  keyless_jobs::advance
       164  keyless_jobs::finish
        61  disputes::one_step
assertion status: 3 (3 = rejected)
OK: the forged keyless credit was rejected on chain
```

What happened:

1. **Post.** The proposer posts the assertion with its batch data and bond.
2. **Challenge.** The challenger bonds a challenge and opens a dispute.
3. **Bisect.** The defender offers commitments to intermediate machine states;
   the challenger picks the first segment it disagrees with. Two rounds
   narrow a 25-step trace to one step.
4. **Keyless verdict.** The disputed step lies in the keyless transaction, so
   Aptos must check its proof. One Poseidon hash plus a Groth16 check exceed a
   single transaction's execution budget, so `keyless_jobs` computes the
   verdict over several transactions, bound to the exact transaction bytes,
   batch time and setup.
5. **One step.** The challenger submits the leaf with its Merkle path in the
   batch, and a proof of the state slot. Aptos recompiles the transaction —
   including its fee charge, against the batch's declared base fee — runs the
   disputed step, and finds the defender's claimed post-state wrong. The
   assertion is rejected; the challenger is refunded and paid from the
   defender's bond.

That is **4,833 gas units from post to rejection** — under 0.005 APT at
100 octas per unit.

Some fraud needs no game at all. A **structural proof** settles it directly
from the batch data:

- `prove_uncompilable` — a published transaction that does not decode, does
  not authenticate, or could not pay its fee;
- `prove_start_gap` — a transaction that does not start where the previous
  one ended;
- `prove_trace_length` — a trace that does not end where the last
  transaction does.

The watcher picks the cheapest evidence that applies. A party that stops
moving loses by `claim_timeout`.

## 7. Keyless accounts

Users sign in with Google or another OpenID Connect provider instead of
holding a key. SENA verifies proofs for the audited Aptos Keyless circuit
(`circuit-v1.0.1`) against the Aptos mainnet ceremony key, on L2 and in
disputes on L1.

### Enable it in genesis

```json
"keyless": {
  "setup": "aptos-keyless-mainnet-2025-01",
  "jwks": [
    { "iss": "https://accounts.google.com", "kid": "<key id>", "n": "<RSA modulus, base64url>" }
  ]
}
```

The `jwks` are the provider's current signing keys, from its JWKS endpoint;
later rotations are council decisions (`SetJwk`). The insecure devnet setup,
`aptos-keyless-devnet-insecure`, needs `"allow_insecure_test_setup": true`
and exists only because Aptos publishes a real proof for it. Initialise
`disputes` with the matching setup id (1 for mainnet), and run `watch` with
the same genesis.

### The wallet flow

[`sena_node::keyless_client`](../crates/sena-node/src/keyless_client.rs) does
the wallet's side:

```rust
use sena_node::keyless_client::{assemble, sign, Jwt, KeylessSession, PepperClient, ProverClient, SignIn};

// 1. A fresh ephemeral key, its expiry and a blinder; the nonce commits to all three.
let session = KeylessSession::generate(expiry_unix_secs);
let nonce = session.nonce();          // put this in the OAuth request

// 2. The user signs in; the provider returns a JWT carrying that nonce.
let jwt = Jwt::parse(&jwt_string)?;

// 3. The pepper (it determines the address — always use the same source) and the proof.
let pepper = PepperClient { url: pepper_url }.fetch(&jwt_string, &session, "sub")?;
let sign_in = SignIn { session: &session, pepper, uid_key: "sub", extra_field: None,
                       exp_horizon_secs, jwk_n: &provider_modulus };
let proved = ProverClient { url: prover_url }.prove(&jwt_string, &sign_in)?;

// 4. The authenticator, refusing a proof for other public inputs.
let auth = assemble(&jwt, &sign_in, proved.proof, Some(proved.public_inputs_hash))?;

// 5. Sign transactions with the ephemeral key until it expires.
let signed = sign(tx, &session, auth);
```

The pepper and prover services are Aptos's (`POST /v0/fetch` and
`POST /v0/prove`). The client has been tested against Aptos's sample proof
and recorded responses; **no live sign-in has been run**, and training-wheels
signatures are not checked.

## 8. Governance

A council configured at genesis signs changes; each signed change is carried
in an ordinary transaction, so it is executed in a batch and disputable like
anything else. An `epoch` in every signature stops replays.

```json
"council": { "members": ["<ed25519 public key, hex>", "..."], "threshold": 2, "guardian_threshold": 1 },
"fee_market": { "base_fee_floor": "25000000000", "gas_target": 5000000 },
"fee_split": { "beneficiaries": [ { "address": "0x…", "share": 900000 } ], "burn": 100000 }
```

| Update | Signatures |
|---|---|
| `SetGasAsset` — add an asset, change its rate or intrinsic gas, re-enable it | council threshold |
| `SetFeeMarket` — base fee floor and gas target | council threshold |
| `SetFeeSplit` — fee beneficiaries and burn | council threshold |
| `SetJwk` — accept or retire a provider key | council threshold |
| `SetParameter` — allowlisted parameters only | council threshold |
| `DisableGasAsset` — the circuit breaker | **guardian threshold** |

The guardian threshold lets a few members switch off a stablecoin quickly —
if it loses its peg, say — while switching it back on needs the whole
council. There is no price oracle, so the breaker is tripped by people.

There is no CLI command for governance yet. A change is built with
`sena_stf`:

```rust
use sena_stf::{gas, CouncilSignature, GovernanceUpdate, Payload, Transaction};

let epoch = 0; // the council's current epoch
let update = GovernanceUpdate::SetFeeMarket { floor: 30_000_000_000, target: 5_000_000 };
let digest = update.signing_digest(epoch);
let signatures = vec![
    CouncilSignature { index: 0, signature: member0.sign(digest.as_bytes()).to_bytes() },
    CouncilSignature { index: 1, signature: member1.sign(digest.as_bytes()).to_bytes() },
];
let mut tx = Transaction { /* sender, nonce, fee_asset… */
    payload: Payload::Governance { epoch, update, signatures }, /* … */ };
gas::fill_fees(&mut tx, rate, intrinsic_gas, max_fee_per_gas);
// sign with the sender's key, then submit with sena_submitTransaction
```

Indices must be strictly increasing, so one member cannot count twice.

Collected base fees are paid out by anyone with
`Payload::DistributeFees { asset, amount, split }`. The `split` must be the
one in force; `amount` leaves the fee vault, each beneficiary gets its share
rounded down, and the rest is burned.

The challenge window, finalization and dispute rules are not governable: they
live in the Aptos contracts, which the L2 cannot change.

## 9. The scripts

| Script | Needs | Does |
|---|---|---|
| `scripts/localnet-dispute.sh` | a localnet | Parts 5–6 in one go: fresh accounts, publish, and the keyless fraud dispute to rejection |
| `scripts/localnet-agents.sh` | a localnet, `cargo build -p sena-node` | Part 5: a sequencer, the relayer posting, the watcher verifying; fails if the watcher challenges |
| `scripts/chain-lifecycle.sh local\|devnet\|testnet` | a network | Publish and initialise; then the safety checks — an underbonded post, finalizing early, a self-challenge and finalizing a challenged assertion must all be refused |
| `scripts/bridge-test.sh setup\|deposit\|status` | testnet, USDC | The bridge with Circle's testnet USDC |

CI runs the first two against a fresh localnet on every change
(`.github/workflows/move.yml`).

## 10. Testnet

Testnet has no programmatic faucet, so accounts are funded by hand.

```sh
scripts/chain-lifecycle.sh testnet
```

The first run creates two accounts, sees they are empty, and stops before
spending anything:

```
  0x7377…ab5b holds 0 octas; needs at least 400000000 (4.00000000 APT)
  0xb4b8…6573 holds 0 octas; needs at least 30000000 (0.30000000 APT)
  fund at https://aptos.dev/network/faucet?address=<address>, then rerun with:
    SENA_PROFILE=sena-testnet-… scripts/chain-lifecycle.sh testnet
```

Fund them at <https://aptos.dev/network/faucet> and rerun the printed command:
`11 passed, 0 failed`.

What testnet costs and needs that a localnet does not:

- **About 2.35 APT to publish**, mostly storage fees; the final publish
  transaction alone uses over a million gas units. Hold at least 4 APT.
- **`--large-packages-module-address 0x7`** on `--chunked-publish`. Aptos
  moved the module there; CLI 7.9.0 still defaults to its old testnet address,
  where staging fails with `LINKER_ERROR`.
- **A package whose public signatures changed cannot be published over the old
  one.** A new version of the contracts goes to new accounts.

The current deployment, with every transaction hash, is in
[`beta/evidence/04-testnet-deployment.md`](beta/evidence/04-testnet-deployment.md).

## 11. The bridge

```sh
aptos init --network testnet --profile sena-testnet --assume-yes < /dev/null
scripts/bridge-test.sh status      # prints the address and what it lacks
```

Fund it with APT and with USDC from <https://faucet.circle.com> (Aptos
testnet), then:

```sh
scripts/bridge-test.sh setup       # publish; initialise assertions, disputes, bridge
scripts/bridge-test.sh deposit     # 1 USDC into custody
scripts/bridge-test.sh status      # custody holds 1000000 USDC units across 1 deposit(s)
```

The bridge custodies Circle USDC through `dispatchable_fungible_asset`, so
Circle's blocklist and pause hooks apply. A withdrawal pays out against a
*finalized* assertion and a Merkle proof of the L2 balance
(`sena_getWithdrawalProof`), so it cannot happen until a window has passed.

**Deposits are not credited on L2 yet.** The deposit lands in custody and
emits an event, but nothing in the node reads it; see
[part 14](#14-what-does-not-work-yet).

## 12. Running it for real

**The sequencer**

- Bind to localhost, or set `--auth-token` (every request then needs
  `Authorization: Bearer <token>`); tune `--rate-limit`. The node warns when
  it listens publicly without a token.
- Set `--fee-recipient` to an account you control.
- Keep the data directory: it holds the state and every block's batch data,
  which the relayer needs to defend assertions for the whole challenge window.

**The relayer**

- Run it next to the sequencer, with `--rpc-token` if the RPC has one. Its
  Aptos profile holds the bond; keep that funded — every post locks
  `--bond` until finalization.
- It **halts if an assertion is rejected**, because building on a rejected
  state would only lose more bonds. Recovering — rolling the sequencer back
  to the last good assertion — is manual.

**Watchers**

- Run them anywhere, by anyone, with a copy of the genesis file. A
  challenge locks `--bond` until the dispute ends; a won dispute pays.
- The watcher reads batch data by scanning the proposer's transactions
  through the fullnode REST API, so it needs a fullnode that keeps history.
- It halts if a wrong assertion **finalized** before it saw it — L1's chain
  then contains fraud, and only people can decide what to do.

**Keys.** Both agents sign through an Aptos CLI profile; there is no HSM or
remote-signer support yet.

## 13. Reference

### `sena-node`

| Command | Purpose | Main flags |
|---|---|---|
| `keygen` | An Ed25519 keypair and its address | — |
| `genesis` | Write `genesis.json` | `--data-dir`, `--dev`, `--fund <address>:<amount>` (repeatable) |
| `run` | Sequencer and JSON-RPC server | `--data-dir`, `--listen`, `--block-interval` (2), `--fee-recipient`, `--auth-token`, `--rate-limit` (600), `--run-for` |
| `send` | Sign and submit a transfer | `--rpc`, `--secret`, `--to`, `--amount`, `--nonce`, `--asset` (1), `--tip` |
| `query` | `info`, `account <addr>`, `block <h>`, `confirmation <hash>`, `proof <addr> [--height]` | `--rpc` |
| `relay` | Post, defend, finalize on Aptos | `--rpc`, `--rpc-token`, `--aptos-url`, `--contract`, `--profile`, `--account`, `--bond`, `--state`, `--max-gas`, `--poll-interval`, `--aptos-bin` |
| `watch` | Verify from L1 and challenge | `--data-dir`, `--aptos-url`, `--contract`, `--profile`, `--account`, `--bond`, `--state`, `--keyless-steps-per-tx` (12), … |
| `verify` | Prints the genesis root; use `watch` for verification | `--data-dir`, `--rpc` |

`cargo run --release --bin sena-demo` runs three scenarios in-process: an
honest chain, a caught fraud, and a withdrawal refused before finality.

### JSON-RPC

`POST` JSON `{"method": "...", "params": {...}}`.

| Method | Params | Returns |
|---|---|---|
| `sena_submitTransaction` | a transaction | its hash, `pending` |
| `sena_getAccount` | `address` | nonce and balances |
| `sena_gasPrice` | `asset` | rate, intrinsic gas, base fee (native and in the asset), a suggested max fee |
| `sena_getConfirmation` | `hash` | `pending`, `soft_confirmed` or `finalized`, with the height |
| `sena_getBlock` | `height` | header (timestamp, base fee, tip recipient), transactions, trace length, start positions, assertion |
| `sena_getChainInfo` | — | chain id, height, finalized height, window, state root, mempool size |
| `sena_getStateRoot` · `sena_getFinalizedHeight` | — | |
| `sena_getAssertion` | `id` | status and time left in its window |
| `sena_getAccountProof` | `address`, optional `height` | a Merkle proof for light clients |
| `sena_getWithdrawalProof` | `address` | a proof against the latest finalized root |
| `sena_resolveIdentifier` | `identifier` | the address a hashed handle is bound to |
| `sena_getTraceCommitments` | `height`, `steps` | machine-state commitments (the relayer uses these to dissect) |
| `sena_getDaBlob` | `height` | the block's batch data, as published |

Amounts are decimal strings, because JSON numbers cannot carry a `u128`.

### Aptos contracts

| Entry function | Arguments after the signer |
|---|---|
| `assertions::initialize` | genesis root, window, minimum bond, bond asset, treasury, max batch age |
| `assertions::post` | chain, parent, pre-root, post-root, timestamp, base fee, tip recipient, transactions, start positions, trace length, bond |
| `assertions::open_challenge` | chain, assertion, bond |
| `assertions::finalize` | chain, assertion |
| `disputes::initialize` | chain, keyless setup |
| `disputes::open` · `dissect` · `select` · `one_step` · `claim_timeout` | the bisection game |
| `disputes::prove_uncompilable` · `prove_start_gap` · `prove_trace_length` | structural fraud proofs |
| `keyless_jobs::start` · `advance` · `finish` | a keyless verdict across transactions |
| `bridge::initialize` · `deposit` · `withdraw` · `force_include` | custody |

Views: `assertions::{assertion_count, assertion_at, record, status,
challengers, challenge_window, minimum_bond, escrow_balance}`,
`disputes::{dispute_state, disputed_step, winner, keyless_setup}`,
`keyless_jobs::progress`,
`bridge::{custody_balance, deposit_count, is_spent, is_overdue}`.

### Genesis JSON

| Field | Meaning |
|---|---|
| `chain_id`, `network_salt` | the chain's identity; the salt hashes social handles |
| `challenge_window_secs` | at least 86,400 |
| `minimum_bond` | decimal string |
| `gas_assets[]` | `asset`, `symbol`, `rate` (units per 10⁶ native units), `intrinsic_gas` (default 10,000), `enabled` |
| `allocations[]` | `address`, `asset`, `amount` |
| `council` | `members` (hex keys), `threshold`, `guardian_threshold` (default 0: no fast path) |
| `fee_market` | `base_fee_floor` (10⁻¹² native units per gas), `gas_target`; defaults 25,000,000,000 and 5,000,000 |
| `fee_split` | `beneficiaries[]` of `address` and `share`, and `burn`, in parts per million summing to 1,000,000 |
| `keyless` | `setup`, `allow_insecure_test_setup`, `jwks[]` of `iss`, `kid`, `n` |

### Where things are

| Path | What |
|---|---|
| `crates/sena-stf` | the state machine: transactions, fees, keyless, governance, execution |
| `crates/sena-fraudproof` | assertions, bisection, one-step adjudication |
| `crates/sena-node` | sequencer, RPC, relayer, watcher, keyless client, CLI |
| `crates/sena-state` | the sparse Merkle trie |
| `crates/sena-light-client` | proof checks for mobile clients |
| `crates/sena-params` | the frozen parameter set |
| `move/sena` | the Aptos contracts |
| `docs/FEES.md` | the fee model |
| `docs/TESTING.md` | what each test layer proves |
| `STATUS.md` | what works and what does not |

## 14. What does not work yet

The full list is in [`STATUS.md`](../STATUS.md). The parts of this guide
they touch:

- **Nothing is audited.** Do not put real value on it.
- **Deposits do not reach L2.** `bridge::deposit` takes custody, but no
  instruction credits the deposit on L2, and the event names an Aptos
  address rather than an L2 one. Today L2 balances come only from genesis.
- **No dispute has been played on testnet**, and the relayer and watcher have
  run against localnets only.
- **No live keyless sign-in** against Aptos's prover and pepper services, and
  training-wheels signatures are unchecked.
- **Recovery after a rejected assertion is manual.**
- **No governance or fee-distribution CLI**; both are built with `sena_stf`.
- **`sena-node verify` is a stub** — use `watch`.
- The per-instruction gas weights are a first calibration; the breaker is
  manual; rates are council-set rather than oracle-fed.
