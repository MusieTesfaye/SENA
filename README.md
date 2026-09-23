# SENA Network

A Layer 2 blockchain that puts Web2 ergonomics into the protocol itself — sign in
with Google or Apple, send to a handle instead of a hex address, pay fees in
stablecoins — and anchors settlement to **Aptos L1** with enforceable **fraud
proofs**.

<p>
<img alt="status" src="https://img.shields.io/badge/status-beta-orange">
<img alt="tests" src="https://img.shields.io/badge/tests-248%20rust%20%2B%2045%20move-brightgreen">
<img alt="devnet" src="https://img.shields.io/badge/aptos-devnet%20deployed-blue">
<img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue">
</p>

> ### Beta — read this before using it
>
> The Rust node runs, seals blocks, serves JSON-RPC, and survives restarts. A
> verifier can rebuild the chain from published data and catch a lying sequencer.
> That part is real and tested.
>
> **It has not been audited. Nothing has been deployed to any network. Keyless
> sign-in is not finished.** Do not put real funds anywhere near it.
>
> [`STATUS.md`](STATUS.md) is the honest, line-by-line account of what works
> today and what does not. Read it before forming a view.

## Quickstart

You need [Rust](https://rustup.rs) 1.85 or newer. Nothing else.

```sh
git clone https://github.com/MusieTesfaye/SENA.git
cd SENA
cargo build --release
```

### 1. See the whole protocol in 30 seconds

```sh
cargo run --release --bin sena-demo
```

Three scenarios, run against the real implementation with no mocks:

1. An honest sequencer seals a block; an independent verifier rebuilds the chain
   from published data alone and reaches the same state root.
2. A sequencer executes a debit of 1 where the batch says 1,000 and pockets the
   difference. The verifier catches it, challenges, and bisection narrows 48
   execution steps down to the falsified one in two rounds — then Aptos L1
   executes that single step and throws the assertion out.
3. A withdrawal is refused against a pending state root and honoured once the
   challenge window has elapsed.

### 2. Run your own devnet

```sh
# A keypair to play with. Note the secret and the address.
./target/release/sena-node keygen

# A genesis config that funds it.
./target/release/sena-node genesis \
    --data-dir ./devnet --dev \
    --fund 0xYOUR_ADDRESS:100000000

# Start the node.
./target/release/sena-node run --data-dir ./devnet --listen 127.0.0.1:8545
```

The node prints its state root on startup. **Two operators with the same genesis
file must see the same root** — that is how you tell you are on the same chain
before exchanging a single transaction.

### 3. Send a transaction

In another terminal:

```sh
RPC=http://127.0.0.1:8545

./target/release/sena-node query --rpc $RPC info

./target/release/sena-node send --rpc $RPC \
    --secret YOUR_SECRET \
    --to 0x1111111111111111111111111111111111111111111111111111111111111111 \
    --amount 1000 --nonce 0

# Blocks seal every 2 seconds by default.
./target/release/sena-node query --rpc $RPC account 0x1111...1111
./target/release/sena-node query --rpc $RPC block 1
```

Or straight over HTTP:

```sh
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"method":"sena_getChainInfo"}' $RPC
```

```json
{
  "result": "chainInfo",
  "chain_id": "sena-devnet-1",
  "height": 1,
  "finalized_height": 0,
  "challenge_window_secs": 86400,
  "state_root": "1986fed2f06f98ab…",
  "mempool_size": 0
}
```

Note `height: 1` alongside `finalized_height: 0`. The block is sealed and its
state is real, but its assertion has not survived the challenge window yet, so
nothing can be withdrawn against it. **Soft confirmation and L1 finality are
different things**, and every response that touches a transaction keeps them
apart.

### 4. It runs on Aptos devnet

The contracts are published and the lifecycle is verified on chain. Aptos itself
rejects the two things it must:

```
assertions::finalize  (inside challenge window)  →  E_WINDOW_OPEN
assertions::finalize  (while challenged)         →  E_WRONG_STATUS
```

Transaction hashes and a reproduction script are in
[`docs/beta/evidence/03-devnet-deployment.md`](docs/beta/evidence/03-devnet-deployment.md).
No bonds move yet — posting an assertion costs gas and nothing else.

### 5. Verify the chain yourself

Do not take the node's word for its own state root. Fetch the published
transactions and re-execute them:

```sh
cargo test -p sena-node --test beta_e2e -- --nocapture
```

`published_batch_data_reproduces_the_asserted_root` does exactly that — pulls a
block over HTTP, replays it from genesis independently, and asserts the root
matches. That test failing would mean the sequencer had lied.

## What problem this solves

Using a blockchain today means holding a seed phrase you can never lose and
buying a volatile token before you can do anything. Most people bounce off that.
The usual workaround is to put a trusted operator in the middle — which quietly
hands custody back to a company.

SENA's position is that both are avoidable, and that the fix belongs in the
network rather than in every application:

| Friction | SENA's answer |
|---|---|
| Seed phrases | OIDC keyless accounts — sign in with an existing Web2 identity |
| Buying a gas token | Pay fees in whitelisted stablecoins |
| `0x7f3a9c…` addresses | Human-readable handles, stored as salted hashes |
| Trusting the operator | Bonded state roots, published data, permissionless fraud proofs |

## How it fits together

A fast sequencer executes transactions locally in seconds and periodically
commits a Merkle root of all balances to a Move contract on Aptos L1. Aptos is
the system of record; SENA is the fast desk in front of it. If the sequencer is
compromised or disappears, funds are withdrawable directly from L1.

Committing a state root makes history *permanent*, not *correct* — a compromised
sequencer could commit a root describing balances no honest execution would
produce. Fraud proofs close that gap:

1. Every root is posted as a **bonded assertion** that finalizes only after a
   challenge window.
2. The **batch data is published**, so anyone can re-execute independently.
3. **Anyone may challenge**, without permission or allowlisting.
4. A challenge is settled by **bisection** down to a single step, which **Aptos
   L1 executes itself**.

The guarantee: an invalid state root cannot finalize while *one* honest verifier
is watching. The cost: trust-minimised withdrawal takes a challenge window.

## Repository layout

| Crate | What it does |
|---|---|
| [`sena-primitives`](crates/sena-primitives) | Hashes, OIDC address derivation, identifier hashing, canonical codec |
| [`sena-state`](crates/sena-state) | Sparse Merkle trie, inclusion and non-inclusion proofs |
| [`sena-stf`](crates/sena-stf) | Accounts, transactions, gas, governance, keyless, execution traces |
| [`sena-fraudproof`](crates/sena-fraudproof) | Bonded assertions, bisection, one-step adjudication |
| [`sena-node`](crates/sena-node) | Mempool, block production, RPC, verifier mode, CLI |
| [`move/sena`](move/sena) | Aptos L1 contracts — **deployed to devnet**, 45/45 tests, see [`move/README.md`](move/README.md) |

## Determinism is a security property

Fraud proofs only work if every honest node computes byte-identical results — a
verifier that diverges from an honest sequencer opens a challenge it will lose.
`SRS REQ-FRAUD-031` therefore forbids the state transition function from
depending on floating point, wall clock, entropy, address layout, or the
iteration order of unordered collections.

This is enforced mechanically, not by convention: `HashMap` and `HashSet` are
denied workspace-wide in [`clippy.toml`](clippy.toml), float arithmetic is a
deny-level lint, and CI executes the state-root tests twice in separate
processes and diffs the results.

## Development

```sh
cargo test --workspace                                    # 248 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The Move contracts need the [Aptos CLI](https://aptos.dev/tools/aptos-cli/),
**version 7.9.0 specifically**:

```sh
aptos move test --package-dir move/sena --named-addresses sena=0xCAFE
```

The version is pinned in both directions and it matters. Prebuilt releases from
`7.14.2` onward abort with SIGILL on CPUs without AVX2 — every Intel
Atom-lineage chip. And `Move.toml` pins the framework to the commit tagged
`aptos-cli-v7.9.0`, because later framework revisions use Move 2 syntax that
`7.9.0` cannot parse. See [`move/README.md`](move/README.md).

## Beta planning

The closed-beta scope, decisions and status live in [`docs/beta/`](docs/beta/):

- [`BETA_SCOPE.md`](docs/beta/BETA_SCOPE.md) — what the beta includes, what is
  deferred, and why
- [`DECISION_LOG.md`](docs/beta/DECISION_LOG.md) — decisions with alternatives
  and reasoning
- [`BETA_EXECUTION_CHECKLIST.md`](docs/beta/BETA_EXECUTION_CHECKLIST.md) — a
  status for every item, including the ones that are blocked
- [`TRACEABILITY.md`](docs/beta/TRACEABILITY.md) — every SRS requirement mapped
  to the code and tests that cite it, generated from source

Protocol parameters are frozen in [`crates/sena-params`](crates/sena-params) as
a single source of truth, with the relationships between them checked by test
rather than asserted in prose.

## Documentation

Specifications live in [`docs/`](docs/), with editable Markdown sources in
[`docs/src/`](docs/src/) and a rebuild script (`python3 docs/src/build.py`).

- **Project Proposal** — the case for the network
- **PRD** — users, features, success metrics
- **SRS** — numbered, testable requirements (`REQ-*`, `NFR-*`)
- **SDD** — architecture, module design, data structures, security analysis

Code cites the requirement it implements (`REQ-FRAUD-012`, and so on), so the
specification and the implementation can be checked against each other.

## License

Apache-2.0. See [LICENSE](LICENSE).
