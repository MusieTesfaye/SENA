# SENA Network

A Layer 2 blockchain that puts Web2 ergonomics into the protocol itself — sign in with
Google or Apple, send to a handle instead of a hex address, pay fees in stablecoins —
and anchors settlement to **Aptos L1** with an enforceable **fraud proof** system.

> **Status: pre-alpha, under active construction.** This repository is being built out
> phase by phase against the specifications in [`docs/`](docs/). Nothing here has been
> audited, and nothing here has been deployed to any network. Do not use it with real
> funds.

## What problem this solves

Using a blockchain today means holding a seed phrase you can never lose and buying a
volatile token before you can do anything at all. Most people bounce off that. The usual
workaround is to put a trusted operator in the middle, which quietly hands custody back
to a company.

SENA takes the position that both are avoidable, and that the fix belongs in the network
rather than in every application:

| Friction | SENA's answer |
|---|---|
| Seed phrases | OIDC keyless accounts — log in with an existing Web2 identity |
| Buying a gas token | Pay fees in whitelisted stablecoins |
| `0x7f3a9c…` addresses | Human-readable handles, stored as salted hashes |
| Trusting the operator | Bonded state roots, published data, permissionless fraud proofs |

## How it fits together

SENA runs a fast sequencer that executes transactions locally in seconds, and
periodically commits a Merkle root of all balances to a Move contract on Aptos L1.
Aptos is the system of record; SENA is the fast desk in front of it. If the sequencer is
compromised or disappears, funds are withdrawable directly from L1.

Committing a state root makes history *permanent*, not *correct* — a compromised
sequencer could commit a root describing balances no honest execution would produce.
Fraud proofs close that gap:

1. Every root is posted as a **bonded assertion** that finalizes only after a challenge window.
2. The **batch data is published**, so anyone can re-execute the chain independently.
3. **Anyone may challenge**, without permission or allowlisting.
4. A challenge is settled by **bisection** down to a single step, which **Aptos L1 executes itself**.

The resulting guarantee: an invalid state root cannot finalize so long as *one* honest
party is watching. The cost: trust-minimised withdrawal to L1 takes a challenge window.

## Build plan

Each phase lands as a reviewable commit with tests that pass in CI.

| Phase | Crate / area | Status |
|---|---|---|
| 0 | Workspace, CI, determinism lints | ✅ done |
| 1 | `sena-primitives` — hashes, addresses, OIDC derivation | ✅ done |
| 2 | `sena-state` — sparse Merkle trie, inclusion proofs | ✅ done |
| 3 | `sena-stf` — accounts, transactions, execution | ⬜ |
| 4 | Social Connect, Gas Paymaster, Governance modules | ⬜ |
| 5 | `sena-fraudproof` — assertions, bisection, one-step proofs | ⬜ |
| 6 | `sena-node` — mempool, block production, RPC, verifier mode | ⬜ |
| 7 | Move L1 contracts, end-to-end adversarial dispute tests | ⬜ |

## Building

```sh
cargo test --workspace      # run everything
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Determinism is a security property

Fraud proofs only work if every honest node computes byte-identical results — a verifier
that diverges from an honest sequencer opens a challenge it will lose. `SRS REQ-FRAUD-031`
therefore forbids the state transition function from depending on floating point, wall
clock, entropy, address layout, or the iteration order of unordered collections.

This is enforced mechanically rather than by convention: `HashMap` and `HashSet` are
denied workspace-wide in [`clippy.toml`](clippy.toml), float arithmetic is a deny-level
lint, and CI executes the state-root tests twice in separate processes and diffs the
results.

## Documentation

The specifications this implementation is built against live in [`docs/`](docs/), with
editable Markdown sources in [`docs/src/`](docs/src/) and a rebuild script
(`python3 docs/src/build.py`).

- **Project Proposal** — the case for the network
- **PRD** — users, features, success metrics
- **SRS** — numbered, testable requirements (`REQ-*`, `NFR-*`)
- **SDD** — architecture, module design, data structures, security analysis

Code in this repository cites the requirement it implements (`REQ-FRAUD-012`, and so on)
so that the specification and the implementation can be checked against each other.

## License

Apache-2.0. See [LICENSE](LICENSE).
