# Aptos L1 contracts

The settlement layer. These Move modules are what makes SENA's optimism safe:
they record bonded assertions, run the dispute game, execute the disputed step,
and gate withdrawals on finality.

> ## Status: compiles and tests pass — not deployed, not audited
>
> All six modules compile and **36 of 36 Move unit tests pass**, including the
> cross-language conformance tests that check this implementation computes the
> same digests and encodings as the Rust reference.
>
> **Nothing here has been deployed to any network, and nothing has been
> audited.** Bond escrow is still bookkeeping rather than coin custody, and four
> instructions are not yet adjudicable (see *Not yet implemented* below).
>
> ```sh
> aptos move test --package-dir move/sena --named-addresses sena=0xCAFE
> ```

## Toolchain — read this before building

The CLI version matters, in both directions:

- **Prebuilt releases from `7.14.2` onward abort with SIGILL on CPUs without
  AVX2**, which includes every Intel Atom-lineage chip (Celeron N-series, Pentium
  Silver). `7.9.0` and earlier run on baseline x86-64.
- **The framework must match the compiler.** `Move.toml` pins the framework to
  commit `46d871fa…`, the tree tagged `aptos-cli-v7.9.0`. Later framework
  revisions use Move 2 syntax (`proof { }`, inline `spec { }`) that `7.9.0`
  cannot parse.

So: use CLI `7.9.0` with the pinned framework. [`.github/workflows/move.yml`](../.github/workflows/move.yml)
does exactly that and fails the build if `Move.toml` ever points at a branch
instead of a commit.

Moving to a newer CLI means moving the framework pin with it, and gives up the
ability to build on machines without AVX2.

## Modules

| Module | Responsibility |
|---|---|
| `codec` | Canonical encoding and hashing, mirrored from `sena-primitives` |
| `trie` | Sparse Merkle proof verification and post-state root derivation |
| `osp` | The one-step verifier — executes the disputed step and rules |
| `assertions` | The bonded assertion chain, challenge windows, finalization |
| `disputes` | The interactive bisection game, timeouts, and clocks |
| `bridge` | Custody, withdrawals against finalized roots, forced inclusion |

## Why `osp` is the module to scrutinise

It is the final arbiter of every dispute. If its RV32-equivalent step semantics
or its Merkle proof verification diverge from the Rust implementation, it decides
disputes wrongly — slashing an honest sequencer, or vindicating a fraudulent one.
Nothing else in the system can catch that, because nothing else is appealed to.

The SRS makes this a named requirement (NFR-SEC-012): independent audit before
mainnet, and top-tier bug bounty coverage.

## How drift is caught

The two implementations share conformance vectors, and both sides now execute:

- [`crates/sena-stf/tests/conformance.rs`](../crates/sena-stf/tests/conformance.rs)
  produces the vectors and pins them against independently recomputed values.
- [`crates/sena-stf/tests/move_conformance.rs`](../crates/sena-stf/tests/move_conformance.rs)
  reads these `.move` files as text and fails if any embedded constant no longer
  matches what Rust computes.

The second runs in ordinary `cargo test` with no Move toolchain, so drift is
caught even by contributors who cannot build Move.

The Move side now runs too, which is the stronger check: tests like
`codec::sha256_matches_rust`, `trie::leaf_hash_matches_rust` and
`osp::machine_commitment_matches_rust` compute values in Move and compare them
against what Rust produced. That is agreement on execution, not merely on
constants sitting in two files.

## Not yet implemented

- `osp` adjudicates account and identifier instructions. `VerifyGasAsset` and
  `VerifyCouncil` abort with `E_UNSUPPORTED_INSTRUCTION` rather than being
  approximated: a verifier that guesses is worse than one that declines. The
  consequence is concrete — **a dispute over a gas-rate or governance step
  cannot currently be settled on L1.**
- Bond custody and slashing are modelled as bookkeeping, not as real coin
  movement.
- `bridge::withdraw` verifies the proof and marks the withdrawal spent; it does
  not yet transfer assets.
- SDD §3.5.4 specifies compiling the state transition function to RV32IM and
  disputing individual machine instructions. Both implementations here bisect
  over a higher-level instruction set instead. The protocol structure is
  identical; the trade-off is discussed in
  [`crates/sena-stf/src/instruction.rs`](../crates/sena-stf/src/instruction.rs).
