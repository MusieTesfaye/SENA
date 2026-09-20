# Aptos L1 contracts

The settlement layer. These Move modules are what makes SENA's optimism safe:
they record bonded assertions, run the dispute game, execute the disputed step,
and gate withdrawals on finality.

> ## Status: written, not yet compiled
>
> **These contracts have not been compiled, tested, deployed, or audited.** They
> were written against the Rust reference implementation in [`../crates/`](../crates/),
> but the Aptos CLI could not be run in the environment they were developed in —
> the prebuilt binary requires AVX2, which that machine's CPU does not provide.
>
> Treat every module here as an unverified draft. The first thing anyone picking
> this up should do is:
>
> ```sh
> aptos move test --package-dir move/sena
> ```
>
> Expect to fix compilation errors. Nothing below should be deployed to any
> network until it compiles, its tests pass, and it has been independently
> audited — `sena::osp` most of all.

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

## How drift is caught today

The two implementations share conformance vectors. Each Move module embeds
constants — digests, encodings, discriminants, parameter values — produced by the
Rust reference, and two Rust test suites check them:

- [`crates/sena-stf/tests/conformance.rs`](../crates/sena-stf/tests/conformance.rs)
  produces the vectors and pins them against independently recomputed values.
- [`crates/sena-stf/tests/move_conformance.rs`](../crates/sena-stf/tests/move_conformance.rs)
  reads these `.move` files as text and fails if any embedded constant no longer
  matches what Rust computes.

The second runs in ordinary `cargo test`, with no Move toolchain. It is a weaker
check than running the Move tests — it proves the constants agree, not that the
code producing them is right — but it catches silent drift, which is the failure
mode that would otherwise go unnoticed until it mattered.

## Not yet implemented

- `osp` adjudicates account and identifier instructions. `VerifyGasAsset` and
  `VerifyCouncil` abort with `E_UNSUPPORTED_INSTRUCTION` rather than being
  approximated: a verifier that guesses is worse than one that declines.
- Bond custody and slashing are modelled as bookkeeping, not as real coin
  movement.
- `bridge::withdraw` verifies the proof and marks the withdrawal spent; it does
  not yet transfer assets.
- SDD §3.5.4 specifies compiling the state transition function to RV32IM and
  disputing individual machine instructions. Both implementations here bisect
  over a higher-level instruction set instead. The protocol structure is
  identical; the trade-off is discussed in
  [`crates/sena-stf/src/instruction.rs`](../crates/sena-stf/src/instruction.rs).
