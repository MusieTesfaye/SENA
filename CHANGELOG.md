# Changelog

Notable changes to SENA. Versions follow [semantic versioning](https://semver.org);
while below 1.0 the protocol may change in breaking ways between releases.

## [Unreleased]

### The Move contracts compile

All six Aptos L1 modules compile and **36 of 36 Move unit tests pass**. This was
the item blocking Gates B through G, and the earlier claim that it was blocked on
hardware was wrong: prebuilt Aptos CLI releases only lose baseline x86-64
support from `7.14.2` onward, and `7.9.0` runs fine without AVX2.

Two things had to line up:

- **CLI pinned to 7.9.0.** Later releases abort with SIGILL on CPUs without
  AVX2, which is every Intel Atom-lineage chip.
- **Framework pinned to `46d871fa`**, the tree tagged `aptos-cli-v7.9.0`. Later
  framework revisions use Move 2 syntax (`proof { }`, inline `spec { }`) that
  `7.9.0` cannot parse. `Move.toml` previously tracked the `mainnet` branch,
  which is a moving target and made the build unreproducible.

Three real fixes came out of the first compile:

- `osp::out_of_order_balances_are_rejected` expected its abort to originate in
  `sena::codec`. An abort originates where the `assert!` is; borrowing an error
  code from another module does not move it. The annotation was wrong, not the
  logic.
- A doc comment sat above a `#[view]` attribute in `bridge.move`, where the
  compiler could not attach it to anything.
- An unused `vector` import.

The cross-language conformance tests now execute on both sides, which is the
stronger check: `codec::sha256_matches_rust`, `trie::leaf_hash_matches_rust` and
`osp::machine_commitment_matches_rust` compute values in Move and compare them
against what Rust produced. Previously only the Rust side ran, comparing
constants in two files.

Still true: nothing is deployed to any network, nothing is audited, bond escrow
is bookkeeping rather than custody, and four instructions
(`VerifyGasAsset`, `VerifyCouncil`, `SetGasAsset`, `SetParameter`) abort rather
than being adjudicated — so a dispute over a gas-rate or governance step has no
L1 resolution path.

### Beta planning baseline No protocol behaviour changed; the parameters were
already what `sena-params` now freezes, and the binding tests prove it.

### Added

- **`sena-params`** — the frozen beta parameter set as a single source of truth,
  version `sena-beta-params-1`. Relationships between parameters are checked by
  `validate()` rather than asserted in prose: notably that both parties' dispute
  budgets fit inside the challenge window at *every* window the chain accepts,
  including the floor.
- **Parameter binding tests** so that a constant changed in the implementation
  without changing `sena-params`, or the reverse, fails the build and names the
  parameter.
- **`docs/beta/`** — the closed-beta scope freeze, decision log (D-01 to D-06),
  execution checklist with a real status for every item, and a generated
  requirements traceability matrix covering 51 of 101 SRS requirements.

#### Decisions

- **D-01: higher-level instruction trace** adopted as the beta execution target
  rather than RV32IM. The security argument does not depend on the step being a
  RISC-V instruction, and RV32IM sits directly in front of the thing the beta
  exists to prove. Requires an SRS/SDD amendment, which is outstanding.
- **D-03: keyless sign-in formally deferred.** The binding logic — the check
  these systems most often get wrong — stays implemented and enforced. Proof
  verification does not ship, and keyless transactions remain refused.

## [0.2.0-beta] — 2026-09-20

First release you can actually run. A node serves JSON-RPC over HTTP, seals
blocks, posts bonded assertions, and survives restarts; a verifier can rebuild
the chain from published data and catch a lying sequencer.

See [`STATUS.md`](STATUS.md) for what is and is not finished.

### Added

- **Runnable node.** `sena-node` CLI with `genesis`, `run`, `send`, `query`,
  `keygen` and `verify` subcommands.
- **HTTP JSON-RPC server** over a transport-agnostic handler, so the RPC surface
  stays testable without a socket.
- **Genesis configuration** as a JSON file, applied through the ordinary
  instruction set so genesis cannot diverge from execution. Two operators with
  the same file see the same state root.
- **Persistence** with self-verifying snapshots. A snapshot records its own root
  and is refused if rebuilding does not reproduce it; a data directory belonging
  to a different chain is refused too.
- **Keyless claim validation and ephemeral-key binding** (`sena-stf::keyless`).
  The check that matters — that a token's `nonce` commits to *this* ephemeral
  key — is implemented and tested, so a genuine JWT obtained elsewhere cannot be
  paired with an attacker's key. Proof verification remains unimplemented and
  keyless transactions are still refused.
- **End-to-end beta tests** driving a live HTTP node, including independent
  re-derivation of an asserted root from published batch data alone.

### Changed

- **Amounts travel as decimal strings in JSON.** `serde_json` cannot encode
  `u128`, and clients whose JSON numbers are doubles — JavaScript included —
  would have silently rounded balances above 2^53.
- **Transaction and governance signing digests use the canonical binary codec**
  rather than `serde_json`. What a user signs must be reproducible by anything
  that verifies the signature, including a Move contract.

### Fixed

- `u128` amounts could not be submitted over JSON-RPC at all. Found by running
  the system rather than by a unit test.

## [0.1.0] — 2026-09-20

The protocol, built in eight phases. Not runnable as a service; a library plus a
demonstration binary.

### Added

- `sena-primitives`: canonical encoding, hashing, OIDC address derivation,
  privacy-preserving identifier hashing, binary codec.
- `sena-state`: sparse Merkle trie with inclusion and non-inclusion proofs, and
  proof-based root derivation — the operation Aptos L1 performs while holding no
  state.
- `sena-stf`: accounts, transactions, multi-asset gas, bounded governance, and
  an execution model whose every instruction touches exactly one state slot, so
  one-step verification stays small enough for Move.
- `sena-fraudproof`: bonded assertions, interactive bisection, one-step
  adjudication, and verifier-node logic.
- `sena-node`: mempool, block production, verifier mode, RPC surface.
- `move/sena`: Aptos L1 contracts — written, not compiled.
- Cross-language conformance vectors, checked by `cargo test` without a Move
  toolchain.
- Determinism enforced mechanically: `HashMap`/`HashSet` denied workspace-wide,
  float arithmetic a deny-level lint, and CI diffing state roots across two
  separate processes.

### Fixed

- Dispute clock budgets were a fixed 48 hours per party — 96 hours in total,
  longer than the 24-hour challenge-window floor. A dispute could have outlived
  the window it exists to resolve within, letting fraud finalize while still
  under challenge. Budgets now derive from the window.
