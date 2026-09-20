# Changelog

Notable changes to SENA. Versions follow [semantic versioning](https://semver.org);
while below 1.0 the protocol may change in breaking ways between releases.

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
