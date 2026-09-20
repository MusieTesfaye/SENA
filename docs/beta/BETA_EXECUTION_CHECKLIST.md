# SENA Closed-Beta Execution Checklist

**Use:** Update during implementation. Every checked item should link to a
commit, test, deployment record, transaction hash, log archive, or review
finding.

**Status values:** `Not started` · `In progress` · `Blocked` · `Complete` · `Deferred by beta scope`

> **Statuses as of `v0.2.0-beta` (2026-09-20).** Filled in against the actual
> repository rather than left blank. Where an item is `Complete`, the evidence
> column names what to check. Where it is `Blocked`, the blocker is named.
>
> The single item blocking the most downstream work is **§6 Move compilation** —
> blocked on hardware, not on a design question.

## 1. Release identity and scope

- [x] `Complete` — Create a beta branch and assign a beta version. → tag `v0.2.0-beta`; `PROTOCOL_VERSION` in [`sena-params`](../../crates/sena-params/src/lib.rs)
- [ ] `In progress` — Record the exact Rust compiler, target, Aptos CLI, Aptos framework revision, Move package hash, and STF binary hash. → Rust pinned in [`rust-toolchain.toml`](../../rust-toolchain.toml); **Aptos CLI and Move package hash blocked on compilation**
- [x] `Complete` — Publish a beta scope addendum stating which PRD/SRS features are included. → [`BETA_SCOPE.md`](BETA_SCOPE.md)
- [x] `Complete` — Mark keyless login, multi-asset gas, governance, fast withdrawals, and decentralized sequencing as included or deferred. → [`BETA_SCOPE.md` §3](BETA_SCOPE.md), [`DECISION_LOG.md`](DECISION_LOG.md)
- [x] `Complete` — Resolve the RV32IM versus higher-level trace decision. → D-01, **proposed, awaiting sign-off**; SRS/SDD amendment outstanding
- [x] `Complete` — Freeze canonical encodings for transactions, batches, assertions, proofs, state nodes, and withdrawals. → [`codec.rs`](../../crates/sena-primitives/src/codec.rs); conformance vectors in [`conformance.rs`](../../crates/sena-stf/tests/conformance.rs)
- [x] `Complete` — Freeze beta protocol parameters and their bounds. → [`sena-params`](../../crates/sena-params), set `sena-beta-params-1`; bounds checked by `validate()`
- [x] `Complete` — Complete the decision log. → [`DECISION_LOG.md`](DECISION_LOG.md); four decisions remain open pending external inputs

## 2. Build reproducibility and conformance

- [x] `Complete` — Pin the Rust toolchain and build image. → [`rust-toolchain.toml`](../../rust-toolchain.toml)
- [ ] `Blocked` — Pin Aptos CLI and Aptos framework inputs. → `Move.toml` pins `rev = "mainnet"`, which is a moving target and must be pinned to a commit
- [ ] `Not started` — Make clean builds reproducible.
- [ ] `Blocked` — Record and verify the STF binary hash. → depends on D-01 sign-off and the execution target
- [x] `Complete` — Add Rust-to-Move conformance tests for state roots and proof encodings. → [`move_conformance.rs`](../../crates/sena-stf/tests/move_conformance.rs) — checks constants agree; does **not** compile Move
- [x] `Complete` — Cover malformed, truncated, duplicate, reordered, and non-canonical inputs. → [`account.rs`](../../crates/sena-stf/src/account.rs) tests; [`codec.rs`](../../crates/sena-primitives/src/codec.rs) tests
- [x] `Complete` — Test empty batches, single-transaction batches, large batches, deletion, overwrite, and boundary values. → [`trie_properties.rs`](../../crates/sena-state/tests/trie_properties.rs), [`execution.rs`](../../crates/sena-stf/tests/execution.rs)
- [ ] `In progress` — Test deterministic output across clean machines and supported CPU architectures. → CI runs the state-root tests twice in separate processes; **single architecture only**
- [x] `Complete` — Ensure no STF behavior depends on wall-clock time, entropy, unordered iteration, thread scheduling, or ambient environment. → `HashMap`/`HashSet` denied workspace-wide in [`clippy.toml`](../../clippy.toml); float arithmetic a deny-level lint
- **Evidence:** [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml); conformance vectors printable with `cargo test -p sena-stf --test conformance -- --nocapture`

## 3. Durable sequencer and node

- [ ] `In progress` — Implement durable state storage. → file-backed snapshots in [`store.rs`](../../crates/sena-node/src/store.rs); **RocksDB/NOMT not integrated**
- [ ] `In progress` — Persist accounts, blocks, transactions, roots, assertions, batches, challenges, checkpoints, and verifier results. → state, blocks, batches and the assertion chain persist; **challenges, checkpoints and verifier results do not**
- [x] `Complete` — Implement crash-safe commit ordering. → temp-file-and-rename in `store.rs`
- [x] `Complete` — Recover cleanly after process termination at every commit boundary. → snapshots self-verify against a recorded root; corrupt and cross-chain data refused
- [ ] `Not started` — Retain challenge-window evidence and execution checkpoints.
- [ ] `Not started` — Define safe garbage collection for finalized history and dispute evidence.
- [x] `Complete` — Implement live RPC transport. → [`server.rs`](../../crates/sena-node/src/server.rs), HTTP JSON-RPC
- [x] `Complete` — Version RPC responses and distinguish soft confirmation from L1 finality. → `Confirmation` enum; `sena_getAssertion` reports window remaining
- [ ] `Not started` — Add authentication, authorization, rate limits, and request size limits. → **beta blocker for any exposed endpoint**
- [x] `Complete` — Provide node initialization, replay, inspection, and recovery commands. → `sena-node genesis / run / query / send / keygen`
- **Evidence:** [`beta_e2e.rs`](../../crates/sena-node/tests/beta_e2e.rs) — restart, corruption and cross-chain tests

## 4. Batch publication and data availability

- [ ] `Not started` — Select Aptos or external DA for beta. → open decision in [`DECISION_LOG.md`](DECISION_LOG.md)
- [x] `Complete` — Implement canonical batch serialization.
- [ ] `In progress` — Publish complete ordered batch data. → served over RPC (`sena_getBlock`); **not published to L1 or any DA layer**
- [x] `Complete` — Record the data commitment in every assertion. → `Assertion::batch_commitment`
- [ ] `In progress` — Implement retrieval by assertion ID and commitment. → retrieval is by height, not commitment
- [ ] `Not started` — Verify the commitment before replay.
- [ ] `Not started` — Retain data through pending descendants and open disputes.
- [ ] `Not started` — Implement data-availability challenges.
- [ ] `Not started` — Define rejection and bond outcomes for missing data.
- [ ] `Not started` — Test altered, truncated, unavailable, delayed, duplicated, and wrong-commitment data.

> **This section is the weakest part of the system.** Batch data currently comes
> from the same node that produced the assertion. A sequencer that withholds it
> cannot be challenged, which is precisely the failure fraud proofs exist to
> prevent. Until data is published independently, the security claim is
> incomplete.

## 5. Aptos settlement adapter

- [ ] `Not started` — Implement signed Aptos transaction submission.
- [ ] `Not started` — Implement sequence-number management and retries.
- [ ] `Not started` — Implement gas-budget handling and confirmation tracking.
- [ ] `In progress` — Publish assertions with all required fields. → the structure exists and is tested; **nothing is submitted to Aptos**
- [x] `Complete` — Record parent assertion and state-root continuity. → enforced by `AssertionChain::post`
- [ ] `Not started` — Submit challenges and bisection moves.
- [ ] `Not started` — Submit one-step proofs and timeout actions.
- [ ] `Not started` — Watch events and assertion status.
- [ ] `Not started` — Persist a local L1 mirror.
- [ ] `Not started` — Reconcile the local mirror with Aptos resources and events.
- [ ] `Not started` — Handle rejected, delayed, duplicated, and rate-limited L1 transactions.

> The assertion chain is a Rust state machine. **No SENA transaction has ever
> been submitted to Aptos.**

## 6. Move contract lifecycle and authorization

- [ ] `Blocked` — Compile the full Move package in clean CI. → **the Aptos CLI requires AVX2; the development machine does not have it.** Needs different hardware or a source build. This blocks Gates B through G.
- [ ] `Blocked` — Run Move unit tests in clean CI. → tests are written ([`move/sena/sources/`](../../move/sena/sources)) and have never executed
- [ ] `Blocked` — Add coverage and publish the coverage artifact.
- [ ] `Not started` — Verify all public functions enforce valid lifecycle stages.
- [ ] `Not started` — Add signer or capability checks for privileged transitions.
- [ ] `Not started` — Prevent unauthorized dispute resolution.
- [x] `Complete` — Prevent governance from finalizing assertions, dismissing challenges, or weakening safety floors. → by construction: no such entry point exists in `assertions.move` or `disputes.move`; window floor clamped in code
- [ ] `Not started` — Implement real assertion bond escrow. → modelled as bookkeeping, not coin movement
- [ ] `Not started` — Implement challenger bond escrow.
- [ ] `Not started` — Implement refund, slash, reward, and treasury accounting.
- [ ] `Not started` — Ensure each settlement action is exactly-once.
- [ ] `In progress` — Connect OSP results to dispute and assertion status. → implemented in Rust; Move side written and uncompiled
- [x] `Complete` — Implement descendant rejection and rollback semantics. → `challenger_won` sweeps descendants; tested in Rust
- [ ] `Not started` — Emit lifecycle events.

## 7. Fraud-proof and verifier lifecycle

- [x] `Complete` — Provide a documented independent verifier mode. → [`verifier_node.rs`](../../crates/sena-node/src/verifier_node.rs)
- [x] `Complete` — Start a verifier from an empty data directory. → tested in [`beta_e2e.rs`](../../crates/sena-node/tests/beta_e2e.rs)
- [ ] `In progress` — Retrieve batch data without sequencer-local access. → retrieved over RPC from the sequencer; **not independent**
- [x] `Complete` — Replay every batch and compare post-state roots. → `published_batch_data_reproduces_the_asserted_root`
- [x] `Complete` — Automatically open a challenge on divergence. → `VerifierNode::open_dispute`
- [x] `Complete` — Complete bisection within move deadlines. → `TracePlayer::play`; converges in 2 rounds over 48 steps
- [x] `Complete` — Generate a valid OSP. → `TracePlayer::one_step_proof`
- [ ] `Blocked` — Resolve a deliberately invalid assertion on Aptos. → resolved in Rust; **Aptos path blocked on §6**
- [x] `Complete` — Confirm the invalid assertion cannot finalize. → tested in Rust
- [x] `Complete` — Confirm descendants are rejected. → `a_successful_challenge_rejects_every_descendant`
- [ ] `Not started` — Confirm proposer bond slashing and challenger reward. → no real bonds exist
- [x] `Complete` — Test an invalid challenge and challenger slashing. → `an_honest_sequencer_defeats_a_frivolous_challenger`
- [x] `Complete` — Test timeout and chess-clock behavior. → `a_party_that_stops_responding_forfeits`, `a_party_that_exhausts_its_total_budget_forfeits`
- [ ] `Not started` — Restart the verifier without losing deadlines or evidence.
- [ ] `Not started` — Test verifier lag and recovery.
- **Evidence:** [`dispute.rs`](../../crates/sena-fraudproof/tests/dispute.rs) — 23 adversarial tests, all in-process

## 8. Bridge and test assets

- [ ] `Not started` — **Entire section.** No asset selected, no deposits, no withdrawals, no custody, no reconciliation.

> `bridge.move` verifies a withdrawal proof and marks it spent. It does not move
> assets. Nothing here has been compiled or run.

## 9. User and developer access

- [x] `Complete` — Provide a CLI or SDK for account creation and signing. → `sena-node keygen`, `send`
- [x] `Complete` — Provide transaction submission and status queries. → `send`, `query confirmation`
- [x] `Complete` — Expose balances, receipts, assertion status, and finality status. → `query account`, `query info`, `sena_getAssertion`
- [x] `Complete` — Document handle resolution. → `sena_resolveIdentifier`; tested
- [x] `Complete` — Document the selected gas model. → [`gas.rs`](../../crates/sena-stf/src/gas.rs), [`BETA_SCOPE.md` §3](BETA_SCOPE.md)
- [ ] `Not started` — Document wallets, network switching, and faucet setup. → no testnet exists to switch to
- [x] `Deferred by beta scope` — Keyless provider tests. → D-03
- [x] `Complete` — Publish a new-tester quickstart from an empty account. → [`README.md`](../../README.md); run end to end against a clean checkout before being written

## 10. Performance and reliability

- [ ] `Not started` — **Entire section.** No benchmarks have been run. No throughput, latency, replay-rate, dispute-duration, OSP-gas, recovery-time or storage-growth figure exists.

> The SRS targets >1,000 TPS (NFR-PERF-001). **That number is unmeasured** and
> must not be quoted until it is.

## 11. Observability and operator safety

- [ ] `In progress` — Emit structured logs. → the node logs block and assertion events to stdout; not structured
- [ ] `Not started` — Add metrics for sequencer health, verifier lag, DA availability, deadlines, L1 failures, withdrawals, and custody balance.
- [ ] `Not started` — Add alerts for expiring challenge clocks and stuck transactions.
- [ ] `Not started` — Add event-cursor persistence and duplicate handling.
- [ ] `Not started` — Add root and balance reconciliation jobs.
- [ ] `Not started` — Add emergency pause.
- [x] `Complete` — Ensure emergency controls cannot finalize assertions or dismiss disputes. → vacuously: no such controls exist, and no entry point could be added without changing the dispute contracts
- [ ] `Not started` — Document key separation, rotation, backup, revocation, and compromise procedures.
- [ ] `Not started` — Create runbooks.
- [ ] `Not started` — Run a tabletop incident exercise.

## 12. Security and adversarial review

- [ ] `Not started` — Complete final beta threat model. → an informal one exists in SDD §5.4
- [x] `Complete` — Run property tests for codec, trie, state transition, and proof logic. → proptest across [`sena-state`](../../crates/sena-state/tests), [`sena-stf`](../../crates/sena-stf/tests), [`sena-fraudproof`](../../crates/sena-fraudproof/tests)
- [ ] `Not started` — Run fuzzing against transaction, proof, batch, and withdrawal parsers.
- [ ] `Not started` — Run mutation tests.
- [ ] `Not started` — Review denial-of-service and gas-exhaustion paths.
- [x] `Complete` — Review replay and domain-separation protections. → nonce replay, governance epoch replay and domain separation all tested
- [ ] `In progress` — Review resource custody and balance conservation. → conservation tested in the STF; no real custody exists
- [ ] `Not started` — Review upgrade and migration behavior.
- [ ] `Not started` — Complete independent security review. → **required before any public exposure**
- [ ] `Not started` — Track all findings to resolution.
- [x] `Complete` — Publish known limitations and excluded features. → [`STATUS.md`](../../STATUS.md)

## 13. Release gates

### Gate A — Scope and protocol freeze — **In progress**

- [x] Beta scope approved → drafted, **awaiting sign-off**
- [x] All included and deferred features documented
- [x] Execution target selected → D-01, **SRS/SDD amendment outstanding**
- [x] Parameters and formats frozen
- [ ] Toolchain and STF hash recorded → Rust pinned; STF hash blocked

### Gate B — Local end-to-end integration — **Blocked on §6**

All items blocked: no local Aptos deployment is possible until the Move package
compiles.

### Gate C — Reproducible testnet deployment — **Not started**

### Gate D — Independent verification — **Partially met in-process**

Detection, challenge, bisection and one-step resolution all work and are tested,
but entirely within Rust. Nothing has touched Aptos.

### Gate E — Test-asset safety — **Not started**

### Gate F — Operations — **Not started**

### Gate G — Security review — **Not started**

## 14. Evidence index

Not yet created. `docs/beta/evidence/` should be populated as gates are met.

## 15. First implementation sprint

- [x] Approve the beta scope → drafted
- [x] Decide the execution target → D-01
- [ ] Decide the data-availability location
- [ ] Select one test asset
- [ ] Define role permissions and key boundaries
- [x] Freeze serialization and beta parameters
- [x] Create the requirements traceability matrix → [`TRACEABILITY.md`](TRACEABILITY.md), generated
- [ ] Create the testnet deployment repository/configuration
- [ ] Create the evidence directory
- [ ] Assign owners and reviewers for W-01 through W-12
- [ ] Define the first local end-to-end scenario

## Summary

| Section | State |
|---|---|
| 1. Release identity and scope | Mostly complete |
| 2. Build reproducibility | Partial — Aptos inputs unpinned |
| 3. Durable node | Mostly complete — no RocksDB, no auth |
| 4. Data availability | **Weakest area** — no independent publication |
| 5. Aptos settlement | Not started |
| 6. Move contracts | **Blocked on hardware** — blocks Gates B–G |
| 7. Fraud proofs and verifier | Complete in Rust, untested on Aptos |
| 8. Bridge | Not started |
| 9. User access | Complete for what exists |
| 10. Performance | Not started — no figures exist |
| 11. Observability | Not started |
| 12. Security review | Property tests only |

**Critical path:** compile the Move package → local Aptos integration → settlement
adapter → independent data availability → bridge.

## References

The original planning documents are [`BETA_BUILD_PLAN.md`](BETA_BUILD_PLAN.md)
and the specifications in [`docs/src/`](../src). The reference list in the
source version of this checklist contained several hundred near-duplicate links
and was omitted; the specifications are linked directly where relevant.
