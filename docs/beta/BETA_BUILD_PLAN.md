# SENA Closed-Testnet Beta Build Plan

**Document status:** Build planning baseline
**Scope:** What must be built, integrated, tested, and operated before SENA can enter a closed beta using worthless Aptos test assets
**Source documents:** SENA PRD 1.1.0, SENA SRS 1.1.0, SENA SDD 1.1.0, and the project proposal 1.1.0

> **Repository note.** This is the planning baseline as supplied. Current status
> against it is tracked in [`BETA_EXECUTION_CHECKLIST.md`](BETA_EXECUTION_CHECKLIST.md);
> W-01 decisions are recorded in [`DECISION_LOG.md`](DECISION_LOG.md) and
> [`BETA_SCOPE.md`](BETA_SCOPE.md). The source document's reference list ran to
> several hundred near-duplicate links and is omitted here; specifications are
> linked directly from the documents that cite them.

## 1. Executive decision

SENA should target a **closed testnet beta** before a public beta or mainnet launch. The closed beta must prove the complete security lifecycle, not merely the correctness of isolated Rust or Move components. In particular, it must demonstrate that a sequencer can execute a batch, publish an assertion and its data to Aptos, an independent verifier can detect an intentionally invalid assertion, and the Aptos settlement layer can reject it through the complete challenge and one-step-proof flow.

The existing specifications describe a larger product than is necessary for the first beta. The team should therefore freeze a beta scope before implementing more features. A beta may defer token-holder governance, production-grade keyless login, multiple stablecoins, fast-withdrawal liquidity, and decentralized sequencing, provided those deferrals are explicit, enforced in code, and reflected in the public product claims. The beta must not defer the parts that make the optimistic security claim meaningful: data availability, real Aptos settlement, real bridge accounting, permissionless challenges, an independent verifier, durable node operation, and rollback/recovery.

> **Beta principle:** A feature is beta-ready only when its user-facing path, Rust execution path, Aptos Move path, verifier replay path, failure behavior, observability, and acceptance evidence all agree.

## 2. Beta definition and non-goals

### 2.1 Beta definition

For this plan, SENA beta means a closed Aptos testnet deployment in which invited operators can use a documented client or CLI to submit L2 transactions, receive soft confirmations, move designated worthless test assets, observe L1 assertion status, and independently verify or challenge assertions. The beta may use a single sequencer, but it must not depend on the sequencer as the only verifier or the only source of batch data.

The beta must clearly distinguish:

- **Soft confirmation:** The sequencer has accepted and executed a transaction locally.
- **L1 finality:** The assertion covering the transaction has survived the challenge window on Aptos.
- **Testnet safety:** Test assets have no monetary value, but the protocol must still enforce the same authorization, accounting, replay, and dispute rules expected on mainnet.

### 2.2 Recommended beta scope

| Capability | Closed-beta decision | Reason |
|---|---|---|
| Rust STF and deterministic execution | Required | Foundation of every verifier result |
| Real Aptos assertion settlement | Required | Proves the security anchor works |
| Batch data availability | Required | A verifier cannot challenge unavailable data |
| Independent verifier mode | Required | Tests the 1-of-N security assumption |
| Real dispute and one-step flow | Required | Core differentiator and safety mechanism |
| Test-asset bridge deposits and withdrawals | Required | Proves users can recover assets from L1 |
| Durable storage and restart recovery | Required | A beta cannot be an in-memory demo |
| Live RPC and client/CLI | Required | Operators and users need a usable system |
| Social identifiers | Required if advertised | Core PRD feature, low integration risk |
| One stablecoin-like gas asset | Recommended | Tests the paymaster path without broad asset scope |
| Keyless/OIDC login | Defer unless fully implemented | High cryptographic and provider-integration risk |
| Full multi-asset gas conversion | Defer after one asset works | Requires pricing, vault, and L1 funding economics |
| Token-holder governance | Defer or narrow | Must not control dispute safety paths |
| Decentralized sequencing | Defer | Explicitly listed as future work in the PRD |
| Fast-withdrawal liquidity | Defer | Optional user-experience layer |

## 3. Requirements that must be clarified before coding

Create a signed-off beta addendum before implementation begins. It should resolve the following specification decisions.

### 3.1 Fraud-proof execution target

The SRS and SDD describe an RV32IM machine-level one-step proof, while the current prototype uses a higher-level instruction trace. Choose one design and make every document, test, and implementation use it consistently.

- **Preferred path:** implement the specified deterministic RV32IM target, record its immutable binary hash in assertions, and make the Move one-step verifier execute the same semantics.
- **Alternative path:** formally revise the SRS and SDD to define the higher-level instruction set as the beta execution target, document why it is sound, and make the narrower scope explicit in the beta release notes.

No beta assertion should be accepted if the Rust executor, verifier, and Move adjudicator are proving different machines.

### 3.2 Data-availability model

The SDD permits Aptos-published data or an approved external DA layer. Select one for beta. The recommended first-beta choice is the simplest model that can be economically tested, with the commitment and retrieval path recorded in every assertion.

Define the following before implementation:

- Batch serialization and canonical encoding.
- Data commitment algorithm.
- Publication location and retention period.
- Retrieval API and authentication policy.
- `DA_RESPONSE_TIMEOUT` behavior.
- Data-availability challenge transaction.
- Evidence that unavailable data causes rejection rather than silent finalization.

### 3.3 Asset model

Select exactly one test asset for the first bridge and paymaster implementation. Define its asset identifier, decimal precision, custody model, deposit message, withdrawal message, amount limits, and failure behavior. Do not describe the system as supporting arbitrary stablecoins until the asset registry, rate updates, accounting, and L1 funding paths are implemented.

### 3.4 Beta security boundary

Document which roles exist and what each role may do: publisher/sequencer, L1 package administrator, challenger, independent verifier, governance signer (if retained), bridge operator (if any privileged operation remains), and testnet faucet/funding accounts.

The L1 contracts must enforce these boundaries with signer or capability checks. A role should never be represented only by an address stored in a resource if an unauthorized public function can mutate the same state.

## 4. Build workstreams

Each workstream has a deliverable, dependencies, and an acceptance gate. Track work at the task level in the repository and attach test logs, transaction hashes, package hashes, and configuration versions to each completed gate.

### W-01: Freeze the beta protocol and release inputs

**Purpose:** Prevent implementation drift between the PRD, SRS, SDD, Rust, and Move.

1. Publish `BETA_SCOPE.md` describing included and deferred capabilities.
2. Resolve the RV32IM versus higher-level trace decision.
3. Freeze assertion, batch, proof, and withdrawal serialization formats.
4. Define all beta parameters, including challenge window, move timeout, dispute clock, data timeout, forced-inclusion timeout, liveness timeout, bond sizes, and bisection arity.
5. Assign a unique version and STF binary hash to the beta protocol.
6. Create a requirements traceability file mapping each beta requirement to code, tests, and evidence.

**Acceptance evidence:** Approved beta addendum; versioned parameter file; canonical encoding vectors; STF hash; traceability matrix.

**Source alignment:** PRD Sections 4–7; SRS REQ-FRAUD-031 to REQ-FRAUD-034; SDD Sections 3.5.7 and 4.

### W-02: Make execution deterministic and reproducible

**Purpose:** Ensure sequencer, verifier, and Move adjudication agree on the same state transition function.

1. Pin the Rust compiler, target, dependencies, and build container.
2. Pin the Aptos CLI and Aptos framework revision.
3. Produce a reproducible STF artifact and record its hash.
4. Define canonical serialization for transactions, batches, proofs, state nodes, and machine state.
5. Run differential tests across clean machines and supported CPU architectures.
6. Include malformed encodings, overflow, empty batches, duplicate transactions, deletions, and boundary values.
7. Ensure timestamps, randomness, iteration order, threads, and ambient environment cannot affect STF results.

**Acceptance evidence:** Two clean builds produce identical STF hashes; cross-platform conformance logs; canonical vector archive; deterministic replay test.

**Source alignment:** SRS REQ-FRAUD-031 to REQ-FRAUD-034 and NFR-PORT-003; SDD Sections 3.5.4 and 4.3.

### W-03: Implement durable L2 node infrastructure

**Purpose:** Turn the reference model into a recoverable beta node.

1. Add durable state storage using the selected RocksDB/NOMT design or document an approved equivalent.
2. Persist accounts, transactions, blocks, roots, assertions, batches, challenges, checkpoints, and verifier results.
3. Implement crash-safe commit ordering and restart recovery.
4. Retain all data needed to defend or challenge pending assertions for the full challenge window.
5. Implement garbage-collection rules that cannot delete live dispute evidence.
6. Add a live RPC transport with versioning, authentication where required, rate limits, and explicit soft/finalized status.
7. Add a CLI or SDK for node initialization, inspection, replay, and recovery.

**Acceptance evidence:** Kill-and-restart tests at every commit boundary; state-root continuity after restart; recovery from pending challenges; live RPC interoperability tests.

**Source alignment:** SRS REQ-CORE-001, REQ-CORE-005, NFR-REL-003 to NFR-REL-005, NFR-PORT-001; SDD Sections 2.2.1–2.2.3, 4.2, and 6.

### W-04: Build batch data availability

**Purpose:** Ensure any independent verifier can obtain exactly the data used to produce an assertion.

1. Serialize ordered batches canonically.
2. Publish the complete batch and record its commitment in the assertion.
3. Implement retrieval by assertion ID and commitment.
4. Add integrity verification before execution.
5. Retain data through all pending descendants and open challenges.
6. Implement DA challenges and timeout-based rejection.
7. Test unavailable, truncated, altered, delayed, and duplicated batch data.

**Acceptance evidence:** A clean verifier can retrieve and verify a batch without sequencer-local access; unavailable data causes the specified rejection and bond outcome.

**Source alignment:** SRS REQ-FRAUD-007 to REQ-FRAUD-010; SDD Section 3.5.2.

### W-05: Implement the Aptos settlement adapter

**Purpose:** Connect the node to real Aptos transactions and finality.

1. Build an Aptos client with signed transaction submission, retry, sequence-number management, gas budgeting, and confirmation tracking.
2. Publish assertions containing parent, block range, pre-root, post-root, data commitment, transaction count, STF hash, proposer, and bond.
3. Watch assertion status and challenge windows from Aptos events or REST/indexer data.
4. Submit challenges, bisection moves, OSPs, timeout claims, and finalization actions.
5. Handle L1 reorg-equivalent operational conditions, rejected transactions, rate limits, and delayed confirmation.
6. Maintain a durable local mirror of L1 state and reconcile it against on-chain resources.

**Acceptance evidence:** A real testnet assertion is posted, observed, challenged, resolved, and finalized or rejected using signed Aptos transactions; all transaction hashes and event records are archived.

**Source alignment:** SRS REQ-CORE-002 to REQ-CORE-004 and REQ-FRAUD-001 to REQ-FRAUD-006; SDD Sections 2.2.5 and 6.

### W-06: Complete and harden Move contracts

**Purpose:** Make Aptos the actual enforcement layer rather than a source-only design.

1. Compile the complete package against the pinned Aptos framework.
2. Add Move unit tests for every public and entry function.
3. Enforce state-machine stages and valid caller capabilities.
4. Implement real assertion and challenger bond custody.
5. Implement refunds, slashing, challenger rewards, and treasury allocation exactly once.
6. Connect successful OSP results to dispute resolution and assertion status.
7. Ensure unresolved ancestor challenges block descendant finalization.
8. Implement forced inclusion and proposer-liveness behavior, not only metadata recording.
9. Implement the selected one-step execution target and all beta-supported instructions.
10. Add event schemas for every lifecycle transition.

**Acceptance evidence:** `aptos move compile`, `aptos move test`, and coverage results pass in CI; unauthorized and malformed calls abort; all lifecycle transitions are proven by resource, balance, event, and status assertions.

**Source alignment:** SRS REQ-FRAUD-001 to REQ-FRAUD-030 and NFR-SEC-007 to NFR-SEC-012; SDD Sections 2.2.5 and 3.5.

### W-07: Build the independent verifier and dispute driver

**Purpose:** Exercise the 1-of-N security assumption in practice.

1. Provide a documented `--mode verifier` deployment.
2. Follow L1 assertions and retrieve batch data independently.
3. Re-execute every batch from a finalized local checkpoint.
4. Automatically open a challenge on divergence.
5. Generate and submit bisection moves within the per-move and chess-clock deadlines.
6. Generate the OSP and monitor final resolution.
7. Detect unavailable data and open DA challenges.
8. Recover verifier state after restart without losing deadlines.
9. Support an operator-controlled dry-run mode for testnet rehearsal.

**Acceptance evidence:** An independent verifier, started from an empty data directory, detects a deliberately falsified assertion and completes the challenge without sequencer assistance.

**Source alignment:** SRS REQ-FRAUD-011 to REQ-FRAUD-027; SDD Sections 2.2.7, 2.2.8, and 3.5.3–3.5.6.

### W-08: Implement the bridge with real test assets

**Purpose:** Prove that users can recover assets against finalized L1 state.

1. Choose one Aptos test asset and document its type and decimals.
2. Implement deposits and L2 crediting with replay-safe deposit IDs.
3. Implement withdrawal proofs against finalized assertions only.
4. Bind withdrawals to recipient, asset type, amount, and canonical message domain.
5. Transfer or release the asset from L1 custody.
6. Emit deposit, withdrawal, rejection, and completion events.
7. Implement duplicate, expired, malformed, wrong-recipient, wrong-asset, and wrong-amount handling.
8. Implement forced inclusion for censored user transactions.
9. Reconcile the L1 custody balance with the L2 liability ledger.

**Acceptance evidence:** Real worthless test assets move in and out on Aptos testnet; balance conservation holds before and after successful, failed, replayed, and challenged withdrawals.

**Source alignment:** PRD Sections 4.4–4.5; SRS REQ-FRAUD-005, REQ-CORE-004, and REQ-FRAUD-028 to REQ-FRAUD-030; SDD Sections 2.2.5 and 3.5.5–3.5.6.

### W-09: Define and implement the beta user transaction path

**Purpose:** Make the system usable by invited testers.

1. Provide a CLI or SDK for account creation, signing, submission, status, balances, and receipts.
2. Clearly show soft confirmation versus L1 finality.
3. Implement social-handle resolution if retained in beta.
4. Implement one supported gas asset or explicitly require Aptos test APT for beta.
5. If keyless login is included, implement provider fixtures, proof generation, proof verification, expiry, nonce, replay, and recovery tests.
6. Document wallet, network, faucet, and test-asset setup.

**Acceptance evidence:** A new tester can follow the runbook from an empty account to a submitted transaction, confirmed balance change, deposit, and finalized withdrawal without manual database edits.

**Source alignment:** PRD Sections 4.1–4.3 and 5; SRS Sections 3.1.1–3.1.3 and REQ-CORE-005.

### W-10: Add governance only within a safe beta boundary

**Purpose:** Make governance changes auditable without giving governance authority over active disputes.

1. Decide whether governance is in beta or deferred.
2. If included, implement signed payload verification and replay protection.
3. Keep assertion finalization, challenge dismissal, dispute outcome, and challenge-window floor unreachable from governance.
4. Add parameter bounds, effective heights, and upgrade compatibility.
5. Test governance changes as ordinary STF transactions covered by fraud proofs.

**Acceptance evidence:** Governance can update only approved parameters; attempts to override dispute safety fail by construction.

**Source alignment:** PRD Section 4.6; SRS REQ-GOV-001 to REQ-GOV-007; SDD Section 3.4.

### W-11: Observability, operations, and incident response

**Purpose:** Operate a beta safely and know when the security model is degrading.

1. Emit structured logs and metrics for transactions, blocks, assertions, data retrieval, challenges, deadlines, withdrawals, balances, and failures.
2. Add dashboards and alerts for stuck assertions, unavailable data, expiring clocks, failed L1 transactions, verifier lag, and custody imbalance.
3. Build reconciliation jobs for L2 roots, L1 assertions, bridge liabilities, and event cursors.
4. Add emergency controls for pausing new assertions or withdrawals without allowing privileged finalization or challenge dismissal.
5. Document key generation, role separation, rotation, compromise response, and offline backups.
6. Create incident runbooks for invalid assertion, unavailable batch, sequencer outage, verifier outage, Aptos outage, failed upgrade, and suspected key compromise.

**Acceptance evidence:** A tabletop exercise produces alerts and a documented response for each critical failure scenario; reconciliation finds injected inconsistencies.

**Source alignment:** SRS NFR-REL-001 to NFR-REL-005 and NFR-MAINT-003; SDD Sections 5 and 6.

### W-12: Security review and adversarial testnet

**Purpose:** Validate the system outside the authoring team before public access.

1. Conduct internal threat modeling against the final beta implementation.
2. Run property, fuzz, negative, and mutation tests for codecs, trie proofs, state transitions, dispute clocks, and bridge accounting.
3. Conduct a local Aptos end-to-end adversarial campaign.
4. Run an invited testnet campaign with independent verifier operators.
5. Obtain an independent review of Move authorization, OSP, bridge custody, canonical encoding, proof verification, and economic incentives.
6. Publish known limitations and unresolved findings.

**Acceptance evidence:** No unresolved critical or high-severity issue affecting asset custody, assertion finality, dispute resolution, proof soundness, replay protection, or privileged access; adversarial exercises produce expected outcomes.

**Source alignment:** SRS NFR-SEC-012 and NFR-MAINT-005; PRD Success Metrics.

## 5. End-to-end acceptance scenarios

These are release gates, not optional examples.

| ID | Scenario | Pass condition |
|---|---|---|
| E2E-01 | Honest assertion | Assertion is posted, observed, remains unchallenged, and finalizes after the configured window |
| E2E-02 | Invalid assertion | Independent verifier detects a wrong post-root, opens a challenge, and prevents finalization |
| E2E-03 | Full bisection | Defender and challenger exchange valid moves until one disputed step remains |
| E2E-04 | Invalid OSP | Incorrect one-step proof is rejected and the correct party wins |
| E2E-05 | Timeout | A party that misses its deadline loses according to the configured clock rules |
| E2E-06 | Data unavailability | Missing batch data triggers a DA challenge and the assertion is rejected or remains non-finalizable |
| E2E-07 | Descendant rollback | Successful challenge rejects the assertion and all descendants and restores the last finalized state |
| E2E-08 | Bridge deposit | A test asset deposit is credited exactly once on SENA |
| E2E-09 | Bridge withdrawal | A withdrawal against a finalized root transfers the correct asset and amount to the correct recipient |
| E2E-10 | Withdrawal rejection | Pending-root, wrong-recipient, wrong-asset, wrong-amount, malformed, and replayed withdrawals fail safely |
| E2E-11 | Forced inclusion | A censored L1 inbox transaction becomes includable after timeout and is not silently lost |
| E2E-12 | Sequencer restart | Restart preserves state, pending assertions, checkpoints, and deadlines |
| E2E-13 | Verifier restart | Restart preserves independent replay progress and challenge obligations |
| E2E-14 | L1 outage | Temporary Aptos unavailability does not corrupt local state or cause an honest party to lose a dispute |
| E2E-15 | Authorization | Unauthorized initialization, resolution, slashing, withdrawal, and parameter changes fail |
| E2E-16 | Receipt semantics | APIs and clients distinguish soft confirmation, challenged state, finality, and rollback |

## 6. Release gates

- **Gate A — Protocol freeze.** Beta scope, execution target, DA model, asset model, parameter values, serialization formats, and role permissions approved and versioned.
- **Gate B — Local integration.** A local Aptos environment runs the complete honest and adversarial assertion lifecycle. Rust and Move produce matching roots, proofs, statuses, balances, and events.
- **Gate C — Reproducible deployment.** A clean environment can build the node and Move package, publish the package, initialize the testnet configuration, and record package/STF hashes without manual state edits.
- **Gate D — Independent verification.** A verifier started independently can retrieve data, replay the chain, challenge a deliberately invalid assertion, complete the dispute, and recover from restart.
- **Gate E — Asset safety.** A supported worthless test asset can be deposited, credited, withdrawn after finality, rejected under invalid conditions, and reconciled against L1 custody.
- **Gate F — Operational readiness.** Monitoring, alerting, key procedures, emergency controls, recovery procedures, and incident runbooks exercised.
- **Gate G — External review.** Security review findings triaged. No critical or high-severity issue open in the settlement, dispute, bridge, proof, authorization, or replay paths.

## 7. Suggested build order

1. Freeze the beta scope and resolve the execution-target mismatch.
2. Pin toolchains and canonical encodings.
3. Build durable storage and live node interfaces.
4. Complete Move compilation, authorization, state transitions, and events.
5. Implement the Aptos settlement adapter.
6. Implement data availability and independent verifier operation.
7. Wire the full dispute lifecycle.
8. Implement real test-asset custody and withdrawals.
9. Add CLI/SDK, monitoring, recovery, and runbooks.
10. Run local adversarial tests.
11. Run closed testnet with independent operators.
12. Complete external review and publish limitations.

Do not start with keyless UX polish or broad stablecoin support while the assertion, dispute, data, and bridge paths remain unproven. Those features are valuable, but they do not establish the security property that differentiates SENA.

## 8. Definition of done for the first beta release

- A versioned beta scope and parameter set.
- Reproducible node and Move builds.
- A deployed Aptos package with recorded addresses and hashes.
- A working sequencer-to-Aptos settlement adapter.
- A retrievable and integrity-checked batch-data path.
- An independent verifier deployment guide.
- A successful deliberately-invalid-assertion challenge.
- A functioning one-step resolution path.
- Real test-asset deposit and withdrawal transactions.
- Durable restart and rollback evidence.
- Client or CLI documentation for testers.
- Monitoring dashboards and incident runbooks.
- Complete end-to-end test logs and transaction hashes.
- Security review results and an issue disposition record.
- A public limitations document that does not overstate keyless login, gas abstraction, governance, or security guarantees.

## 9. Specification traceability

| Plan area | Primary repository requirements |
|---|---|
| Protocol freeze and determinism | SRS REQ-FRAUD-031–034; SDD 3.5.4, 4.3 |
| Durable node | SRS NFR-REL-003–005, NFR-PORT-001; SDD 2.2.1–2.2.3 |
| Data availability | SRS REQ-FRAUD-007–010; SDD 3.5.2 |
| Assertions and bonds | SRS REQ-FRAUD-001–006; SDD 3.5.1, 3.5.7 |
| Bisection and OSP | SRS REQ-FRAUD-011–018; SDD 3.5.3–3.5.4 |
| Rollback and incentives | SRS REQ-FRAUD-019–023; SDD 3.5.5 |
| Verifier operation | SRS REQ-FRAUD-024–027; SDD 2.2.7–2.2.8 |
| Censorship resistance | SRS REQ-FRAUD-028–030; SDD 3.5.6 |
| Asset recovery | SRS REQ-CORE-002–006; PRD 4.4 |
| Keyless accounts | SRS REQ-AUTH-001–007; SDD 3.1 |
| Social Connect | SRS REQ-SOCIAL-001–005; SDD 3.2 |
| Gas abstraction | SRS REQ-GAS-001–010; SDD 3.3 |
| Governance | SRS REQ-GOV-001–007; SDD 3.4 |
| Reliability and observability | SRS NFR-REL-001–005, NFR-MAINT-003–005 |
| Security review | SRS NFR-SEC-007–012; PRD Success Metrics |

A generated, per-requirement version of this table is in [`TRACEABILITY.md`](TRACEABILITY.md).

## 10. Decision log

See [`DECISION_LOG.md`](DECISION_LOG.md), which follows this plan's template and
records D-01 through D-06 plus the decisions still open.
