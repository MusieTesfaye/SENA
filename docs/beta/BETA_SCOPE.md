# SENA Closed-Beta Scope

**Status:** Proposed — awaiting sign-off
**Parameter set:** `sena-beta-params-1` ([`crates/sena-params`](../../crates/sena-params))
**Protocol version:** `0.3.0-beta`
**Satisfies:** `BETA_BUILD_PLAN.md` W-01

This is the scope freeze the build plan requires before further feature work. It
records what the closed beta will and will not include, and why. Decisions with
alternatives considered are in [`DECISION_LOG.md`](DECISION_LOG.md).

The build plan's own principle governs every line below:

> A feature is beta-ready only when its user-facing path, Rust execution path,
> Aptos Move path, verifier replay path, failure behavior, observability, and
> acceptance evidence all agree.

By that standard the Move path has cleared its first bar: the package compiles
and 36 of 36 unit tests pass, including conformance tests that check it agrees
with the Rust reference on computed values. What it has not cleared is
deployment — nothing has been published to any Aptos network, so no capability
below can yet claim its Aptos path *works*, only that it builds.

## 1. What the beta must prove

One thing, and everything else is in service of it:

> An independent party, starting from an empty directory, can detect a
> deliberately invalid assertion, challenge it on Aptos without the sequencer's
> cooperation, and prevent it from finalizing.

A beta that demonstrates fast transactions and pretty balances but not this has
demonstrated a database. The security property is the product.

## 2. Included

| Capability | Rationale | State today |
|---|---|---|
| Deterministic STF and execution traces | Every verifier result depends on it | Implemented, 232 tests |
| Sparse Merkle state with proofs | Withdrawals and one-step proofs both need it | Implemented |
| Bonded assertions and challenge windows | The security anchor | Implemented in Rust and Move; **not deployed** |
| Batch data publication | A verifier cannot challenge data it cannot get | Served over RPC; **not published to L1** |
| Independent verifier mode | Tests the 1-of-N assumption | Implemented; follows via RPC |
| Interactive bisection and one-step proofs | The differentiator | Implemented in Rust and Move; **not deployed** |
| Durable node with verified restart | A beta is not an in-memory demo | Implemented |
| Live JSON-RPC and CLI | Testers need a usable system | Implemented |
| Social Connect handles | Core PRD feature, low integration risk | Implemented |
| One stablecoin-like gas asset | Exercises the paymaster without broad asset scope | Implemented |
| Test-asset bridge deposits and withdrawals | Proves recovery from L1 | **Not implemented** |
| Real Aptos settlement | Proves the anchor is real rather than modelled | **Not implemented** |

## 3. Deferred, and why

Each deferral is a claim the project must stop making until it is reversed.

### Keyless / OIDC login — deferred

**This is the flagship feature and it is being deferred. That needs saying
plainly rather than buried.**

What exists is real and useful: JWT claim parsing, issuer allowlisting, expiry
bounds, `aud` scoping that keeps one user unlinkable across applications,
deterministic address derivation, and verification that the token's `nonce`
commits to *this* ephemeral key — which is the check these systems most often
get wrong, and is where an attacker holding a JWT from a log would otherwise
walk in.

What does not exist is verification that the identity provider issued the token
at all. That is what the zero-knowledge proof attests to, and implementing it
means a Groth16 verifier over BN254 matched exactly to Aptos's keyless circuit:
its verification key, its public input encoding, and its pepper service. Every
one of those is a place where a subtle mismatch is a fund-loss bug rather than a
test failure, and none can be validated without the real artifacts.

Shipping an unvalidated proof verifier would be worse than shipping none,
because it would look like the feature works. The code therefore **refuses**
keyless transactions outright rather than accepting them on the strength of the
checks that do pass.

Reversing this deferral requires: Aptos's verification key and circuit
specification, a test corpus of real provider tokens, pepper service
integration, and independent review of the verifier. It is the first roadmap
item after the settlement path is real.

Until then the project must not describe keyless sign-in as working.

### Multi-asset gas — narrowed to one asset

The paymaster, the whitelist, the rate validation and the rounding rules are
implemented and tested. What is deferred is breadth: a second asset needs
pricing, vault accounting and L1 funding economics that add risk without adding
proof. One asset exercises the whole code path.

### Token-holder governance — deferred; council retained and bounded

Off-chain token voting is out of beta scope. The multi-signature council remains,
because parameters must be changeable, and it is already bounded by construction:
`GOVERNABLE_PARAMETERS` is an allowlist, and the dispute system exposes no
governance entry point at all. A council cannot finalize an assertion, dismiss a
challenge, or lower the challenge window — not by policy, but because the
capability does not exist.

Worth stating directly: **the council, not a vote, is the authority the protocol
recognises today.** Describing this as decentralised governance would be
inaccurate.

### Decentralised sequencing — deferred

Listed as future work in the PRD. Fraud proofs constrain what the sequencer may
*assert*; they do not constrain what it includes or in what order. Forced
inclusion bounds censorship and is specified, but is not yet wired into the Rust
node.

### Fast-withdrawal liquidity — deferred

A user-experience layer over a working withdrawal path. There is no working
withdrawal path yet.

## 4. Execution target: higher-level instruction trace

`BETA_BUILD_PLAN.md` §3.1 requires this decision, and names the RV32IM target as
preferred. **The recommendation here is the alternative path: formally adopt the
higher-level instruction set as the beta execution target.**

The reasoning, since this departs from the stated preference:

**The security argument is identical.** Bisection narrows a disagreement to one
step; Aptos L1 executes that step and rules. Nothing in that argument depends on
the step being a RISC-V instruction rather than a state-machine operation. Both
implementations already do this, and the adversarial tests demonstrate an honest
challenger winning wherever fraud is placed.

**The cost of RV32IM is the critical path.** It means compiling the STF to
RISC-V, writing an RV32IM interpreter in Move, and making both agree bit for
bit. That is the single largest work item in the plan, and it sits in front of
the thing the beta exists to prove. The build plan's own §7 warns against
exactly this ordering.

**The real trade-off, stated honestly:** an RV32IM target makes the disputed
step independent of the state machine's design, so new features cannot introduce
steps the L1 verifier does not understand. With a higher-level set, every new
instruction must also be implemented in Move, and an instruction that is
expensive to verify becomes a protocol problem. This is a genuine loss and it is
why the beta instruction set is frozen (§5) — a frozen set has no new
instructions to worry about.

**Migration path.** The STF is already structured so each instruction touches
exactly one state slot, which is what keeps one-step verification small. Moving
to RV32IM later replaces the step model without changing the assertion,
bisection or settlement protocols. It should be revisited before mainnet, and
before the instruction set is unfrozen.

This decision requires an SRS and SDD amendment recording the higher-level set
as the beta target. That amendment is not yet written.

## 5. Frozen beta instruction set

One-step adjudication must be implementable in Move for every instruction. The
beta set is therefore closed, and adding to it is a protocol change:

| Instruction | Slot touched | Move adjudication |
|---|---|---|
| `ConsumeNonce` | account | Implemented, tested |
| `Debit` | account | Implemented, tested |
| `Credit` | account | Implemented, tested |
| `BindIdentifier` | social index | Implemented, tested |
| `UnbindIdentifier` | social index | Implemented, tested |
| `VerifyGasAsset` | asset record | **Not implemented — aborts** |
| `VerifyCouncil` | council record | **Not implemented — aborts** |
| `SetGasAsset` | asset record | **Not implemented** |
| `SetParameter` | parameter | **Not implemented** |

The last four abort with `E_UNSUPPORTED_INSTRUCTION` rather than being
approximated. A verifier that guesses is worse than one that declines — but the
consequence is real and must be stated: **a dispute over a gas-rate or
governance step cannot currently be adjudicated on L1.** Closing that gap is a
beta blocker, not a nice-to-have.

## 6. Frozen parameters

Parameters live in [`crates/sena-params`](../../crates/sena-params) as the single
source of truth, with the relationships between them checked by test rather than
asserted in prose. Notably: both parties' dispute budgets together must fit
inside the challenge window at *every* window the chain accepts, including the
floor — a relationship an earlier fixed budget violated.

| Parameter | Value |
|---|---|
| `challenge_window_secs` | 7 days |
| `challenge_window_floor_secs` | 24 hours (enforced in code) |
| `move_timeout_secs` | 6 hours |
| `clock_budget_divisor` | 4 (each party gets a quarter of the window) |
| `bisection_arity` | 8 |
| `da_response_timeout_secs` | 12 hours |
| `forced_inclusion_timeout_secs` | 24 hours |
| `proposer_liveness_timeout_secs` | 24 hours |
| `sequencer_bond_min` | 1,000,000 |
| `challenger_bond` | 100,000 |
| `slash_reward_percent` | 50 (the remainder to treasury) |
| `base_gas_native` | 1,000 |
| `gas_rate_scale` | 1,000,000 |
| `max_block_transactions` | 512 |

Changing any value requires bumping `PARAM_SET_VERSION` and recording the change
in [`DECISION_LOG.md`](DECISION_LOG.md).

## 7. Still undecided

These block later workstreams and are not resolved here, because they need
inputs the codebase does not contain.

| Decision | Blocks | Needs |
|---|---|---|
| Data availability location | W-04 | Cost measurement of publishing batches to Aptos |
| Beta test asset | W-08 | A chosen Aptos testnet coin or fungible asset |
| Role and key boundaries | W-06, Gate C | Operational decisions about who holds what |
| STF upgrade policy | W-01 | Whether the binary hash is fixed or governed |

## 8. Honest position on beta readiness

Against the build plan's Gate A through Gate G, the project is at **Gate A, in
progress.** This document and the parameter freeze are most of Gate A; the SRS
and SDD amendment for the execution target is outstanding.

Gate B — local end-to-end integration against a local Aptos node — is now
reachable. The Move package compiles and self-tests; what it needs next is a
local Aptos deployment and the assertion lifecycle run against it.

What is genuinely done is the layer beneath all of it: a deterministic state
machine, a Merklized state with proofs, a working dispute protocol with
adversarial tests, and a node that runs, serves RPC and survives restarts. That
is a real foundation. It is not a beta.
