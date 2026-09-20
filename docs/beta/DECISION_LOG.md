# Beta decision log

**Satisfies:** `BETA_BUILD_PLAN.md` §10

Decisions recorded before implementation, as the build plan requires. Status
values are `Proposed` (recommended, awaiting sign-off) and `Accepted`.

Where a decision departs from the build plan's stated preference, the reasoning
is given in full rather than summarised — those are the ones most worth
disagreeing with.

---

## D-01 — Beta execution target

| | |
|---|---|
| **Options** | RV32IM machine-level trace · higher-level instruction trace |
| **Selected** | Higher-level instruction trace |
| **Status** | Proposed |
| **Affects** | REQ-FRAUD-012, 016, 017, 032 |

**Rationale.** The security argument does not depend on the step being a RISC-V
instruction: bisection narrows a disagreement to one step and L1 executes it,
whatever a step is. RV32IM would require compiling the STF to RISC-V and writing
an interpreter in Move, which is the largest item in the plan and sits directly
in front of the thing the beta exists to prove. The build plan's own §7 warns
against that ordering.

**What this costs.** An RV32IM target makes the disputed step independent of the
state machine, so new features cannot introduce steps the verifier does not
understand. Here, every new instruction must also be implemented in Move. This
is mitigated by freezing the instruction set (D-02) and is a genuine reason to
revisit before mainnet.

**Follow-up required.** An SRS and SDD amendment adopting the higher-level set
as the beta target. Not yet written — until it is, the specifications and the
implementation disagree, which is exactly the drift W-01 exists to prevent.

---

## D-02 — Beta instruction set

| | |
|---|---|
| **Options** | Open set · frozen set |
| **Selected** | Frozen at nine instructions |
| **Status** | Proposed |
| **Affects** | REQ-FRAUD-016, 017; W-06 item 9 |

**Rationale.** Follows from D-01. A closed set bounds the Move verifier's
surface and removes the main risk that choice carries.

**Known gap.** Four of the nine — `VerifyGasAsset`, `VerifyCouncil`,
`SetGasAsset`, `SetParameter` — are not adjudicable in Move and abort. A dispute
over a gas-rate or governance step therefore cannot currently be settled on L1.
This is a beta blocker.

---

## D-03 — Keyless / OIDC login

| | |
|---|---|
| **Options** | Included · deferred |
| **Selected** | Deferred; binding logic retained and enforced |
| **Status** | Proposed |
| **Affects** | REQ-AUTH-001 to REQ-AUTH-007 |

**Rationale.** Matches the build plan's own recommendation. Proof verification
requires matching Aptos's keyless circuit exactly — verification key, public
input encoding, pepper service — and none of that can be validated without the
real artifacts. A mismatch is a fund-loss bug, not a test failure.

**What is retained.** Claim parsing, issuer allowlisting, expiry bounds, `aud`
scoping, address derivation, and ephemeral-key binding. The binding check is the
substantive one: without it, anyone holding a JWT from a log can pair it with
their own key and take the account.

**Behaviour.** Keyless transactions are refused. The checks that pass establish
that a *presented* token is correctly bound and current; they do not establish
that it is real.

**Public claims.** The project must not describe keyless sign-in as working
until this is reversed.

---

## D-04 — Protocol parameters

| | |
|---|---|
| **Options** | Constants per module · single versioned crate |
| **Selected** | Single crate, `sena-params`, version `sena-beta-params-1` |
| **Status** | Proposed |
| **Affects** | REQ-FRAUD-004, 014, 015 |

**Rationale.** A challenge window reading 7 days in the SRS, 24 hours in Move
and 48 hours in a test is not a documentation problem — it is a chain
finalizing on a schedule nobody chose. Tests bind the implementation's constants
to the frozen set, so drift fails the build and names the parameter.

**Relationships checked, not asserted.** Both parties' dispute budgets together
must fit inside the challenge window at *every* window the chain accepts,
including the floor. An earlier fixed 48-hour budget violated this at the
24-hour floor: a dispute could have outlived the window it exists to resolve
within, letting fraud finalize while still under challenge. Budgets are now
derived from the window.

---

## D-05 — Governance scope

| | |
|---|---|
| **Options** | Token voting included · council only · deferred entirely |
| **Selected** | Council retained and bounded; token voting deferred |
| **Status** | Proposed |
| **Affects** | REQ-GOV-001 to REQ-GOV-007 |

**Rationale.** Parameters must be changeable during a beta, but nothing about
governance should be able to touch dispute safety. The dispute contracts expose
no governance entry point, and `GOVERNABLE_PARAMETERS` is an allowlist rather
than a denylist, so reach is added deliberately.

**Stated plainly.** The council, not a vote, is the authority the protocol
recognises. Calling this decentralised governance would be inaccurate.

---

## D-06 — Gas asset breadth

| | |
|---|---|
| **Options** | Multi-asset · single asset |
| **Selected** | One asset for beta |
| **Status** | Proposed |
| **Affects** | REQ-GAS-001 to REQ-GAS-010 |

**Rationale.** The paymaster, whitelist, rate validation and rounding rules are
implemented and exercised by one asset. A second adds pricing, vault accounting
and L1 funding economics — risk without additional proof.

---

## Open — awaiting inputs the codebase does not contain

| Decision | Options | Blocks | Needs |
|---|---|---|---|
| Batch data location | Aptos · external DA | W-04 | Cost of publishing batches to Aptos |
| Beta test asset | Aptos coin · fungible asset | W-08 | A chosen testnet asset |
| Role and key boundaries | — | W-06, Gate C | Operational decisions |
| STF upgrade policy | Fixed · governed | W-01 | Policy decision |

---

## Change history

| Date | Change |
|---|---|
| 2026-09-20 | D-01 to D-06 proposed; parameter set `sena-beta-params-1` frozen |
