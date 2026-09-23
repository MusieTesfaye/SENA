# Status

**Version 0.2.0-beta** · 248 Rust tests + 45 Move tests passing · **deployed to Aptos devnet** · not audited

> **Live on devnet.** The package is published and the assertion lifecycle runs
> on chain. Aptos itself refuses to finalize an assertion inside its challenge
> window, and refuses to finalize a challenged one —
> [evidence with transaction hashes](docs/beta/evidence/03-devnet-deployment.md).
> No bonds move yet, and nothing is audited.

**Beta planning:** [`docs/beta/BETA_SCOPE.md`](docs/beta/BETA_SCOPE.md) ·
[`DECISION_LOG.md`](docs/beta/DECISION_LOG.md) ·
[`BETA_EXECUTION_CHECKLIST.md`](docs/beta/BETA_EXECUTION_CHECKLIST.md) ·
[`TRACEABILITY.md`](docs/beta/TRACEABILITY.md)

This document exists so that nobody has to guess which parts of SENA are real.
It is written to be read by someone evaluating the project, and it errs toward
understating rather than overstating. Anything not listed as working should be
assumed not to work.

---

## Works today, and is tested

These are exercised by the test suite on every run, and by
`cargo run --bin sena-demo`.

| Capability | Where | Evidence |
|---|---|---|
| Sparse Merkle state with inclusion and non-inclusion proofs | `sena-state` | 26 tests, incl. property tests over arbitrary key sets |
| Proof-based root derivation (what L1 does in a dispute) | `sena-state` | Property test: agrees with direct application |
| Deterministic execution producing a disputable trace | `sena-stf` | Same batch, same root, order-independent |
| Transfers, nonces, replay protection | `sena-stf` | Replay rejected; value conserved across batches |
| Social handles resolving to addresses | `sena-stf` | Binding, release, and theft-prevention tested |
| Stablecoin gas with in-trace rate validation | `sena-stf` | Wrong rate rejected; rounding cannot make fees zero |
| Governance bounded by an allowlist | `sena-stf` | Council cannot reach the dispute system |
| Bonded assertions, challenge windows, finalization | `sena-fraudproof` | Descendants rejected on a successful challenge |
| Interactive bisection to a single step | `sena-fraudproof` | Converges on the falsified step, logarithmic rounds |
| One-step adjudication | `sena-fraudproof` | Honest party wins wherever fraud is placed (property test) |
| Mempool admission that accounts for queued state | `sena-node` | Two individually-affordable transfers correctly rejected together |
| Block production and assertion posting | `sena-node` | Blocks chain; roots continue |
| JSON-RPC over HTTP | `sena-node` | End-to-end tests drive a live server |
| Independent verification from published data | `sena-node` | `published_batch_data_reproduces_the_asserted_root` |
| Persistence across restart, verified on load | `sena-node` | Corrupt state and cross-chain data both refused |
| Keyless claim validation and ephemeral-key binding | `sena-stf` | Stolen-JWT and expiry-extension attacks rejected |
| Move contracts compile and self-test | `move/sena` | 45/45 Move tests, including Rust conformance |
| Assertion lifecycle enforced by Aptos | `move/sena` | Devnet: window and challenge both block finalization |

### The claim that matters

An honest verifier beats a dishonest sequencer. A property test places fraud at
every `Credit` step in a trace and asserts the honest challenger wins each time,
and that bisection lands on exactly the falsified step. The converse is tested
too: a groundless challenge loses.

---

## Not finished

Listed in the order they block a real network.

### 1. Keyless sign-in is incomplete — the flagship feature

**Formally deferred for beta** (decision D-03), matching the build plan's own
recommendation.

**What works:** JWT claim parsing, issuer allowlisting, expiry, `aud` scoping
that makes one user unlinkable across applications, deterministic address
derivation, and — the part keyless systems usually get wrong — verifying that
the token's `nonce` commits to *this* ephemeral key. A genuine JWT obtained from
a log cannot be paired with an attacker's key.

**What does not:** verifying that the token was actually issued by Google or
Apple. That is what the zero-knowledge proof attests to, and no proof verifier is
implemented. `KeylessVerifier` is the seam; `NoVerifier` refuses everything and
is the default.

**Consequence:** keyless transactions are rejected outright. Accepting them on
the strength of the checks that *are* implemented would let anyone spend from any
keyless account by presenting claims they invented. Refusing is the only safe
behaviour, and the code does refuse.

### 2. The Aptos L1 contracts are deployed to devnet, not testnet

**Resolved since the last revision.** All six modules compile, 45 of 45 Move
tests pass, and the package is published to Aptos devnet with the assertion
lifecycle verified on chain.

Two authorization holes were found and fixed in the process, both invisible to
unit tests because those call Move functions directly rather than through a
transaction:

- `disputes::Registry` was never created by anything, so every dispute entry
  point would have aborted on a real network.
- Dispute moves took the acting party as a *parameter* rather than deriving it
  from the signer, so any account could have moved as either side — making the
  turn and clock checks decorative. `challenger_won` was also `public`, meaning
  any module could reject a sound assertion.

What remains open:

- **Devnet only, and devnet resets.** Nothing is on testnet.
- **Bond escrow is bookkeeping, not custody.** No coin moves; posting an
  assertion costs gas and nothing else.
- **No dispute has been played to completion on chain.** Only that a challenge
  blocks finalization.
- **Four instructions are not adjudicable.** `VerifyGasAsset`, `VerifyCouncil`,
  `SetGasAsset` and `SetParameter` abort, so a dispute over a gas-rate or
  governance step cannot be settled on L1. That is a beta blocker.
- **Nothing is audited.**

The toolchain is narrow and deliberately pinned: CLI `7.9.0` with the framework
at commit `46d871fa…`. Newer CLI releases abort on CPUs without AVX2, and newer
framework revisions use syntax `7.9.0` cannot parse. See
[`move/README.md`](move/README.md).

### 3. Nothing has been audited

`sena::osp` — the one-step verifier — is the highest-value target in the system.
It is the final arbiter of every dispute, and if its semantics diverge from the
Rust implementation it decides disputes wrongly in one direction or the other.
Nothing else can catch that, because nothing else is appealed to.

`SRS NFR-SEC-012` makes independent audit of the dispute contracts a named
requirement before mainnet.

### 4. No real L1 integration

Assertions, bonds and withdrawals are modelled in Rust as a state machine. No
transaction has ever been submitted to Aptos. Bond custody and slashing are
bookkeeping, not coin movement.

### 5. Single sequencer, no decentralisation

By design for now, and stated in the SDD. Fraud proofs constrain *what state the
sequencer can assert*; they do not constrain which transactions it includes or
in what order. Forced inclusion is specified and present in the Move draft but
not wired into the Rust node.

### 6. Operational gaps

- Fees are flat per transaction; per-instruction gas metering is not implemented.
- State is an in-memory trie snapshotted to disk. RocksDB and NOMT, as the SDD
  specifies, are not integrated.
- No peer-to-peer layer. A verifier follows a sequencer over RPC.
- No fraud-proof data availability layer; batch data is served by the node.

---

## Known trade-offs, chosen deliberately

These are not gaps. They are decisions, and they are the ones a reviewer should
push on.

**Withdrawal takes a challenge window.** Seven days by default, 24 hours as the
hard floor. This is intrinsic to optimistic rollups, not an implementation
shortcoming. Third-party fast-withdrawal liquidity can mask it; validity proofs
would remove it.

**Security assumes one honest verifier.** The protocol reduces trust from "the
sequencer is honest" to "someone is watching". That is a far weaker assumption,
but it is not *no* assumption. A network where nobody runs a verifier is
functionally custodial regardless of what the protocol permits.

**Bisection is over state-machine instructions, not RV32IM.** The SDD specifies
compiling the state transition function to RISC-V. Both implementations bisect a
higher-level instruction set instead. The protocol structure is identical; the
trade-off is that every new instruction must also be implemented in the L1
verifier. Discussed in [`crates/sena-stf/src/instruction.rs`](crates/sena-stf/src/instruction.rs).

**Salted identifier hashes resist disclosure, not enumeration.** A network-wide
public salt defeats precomputed tables but not an attacker willing to hash a
leaked email corpus. The property delivered is that the state does not publish
anyone's contact details — not that a guess cannot be confirmed.

---

## What beta testing changed

Running the system end-to-end over HTTP surfaced two real defects that unit
tests had not:

**`u128` amounts could not be represented in JSON.** `serde_json` refuses to
encode `u128`, and any client whose JSON numbers are IEEE-754 doubles —
JavaScript included — would have silently rounded a balance above 2^53. Amounts
now travel as decimal strings, with a regression test.

**The transaction signing digest hashed `serde_json` output.** What a user signs
must be reproducible by anything that verifies the signature, including a Move
contract. Payloads now use the canonical binary codec.

An earlier round of work surfaced a third, from a test written against the spec:
the dispute clock budget was a fixed 48 hours per party — 96 hours total, longer
than the 24-hour window floor. A dispute could have outlived the window it exists
to resolve within. The budget is now derived from the window.

---

## Where this sits against the beta gates

Against the seven release gates in
[`BETA_BUILD_PLAN.md`](docs/beta/BETA_BUILD_PLAN.md), the project is at
**Gate A, in progress**. The scope freeze, parameter freeze and traceability
matrix are done; the SRS/SDD amendment for the execution target is outstanding.

Gate B — local end-to-end integration against an Aptos node — is now reachable:
the Move package compiles and its tests pass, which was the item blocking it.
What Gate B still needs is a local Aptos deployment and an assertion lifecycle
run against it. Nothing has been deployed yet.

[`BETA_EXECUTION_CHECKLIST.md`](docs/beta/BETA_EXECUTION_CHECKLIST.md) carries a
status for every item.

## Roadmap

In dependency order, following the build plan's critical path.

1. **Local Aptos integration.** The honest and adversarial assertion lifecycles
   against a local node — Gate B. The contracts compile, so this is the next
   real step.
2. **Adjudicate the remaining four instructions.** Until `VerifyGasAsset` and
   `VerifyCouncil` can be settled on L1, disputes over gas and governance steps
   have no resolution path.
3. **Aptos settlement adapter.** Real signed transactions, real assertions.
4. **Independent data availability.** Batch data currently comes from the same
   node that produced the assertion, which is the weakest link in the security
   claim.
5. **Bridge with one test asset.** Deposits, withdrawals against finalized roots,
   custody reconciliation.
6. **Independent audit** of the dispute contracts and the one-step verifier.
7. **Keyless proof verification** — Groth16 over BN254 against Aptos's
   verification key, replacing `NoVerifier`. Deliberately after the settlement
   path is real, per D-03.
8. **Public verifier programme** — the security model is only as good as the
   number of independent parties actually watching.

---

*Questions about anything in this document are welcome, including the parts that
say something does not work. Those are the ones worth asking about.*
