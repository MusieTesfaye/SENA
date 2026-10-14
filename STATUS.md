# Status

**Unreleased (after 0.2.0-beta)** · 306 Rust tests + 76 Move tests passing · **verified on a local Aptos node; not deployed to any public network** · not audited

> **Fraud proofs work on a real Aptos node.** On a localnet, a batch whose
> keyless transfer was forged a thousandfold was posted with its batch data,
> challenged, bisected to one step, and rejected by Aptos after Aptos itself
> verified the transaction's Groth16 proof against the Aptos Keyless circuit's
> key. The relayer and watcher binaries posted and independently verified an
> honest block from L1 data alone. CI repeats both on every change
> (`.github/workflows/move.yml`, job *localnet dispute and agents*).
>
> Nothing is on devnet, testnet or mainnet, and nothing is audited.

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

| Capability | Where | Evidence |
|---|---|---|
| Sparse Merkle state with inclusion and non-inclusion proofs | `sena-state` | Property tests over arbitrary key sets |
| Deterministic execution producing a disputable trace | `sena-stf` | Same batch, same root, order-independent |
| Transfers, nonces, replay protection, strict Ed25519 | `sena-stf` | A key can spend only from its own account |
| Social handles resolving to addresses | `sena-stf` | Binding, release, and theft-prevention tested |
| Stablecoin gas with in-trace rate validation | `sena-stf` | Wrong rate rejected; rounding cannot make fees zero |
| Governance bounded by an allowlist, council epochs | `sena-stf` | Council cannot reach the dispute system; replayed approvals refused |
| **Keyless accounts on the Aptos Keyless circuit** | `sena-stf` | Aptos's sample proof verifies; every intermediate value matches aptos-core |
| Keyless wallet flow: session, nonce, authenticator, signing | `sena-node::keyless_client` | Assembled sample sign-in verifies; a proof for other inputs is refused |
| Bonded assertions, bisection, one-step adjudication (Rust) | `sena-fraudproof` | Honest party wins wherever fraud is placed (property test) |
| **Every instruction adjudicable on L1**, keyless included | `move/sena` | Move recompiles each disputed transaction and agrees with Rust on every generated case |
| **Batch data published on L1**; L1 computes the batch root | `move/sena` | A post whose data does not match its claim cannot be made |
| Batch-structure fraud proofs (uncompilable tx, start gaps, trace length) | `move/sena` | Move tests; watcher mock-L1 tests |
| **A full keyless fraud dispute on a real Aptos node** | `scripts/localnet-dispute.sh` | Assertion ends rejected; 4,809 gas units from post to rejection |
| Bonds and bridge custody move real fungible assets | `move/sena` | Balances checked on reject, refund, groundless challenge, withdrawal |
| Assertion lifecycle enforced by Aptos | `scripts/chain-lifecycle.sh` | 11/11 on a localnet: window, self-challenge and challenge all block as they must |
| **Relayer**: post with batch data, defend, finalize | `sena-node relay` | Mock-L1 tests; posted a real block on a localnet |
| **Watcher**: re-execute from L1 data, challenge, play to the end | `sena-node watch` | Mock-L1 tests: honest, forged, uncompilable, interrupted, wrong genesis; verified a real block on a localnet |
| Mempool admission against queued state, in constant work per transaction | `sena-node` | Two individually-affordable transfers rejected together |
| Blocks cut to fit one Aptos transaction (48 KiB of batch data) | `sena-node` | `blocks_are_cut_to_fit_one_l1_transaction` |
| JSON-RPC over HTTP with auth, rate limits, body cap | `sena-node` | End-to-end tests drive a live server |
| Persistence across restart, verified on load | `sena-node` | Corrupt state and cross-chain data both refused |
| Light-client account verification against a supplied root | `sena-light-client` | The caller must supply a trusted root |

### The claim that matters

An honest verifier beats a dishonest sequencer — and now on Aptos itself, not
only in a Rust model. On a localnet the forged keyless credit was rejected by
real transactions:

```
    1052  assertions::post            (batch data published, root computed on L1)
     950  assertions::open_challenge
     536  disputes::open
     120  4 bisection moves
    2093  keyless_jobs start, advance ×6, finish   (Groth16 verified on L1)
    ----
    4809  gas units from post to rejection (≈0.0048 APT at 100 octas per unit)
      58  disputes::one_step          → assertion rejected
```

A keyless verdict is spread over several transactions because one Poseidon
public-input hash plus a Groth16 check exceeds a single Aptos transaction's
execution budget; `sena::keyless_jobs` computes it resumably and the one-step
proof consumes it.

---

## Not finished

Listed in the order they block a real network.

### 1. Nothing has been audited

`sena::osp`, `sena::compiler`, `sena::keyless` and `sena::disputes` decide every
dispute. If their semantics diverge from the Rust node, disputes are decided
wrongly in one direction or the other, and nothing else can catch it. Generated
conformance vectors make divergence on known cases a test failure; they are not
a substitute for review. `SRS NFR-SEC-012` requires an independent audit before
mainnet.

### 2. Not deployed to a public network

The current package has run only on a local Aptos node. An earlier contract
version was published to devnet
([evidence](docs/beta/evidence/03-devnet-deployment.md)); that deployment
predates bonds, published batch data and keyless adjudication, and devnet has
since reset. Testnet needs a funded account (no programmatic faucet) and one
run of `scripts/chain-lifecycle.sh testnet` and `scripts/bridge-test.sh`.

The package is larger than one transaction and is published with
`--chunked-publish`.

### 3. Keyless depends on Aptos's services

SENA verifies proofs for the Aptos Keyless circuit; it does not produce them.
Wallets use the Aptos prover and pepper services through
`sena_node::keyless_client`, whose request and response shapes follow the
services' published API but have been exercised here only against fixtures —
no live sign-in has been run. Consequences:

- Proving availability is Aptos's. If the prover is down, new keyless sessions
  cannot start (existing sessions keep working until their ephemeral keys
  expire).
- The pepper determines the address. A wallet must use one pepper source
  consistently, or its user's address changes.
- **Training-wheels signatures are not checked.** Aptos co-signs proofs as a
  defence against circuit bugs; SENA relies on the circuit and the ceremony
  alone.
- JWK rotation is a council governance action. Nothing watches providers'
  JWKS endpoints and proposes rotations automatically; until a rotation lands,
  proofs over a new key are refused.

The insecure devnet setup is usable only behind `allow_insecure_test_setup`,
and exists because Aptos publishes a real proof for it.

### 4. Operating the agents

- **The relayer halts when an assertion is rejected.** That is the right
  default — continuing would build on fraud — but recovering (rolling the
  sequencer back to the last good assertion) is a manual operation.
- **The watcher halts if a wrong assertion finalized before it saw it.** L1's
  canonical chain would then contain fraud; nothing automatic can fix that.
- The watcher finds batch data by scanning the proposer's transaction history
  through the fullnode REST API. That needs a fullnode that keeps history, and
  costs time proportional to that history; an indexer-backed lookup would not.
- Both agents sign through the Aptos CLI and keep keys in its profile; there is
  no HSM or remote-signer integration.

### 5. Single sequencer, no decentralisation

By design for now. Fraud proofs constrain *what state the sequencer can
assert*; they do not constrain which transactions it includes or in what order.
Forced inclusion exists in `sena::bridge` but is not wired into the Rust node.

### 6. Operational gaps

- Fees are flat per transaction; per-instruction gas metering is not implemented.
- State is an in-memory trie snapshotted to disk. RocksDB and NOMT, as the SDD
  specifies, are not integrated.
- No peer-to-peer layer.
- `scripts/bridge-test.sh withdraw` is not automated end to end on a live
  network; withdrawals are tested in Move and in Rust.

---

## Known trade-offs, chosen deliberately

**Withdrawal takes a challenge window.** Seven days by default, 24 hours as the
hard floor. This is intrinsic to optimistic rollups.

**Security assumes one honest verifier.** The protocol reduces trust from "the
sequencer is honest" to "someone is watching". `sena-node watch` is that
someone; a network where nobody runs one is functionally custodial.

**Batch data lives on L1.** Every batch is published in the transaction that
asserts it, so availability is Aptos's rather than the sequencer's. The cost is
L1 gas per byte and a 48 KiB cap per batch.

**Bisection is over state-machine instructions, not RV32IM.** Every instruction
must also be implemented in the L1 verifier; `sena::compiler` and `sena::osp`
are that implementation. Discussed in
[`crates/sena-stf/src/instruction.rs`](crates/sena-stf/src/instruction.rs).

**Salted identifier hashes resist disclosure, not enumeration.** The state does
not publish anyone's contact details, but a guess can be confirmed.

---

## Fixed in this revision

- **Any key could spend from any Ed25519 account.** Authentication now requires
  `sender == public_key` and verifies strictly, as Aptos does.
- **The October 2026 keyless prototype was unsound** (forgeable verification
  key, placeholder ceremony and prover, bypassable JWK check, leaking pepper
  service). It is quarantined in `attic/unsafe-keyless-2026-10/` and replaced by
  the Aptos Keyless circuit.
- **Four instructions could not be adjudicated** (`VerifyGasAsset`,
  `VerifyCouncil`, `SetGasAsset`, `SetParameter`); now every instruction can,
  and L1 compiles the disputed transaction itself rather than trusting either
  party's account of it.
- **Batch roots could commit to data nobody could open.** The data is now
  published on L1 and the root computed there.
- **Mempool admission was quadratic** in the queue, a cheap way to stall the
  sequencer; it now does constant work per transaction.

---

## Where this sits against the beta gates

Against the release gates in [`BETA_BUILD_PLAN.md`](docs/beta/BETA_BUILD_PLAN.md):
**Gate B — local end-to-end integration against an Aptos node — is met.** The
honest lifecycle and an adversarial one (a forged keyless credit disputed to
rejection) both run against a local node, in CI. Gate C (public testnet) is
next and needs only funding and a deployment run.

## Roadmap

1. **Testnet deployment** of the current package, bridge with Circle USDC.
2. **Independent audit** of the dispute contracts, the L1 compiler and keyless
   verification.
3. **Live keyless sign-in** against the Aptos prover and pepper services, and
   training-wheels checking.
4. **Sequencer recovery** after a rejected assertion, and forced inclusion in
   the node.
5. **Public verifier programme** — the security model is only as good as the
   number of independent parties actually watching.

---

*Questions about anything in this document are welcome, including the parts that
say something does not work. Those are the ones worth asking about.*
