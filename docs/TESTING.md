# Testing SENA

Layers, cheapest first. Each tests something the one before it cannot.
For a guided run through all of them, see [`END_TO_END.md`](END_TO_END.md).

| Layer | Command | Time | What it proves |
|---|---|---|---|
| Rust suite | `cargo test --workspace` | ~1 min | The protocol logic is correct in isolation |
| Demo | `cargo run --bin sena-demo` | ~30 s | Fraud is caught, end to end |
| Live node | `sena-node run` + `send` | ~2 min | It works as a service over HTTP |
| Move contracts | `aptos move test` | ~1 min | Aptos computes the same answers |
| On chain | `scripts/chain-lifecycle.sh` | ~3 min | Aptos *enforces* the safety rules |
| Disputes on chain | `scripts/localnet-dispute.sh` | ~3 min | Aptos *adjudicates* fraud, keyless proof and all |
| Agents on chain | `scripts/localnet-agents.sh` | ~2 min | The relayer and watcher binaries work against Aptos |

The last three are the only layers where something other than our own code is
deciding anything.

---

## 1. The Rust suite

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The ones worth reading rather than just running:

```sh
cargo test -p sena-fraudproof --test dispute -- --nocapture
```

`honest_challenger_always_wins_wherever_fraud_is_placed` is a property test: it
puts fraud at every step in a trace and asserts the honest party wins each time,
and that bisection converges on exactly the falsified step. If the fraud proof
system is broken, this is what notices.

```sh
cargo test -p sena-state --test trie_properties
```

`root_is_history_independent` replays arbitrary insert/delete sequences and
checks the root depends only on the final key set. Two honest nodes reaching the
same state by different routes must agree, or they would dispute each other.

```sh
cargo test -p sena-light-client
```

`mobile_verification_performance_is_sub_millisecond` checks that Sparse Merkle
Proof verification runs in < 0.1ms and rejects any forged balance or altered
nonce.

## 2. The demo

```sh
cargo run --release --bin sena-demo
```

Three scenarios against the real implementation. The second is the interesting
one: a sequencer executes a debit of 1 where the batch says 1,000, and bisection
narrows 48 execution steps to the falsified one in two rounds.

## 3. A live node

```sh
./target/release/sena-node keygen
./target/release/sena-node genesis --data-dir ./devnet --dev --fund 0xYOUR_ADDRESS:100000000
./target/release/sena-node run --data-dir ./devnet --listen 127.0.0.1:8545
```

In another terminal:

```sh
RPC=http://127.0.0.1:8545
./target/release/sena-node send --rpc $RPC --secret YOUR_SECRET \
    --to 0x1111111111111111111111111111111111111111111111111111111111111111 \
    --amount 1000 --nonce 0
./target/release/sena-node query --rpc $RPC info
```

**Worth checking deliberately:** `height` advances while `finalized_height`
stays at 0. The block is sealed and its state is real, but its assertion has not
survived the challenge window, so nothing can be withdrawn against it. If those
two numbers ever move together, something is wrong.

### Verify the node independently

Do not take the node's word for its own state root:

```sh
cargo test -p sena-node --test beta_e2e -- --nocapture
```

`published_batch_data_reproduces_the_asserted_root` pulls a block over HTTP,
re-executes it from genesis, and asserts the root matches. That test failing
would mean the sequencer had lied.

## 4. The Move contracts

Requires Aptos CLI **7.9.0** specifically — see [`../move/README.md`](../move/README.md).

```sh
aptos move test --package-dir move/sena --named-addresses sena=0xCAFE
```

76 tests. Three groups matter:

- **Conformance** — `codec::sha256_matches_rust`, `trie::leaf_hash_matches_rust`,
  `osp::machine_commitment_matches_rust` compute values in Move and compare them
  against what Rust produced. A divergence here would make Aptos decide disputes
  wrongly.
- **Generated vectors** — `tests/vectors.move` is written by the Rust node
  (`SENA_WRITE_MOVE_VECTORS=1 cargo test -p sena-fraudproof --test
  move_vectors`): transactions, their compiled programs and executed steps,
  keyless included. `dispute_e2e_test.move` checks L1 compiles and executes
  every one exactly as Rust does.
- **Lifecycle** — `lifecycle_test.move` drives the contracts the way an account
  does. These exist because the module tests call Move functions directly, which
  is why they did not catch that `disputes::Registry` was never created by
  anything.

## 5. On chain

Start a local node first (`aptos node run-localnet`), or name a public network:

```sh
scripts/chain-lifecycle.sh local      # or devnet, testnet
```

Deploys to a fresh account and exercises the lifecycle, asserting an expected
outcome at every step. The two that matter are failures:

```
finalize inside the challenge window  →  E_WINDOW_OPEN
challenge your own assertion          →  E_SELF_CHALLENGE
finalize while challenged             →  E_WRONG_STATUS
```

If either ever succeeds, the script fails loudly. That is the core safety claim,
and at this layer Aptos is the one enforcing it.

The script also derives the assertion ids independently from the canonical
encoding rather than reading them back from the chain, so a mismatch between the
Move and Rust hashing shows up as a rejected argument.

Devnet resets periodically. Use `testnet` for evidence you want to keep.

### A dispute, played on chain

```sh
scripts/localnet-dispute.sh
```

Publishes the package to fresh accounts and replays a plan from
`cargo run -p sena-fraudproof --example dispute_plan`: a batch whose keyless
transfer the proposer credits a thousandfold. The script posts it with its
batch data, challenges, plays the bisection, computes the keyless verdict with
`keyless_jobs` (Aptos verifies the Groth16 proof), submits the one-step proof,
and requires the assertion to end rejected. It prints the gas of every move.

### The relayer and watcher, on chain

```sh
cargo build -p sena-node && scripts/localnet-agents.sh
```

Starts a sequencer, has `sena-node relay` post its block to L1, and has
`sena-node watch` -- given only the genesis file and L1 -- re-execute and verify
it. Fails if the watcher challenges an honest block. The fraud paths of both
agents are covered by `cargo test -p sena-node --test l1_agents`, against an
in-memory model of the contracts.

### Access control

The node is unauthenticated by default, which is right bound to localhost and
wrong for anything else:

```sh
sena-node run --data-dir ./dev --listen 0.0.0.0:8545 \
    --auth-token "$(openssl rand -hex 32)" --rate-limit 600
```

Binding a non-local address without a token prints a warning rather than
refusing — an operator behind their own proxy may legitimately want it, but it
should never happen by accident.

```sh
cargo test -p sena-node --test beta_e2e
```

covers a missing token, a wrong token, a client exceeding the limit, and a body
over the cap.

## 6. Real stablecoins on testnet

The bridge custodies **Circle USDC on Aptos testnet** —
`0x69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832`, 6
decimals. It is a *dispatchable* fungible asset, so transfers run Circle's
blocklist and pause hooks; the bridge calls `dispatchable_fungible_asset`
rather than the plain entry point, or a blocked account would be silently
permitted.

Testnet has no programmatic faucet, so funding is manual and one-off:

```sh
aptos init --network testnet --profile sena-testnet --assume-yes </dev/null
scripts/bridge-test.sh status        # prints your address and what is missing
```

Then fund it:

- **APT for gas** — <https://aptos.dev/network/faucet>
- **USDC** — <https://faucet.circle.com>, select Aptos testnet

```sh
scripts/bridge-test.sh setup         # publish and initialise
scripts/bridge-test.sh deposit       # move USDC into custody
scripts/bridge-test.sh status        # custody balance
```

### Why you cannot demonstrate a withdrawal the same day

A withdrawal requires an assertion that has **finalized**, and the challenge
window floor is 24 hours. There is no configuration that shortens it — the floor
is enforced in `assertions.move` and governance has no path to lower it. Waiting
is the design working.

The withdrawal path also needs a Merkle proof of your L2 balance, which the
sequencer produces. Wiring that into the script is outstanding.

---

## Trying to break it

The tests above check that it works. These are worth attempting to check that it
*fails* correctly — and they are the interesting part of any review.

**Can you finalize a challenged assertion?** Everything else rests on no. Try it
directly against a deployed contract with `aptos move run`.

**Can a non-party move in a dispute?** Until recently, yes — the acting party
was a function argument rather than derived from the signer, which made the turn
and clock checks decorative. Covered now by
`a_non_party_cannot_move_in_a_dispute`, but worth re-probing after any change to
`disputes.move`.

**Can you reject a sound assertion?** `challenger_won` is `public(friend)` and
reachable only from `sena::disputes`. If it ever becomes `public`, any module
could reject honest assertions — the inverse of what this system is for.

**Can you make two honest nodes disagree?** Anything non-deterministic in the
state transition function does this. `HashMap` and `HashSet` are denied
workspace-wide and float arithmetic is a deny-level lint, but a new dependency
could reintroduce it. CI runs the state-root tests twice in separate processes
and diffs the results.

**Can you submit a `u128` amount that a JavaScript client would misread?**
Amounts travel as decimal strings for exactly this reason — `serde_json` cannot
encode `u128`, and a JSON number above 2^53 would be silently rounded. Try
`amounts_travel_as_strings_not_json_numbers`.

## What no test here covers

- **On testnet, only the lifecycle and a deposit have run**
  ([evidence](beta/evidence/04-testnet-deployment.md)); disputes and the
  agents have run on a local node only.
- **The withdrawal path has not been driven end to end on chain.** The node
  produces a proof and the contract verifies it and pays out in Move tests, but
  nobody has yet spent a proof from `sena_getWithdrawalProof` against a
  finalized assertion on a live network.
- **No live keyless sign-in.** The wallet client is tested with Aptos's sample
  proof and fixture responses, not against the Aptos prover and pepper
  services with a real identity provider.
- **The watcher's fraud paths run against a model of L1**, not a live one; the
  dispute itself is proven on chain separately, by `localnet-dispute.sh`.
- **Nothing has been audited or fuzzed.**

[`../STATUS.md`](../STATUS.md) keeps the full list.
