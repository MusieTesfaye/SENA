# Fraud proofs on Aptos

Posting a state root makes history permanent, not correct. A dishonest
sequencer could post a root that credits itself money. Fraud proofs close
that gap.

## The game

1. **Challenge.** A watcher sees a posted block whose post-state root is not
   what re-executing it gives. It bonds and challenges.
2. **Bisect.** The block's execution is a trace of steps. The two parties
   narrow it down, range by range, to the **first step** they disagree on.
   The number of moves grows with the logarithm of the trace's length.
3. **One step, on Aptos.** Aptos re-executes that single step itself, in
   Move, from the state slot the step reads (with a Merkle proof) and the
   instruction the step runs.
4. **Verdict.** If the step's result differs from what the sequencer claimed,
   the assertion is **rejected** and the challenger wins the bond.

A party that stops responding loses by timeout.

## Aptos derives the instruction itself

The disputed step's instruction is not taken from either party. Aptos
**recompiles the disputed transaction** from the batch data that was posted
with the block, in Move, using the same rules the node uses. Generated
conformance vectors check that the Rust node and the Move compiler agree on
every instruction and every refusal.

## Keyless, disputed

A keyless signature is a Groth16 proof. If a block credits a forged keyless
transfer, the dispute ends at the step that verifies it, and Aptos runs the
Groth16 check and the Poseidon public-input hash on chain. That is too much
work for one Aptos transaction, so it is spread across several.

## Measured

On a local Aptos node, a forged keyless credit, disputed to the end:

```text
    1072  assertions::post            (batch data published, root computed on L1)
     950  assertions::open_challenge
     536  disputes::open
     120  4 bisection moves
    2094  keyless_jobs start, advance ×6, finish   (Groth16 verified on L1)
      61  disputes::one_step          → assertion rejected
    ----
    4833  gas units from post to rejection (≈0.0048 APT)
```

## The assumption

Security needs **one honest watcher**. If nobody watches, a wrong block
finalizes. The testnet runs one; anyone can run another with
`sena-node watch` ([Run a node](/docs/run-a-node)).
