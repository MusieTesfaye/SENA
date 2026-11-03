# Architecture

SENA is an **optimistic rollup** on Aptos. A fast sequencer orders
transactions and gives confirmations in about a second; Aptos is the system
of record, and anyone can prove the sequencer wrong.

```text
   wallets ──▶ sequencer (L2) ──▶ blocks, every ~2 s
                    │
                    │ relayer: each block + its data + a bond
                    ▼
        ┌──────── Aptos ─────────┐
        │ assertions  disputes   │◀── watcher: re-executes every block,
        │ bridge      keyless    │    challenges a wrong one
        └────────────────────────┘
```

## The pieces

| Part | Role |
|---|---|
| **Sequencer** | Admits transactions, executes them, seals blocks, serves JSON-RPC. |
| **State** | A sparse Merkle tree of balances, nonces, fee assets, attestations and governance records. Each block commits to its root. |
| **Relayer** | Posts each block to Aptos as a bonded *assertion*: pre- and post-state roots and **all of the block's transactions**. Answers disputes; finalizes after the window. |
| **Watcher** | Reads assertions and their data from Aptos alone, re-executes them, and challenges any whose roots are wrong. |
| **Aptos contracts** | `assertions` (bonds, windows, finality), `disputes` (bisection, one-step proof), `compiler` and `osp` (the L2 rules, in Move), `keyless` (Groth16 on L1), `bridge` (custody). |

## A transaction's life

1. **Signed** in the wallet: by a Google sign-in (keyless) or an Ed25519 key.
   It names the chain id, so it cannot be replayed on another SENA network.
2. **Admitted** if the sender can pay the fee, counting what is already
   queued.
3. **Executed** into a trace of small instructions (debit, credit, check the
   fee asset, charge the base fee…), each of which changes one state slot.
4. **Soft-confirmed** in a block about a second later.
5. **Posted** to Aptos with the block.
6. **Final** after the 24-hour challenge window passes unchallenged. Only then
   can it be withdrawn against on Aptos.

## Why the data is on Aptos

A rollup is only as honest as its data is available: if nobody can see the
transactions, nobody can check them. SENA publishes every block's
transactions in the same Aptos transaction that asserts it, and Aptos
computes the batch root itself. Availability is Aptos's, not the
sequencer's. The cost is about 48 KiB of data per block at most.
