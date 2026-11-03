# Fees in stablecoins

There is no SENA token to buy. You pay fees in the coin you send:

| Coin | Fee paid in | Rate |
|---|---|---|
| USDC | USDC | 1 : 1 with the network's dollar unit |
| USDT | USDT | 1 : 1 |
| DAI | DAI | 1 : 1 |
| EURC | EURC | 0.925 EURC per dollar of fee |

## What a transfer costs

Fees work like Ethereum's, priced in dollars:

- **Gas** measures the work: 21,000 for any transaction, plus the coin's own
  intrinsic gas, plus each step. A plain USDC transfer uses 41,000 gas.
- **The base fee** per gas rises when blocks are busy and falls when they are
  not, never below a floor. At the floor, a USDC transfer costs about
  **$0.0035** from a Google-signed account (checking the zero-knowledge proof
  is 100,000 of its gas), or about $0.001 from a plain key.
- **A tip** is optional, and goes to the sequencer.

Before you send, the wallet shows the most the fee can be. That amount is held,
and whatever is not used comes straight back in the same transaction.

## Where fees go

- **The base fee** goes to a fee vault. A governed fee split pays it out to
  named beneficiaries, as Celo's `FeeHandler` does.
- **Tips** go to the sequencer.

Every one of these rules is replayed by the Aptos contracts if a block is
disputed. Charging you more than the rules allow is a fraud anyone can
prove.
