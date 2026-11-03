# Testnet

SENA's public testnet settles on Aptos testnet. Its coins are test coins: free
from the faucet, worth nothing.

<TestnetDetails />

## Get started

1. **Get a wallet**: the [web wallet](/docs/wallets#the-web-wallet), the
   [browser extension](/docs/wallets#the-browser-extension), or
   [MetaMask with the SENA Snap](/docs/wallets#metamask).
2. **Sign in with Google.** Your address is created on the spot.
3. **Press Faucet** on any coin to get 100 test dollars.
4. **Send** to an address, an email address or a phone number.
5. **Watch it** in the [explorer](/explorer).

## What runs it

One server runs the sequencer, which orders transactions and seals blocks.
Beside it:

- a **relayer** posts every block to the SENA contracts on Aptos testnet, with
  its data and a bond;
- a **watcher** re-executes every block from what was posted on Aptos and
  challenges any that is wrong;
- a **faucet** hands out test stablecoins;
- an **identity issuer** checks that you own an email or phone number and
  signs an attestation you can put on chain;
- a **key follower** accepts Google's new signing keys when Google rotates
  them.

Anyone can run their own watcher; see [Run a node](/docs/run-a-node).

::: warning Beta
SENA has not been audited. This testnet can be reset. Use test funds only.
:::
