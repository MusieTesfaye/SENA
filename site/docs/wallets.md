# Get a wallet

Three ways in. All three are real wallets on the testnet; pick whichever suits
you.

| | Sign in | Keys live | Best for |
|---|---|---|---|
| [Web wallet](#the-web-wallet) | Google | in this browser tab's storage | trying SENA in one click |
| [Browser extension](#the-browser-extension) | Google | in the extension | everyday use, and dapps |
| [MetaMask + SENA Snap](#metamask) | MetaMask | derived from your MetaMask recovery phrase | people who already use MetaMask |

## The web wallet

Open the [web wallet](/testnet) and press **Continue with Google**. Signing in
takes a few seconds while Aptos's prover makes the zero-knowledge proof.
There is nothing to install and no phrase to write down.

## The browser extension

The SENA extension runs in Chrome, Edge and Brave.

1. Download the extension zip from the [testnet page](/testnet) and unzip it.
2. Open `chrome://extensions` (in Edge, `edge://extensions`), turn on
   **Developer mode**, and choose **Load unpacked**. Pick the unzipped folder.
3. Pin SENA to the toolbar, open it, and sign in with Google.

Websites can ask the extension to connect and to sign. It always shows you
what you are approving.

## MetaMask

MetaMask cannot "add SENA as a network". Its network list is for chains that
speak Ethereum's format, and SENA has its own. Instead, MetaMask runs
**Snaps**: plug-ins that teach it new chains. This is how MetaMask supports
Solana, Bitcoin and Aptos.

1. Open the web wallet and choose **Connect MetaMask**.
2. MetaMask asks to install the **SENA Snap**. Approve it.
3. Your SENA address is derived from your MetaMask recovery phrase, so it is
   the same on every device where you use that phrase.

::: info MetaMask Flask
MetaMask installs only Snaps that MetaMask has reviewed. Until SENA's is
reviewed, use [MetaMask Flask](https://metamask.io/flask/), MetaMask's build
for developers, in a separate browser profile.
:::

## Get test coins

Every wallet has a **Faucet** button on each coin: 100 test USDC, USDT, EURC
or DAI. They are worth nothing, and are limited per hour.
