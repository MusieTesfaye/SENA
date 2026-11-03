# Launching the public testnet

Everything that goes online, in order. Allow an afternoon. Nothing here
costs money: Oracle's free tier, Vercel's hobby plan, free testnet APT, and a
free npm account.

| What | Where | Repository |
|---|---|---|
| The chain: node, relayer, watcher, faucet, issuer | Oracle Cloud VM | SENA, [`deploy/`](../deploy/README.md) |
| The website: vision, docs, explorer | Vercel | SENA, `site/` |
| The web wallet, and the extension's download | Vercel | wallet |
| The MetaMask Snap | npm | wallet, `snap/` |

## 1. The chain (about 30 minutes)

Follow [`deploy/README.md`](../deploy/README.md):
1. Create an Ampere A1 VM on Ubuntu.
2. Open ports 80 and 443.
3. Run `deploy/setup.sh`.
4. Fund the two Aptos addresses it prints with testnet APT.

When it finishes, it prints the URLs and `VITE_*` values the next steps need.
They're also kept in `deploy/data/testnet.json`. Check it:

```sh
curl -s https://rpc.<host> -d '{"method":"sena_getChainInfo"}'
```

## 2. Google sign-in (10 minutes)

In [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials),
use one OAuth client of type **Web application** for the wallet and the
extension:

| Setting | Values |
|---|---|
| Authorised JavaScript origins | `https://<wallet>.vercel.app` |
| Authorised redirect URIs | `https://<wallet>.vercel.app/` and `https://phkknehihpoajnkoiabbbknbjaonflad.chromiumapp.org/` |

The second redirect is the SENA extension's. Its id is fixed by the key in
the wallet repository. On the consent screen, publish the app, or add the
Google accounts you will demo with as test users.

## 3. The web wallet on Vercel (10 minutes)

1. **Add New → Project** and import `MusieTesfaye/wallet`. Its `vercel.json`
   sets the build.
2. Environment variables, from step 1's output:

   ```
   VITE_SENA_RPC_URL=https://rpc.<host>
   VITE_FAUCET_URL=https://faucet.<host>
   VITE_ISSUER_URL=https://issuer.<host>
   VITE_TRUSTED_ISSUERS=<issuer address>
   VITE_GOOGLE_CLIENT_ID=<client id from step 2>
   ```
3. Deploy. The extension downloads from `https://<wallet>.vercel.app/sena-extension.zip`.

## 4. The website on Vercel (5 minutes)

1. Import `MusieTesfaye/SENA` as a second project, with **Root Directory**
   `site`.
2. Environment variables:

   ```
   VITE_SENA_RPC_URL=https://rpc.<host>
   VITE_FAUCET_URL=https://faucet.<host>
   VITE_ISSUER_URL=https://issuer.<host>
   VITE_APTOS_CONTRACT=<aptos_contract from testnet.json>
   VITE_WALLET_URL=https://<wallet>.vercel.app
   VITE_EXTENSION_URL=https://<wallet>.vercel.app/sena-extension.zip
   ```
3. Deploy. Until this branch is merged, set the project's production branch
   to `claude/exciting-ritchie-8g61na`.

## 5. Identities (optional, 15 minutes per provider)

To let people link an email or phone, give the issuer its providers. Section
3 of [`deploy/README.md`](../deploy/README.md) covers this. Include the
wallet's Vercel address and the extension's addresses in `WALLET_ORIGINS`.

## 6. The MetaMask Snap (10 minutes)

```sh
cd wallet/snap && npm install && npm test && npm publish --access public
```

The `@sena-network` npm scope must be yours. Create the organisation on
npmjs.com, or rename the package. Until MetaMask reviews the Snap, people
install it with [MetaMask Flask](https://metamask.io/flask/).

## The demo, end to end

1. **The site**: the vision, then the live block count on the home page.
2. **The wallet**: *Continue with Google*. An address appears, with no seed
   phrase.
3. **Faucet** on USDT, then **Send** 10 USDT to a second account, signed in
   with another Google account. The fee is shown and paid in USDT.
4. **The explorer**: the transfer, its block, and its assertion on Aptos.
   Follow the contract link to the Aptos explorer to see the posts.
5. **The extension**: the same account in the toolbar. Then a site asks to be
   paid through `window.sena`, and the approval window shows what it asks.
6. **MetaMask**: *Use MetaMask*. A SENA account appears inside MetaMask
   Flask, and every transaction is shown there before signing.
7. **Identities**, if set up: link your email, then pay it from the other
   account by typing the email.

## Before you show it

- Say plainly that it's **unaudited beta on testnet**. The site and docs
  already say so.
- The chain lives on one VM. Back up `deploy/data/`.
