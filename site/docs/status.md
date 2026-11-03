# Status and roadmap

SENA is **beta software, not audited, on Aptos testnet.** This page is the
short version; the line-by-line account, with the evidence for each claim, is
[STATUS.md](https://github.com/MusieTesfaye/SENA/blob/main/STATUS.md).

## Working, and tested

- **Keyless accounts** on Aptos's audited circuit and mainnet ceremony key,
  verified on L2 and in disputes on Aptos.
- **Fees in USDC, USDT, EURC and DAI**, each paying its own: metered gas, a
  demand-driven base fee, refunds and tips.
- **Pay by email, phone or username** through issuer attestations, with the
  account's consent, revocable.
- **A chain id in every signature**: nothing signed for one SENA network is
  valid on another.
- **Fraud proofs on Aptos** for every instruction, keyless included. A forged
  transfer has been disputed to rejection on an Aptos node.
- **Block data published on Aptos**, with the batch root computed there.
- **Relayer and watcher**, each tested against a live Aptos node.
- **Wallets**: web, browser extension, MetaMask Snap.
- **331 Rust and 78 Move tests**, plus browser tests of the wallet against a
  live node.

## Not finished

- **No audit.**
- **Deposits from Aptos are not credited on SENA yet**: the bridge takes
  custody, but no instruction credits the L2. Coins come from genesis and
  faucets.
- **No dispute played on Aptos testnet yet.** Disputes have run on local
  Aptos nodes only.
- **One sequencer**, and forced inclusion through Aptos is not wired into the
  node.
- **No private identifiers** (Celo's ODIS): linked phone numbers can be
  guessed.
- **No account recovery.**
- **Fees are not converted to APT**: the operator funds Aptos gas by hand.

## Roadmap

1. Complete the testnet: a dispute and a withdrawal on Aptos testnet;
   deposits credited on L2.
2. ODIS-style private identifiers.
3. Independent audit.
4. Recovery and more sign-in providers.
5. Mainnet with independent watchers and a council that is not one company.
