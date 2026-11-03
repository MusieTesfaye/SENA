# The vision

**Digital dollars that anyone can use with an account they already have,
without trusting the company that runs the rails.**

## The problem

Stablecoins already move real money. Using them still feels like operating a
server:

- **A seed phrase.** Lose twelve words and the money is gone. Most people
  will never accept that.
- **A gas token.** Before you can send dollars, you must buy a second,
  volatile token to pay the fee, on an exchange, with identity checks.
- **A hex address.** `0x7f3a9c…` is how you pay someone. One wrong character
  and the money is gone.

The usual fix is a company in the middle: a custodial app that holds the keys
and the coins. That works until the company fails, freezes accounts, or is
hacked. It hands custody back to the institutions crypto was meant to route
around.

## What SENA does

SENA is a payments network, a Layer 2 on Aptos, that fixes all three in the
protocol itself rather than in each app:

| Friction | SENA |
|---|---|
| Seed phrase | **Sign in with Google.** Aptos Keyless: a zero-knowledge proof that you signed in. No key to lose, and nobody holds one for you. |
| Gas token | **Pay fees in the coin you send.** USDC, USDT, EURC and DAI each pay their own fees, as on Celo. |
| Hex address | **Pay an email or phone number.** Issuers attest that an identifier belongs to an account (Celo's SocialConnect). |
| Trusting the operator | **Fraud proofs on Aptos.** Every block is posted with its data. Anyone can challenge a wrong one, and Aptos decides. |

The result is an app that feels like Venmo, on rails nobody can quietly
change.

## Why this design

**Celo proved the product, on Ethereum's terms.** Celo pioneered paying fees in
stablecoins and paying people by phone number. SENA takes the parts that
worked, the fee abstraction and federated attestations, and puts them on a
newer foundation.

**Aptos supplies what SENA would otherwise have to build:**

- **Keyless accounts.** Aptos built and audited the zero-knowledge circuit
  that turns a Google sign-in into a signature, and runs the prover. SENA
  verifies the same proofs with the same verifying key.
- **Fast, cheap settlement.** Disputes are decided by Move contracts on
  Aptos, which replay a single disputed step, keyless proof included.
- **Circle's USDC is native on Aptos.** SENA's bridge contract already takes
  custody of it on testnet; crediting deposits on SENA is next.

**An optimistic rollup keeps the trust small.** The sequencer gives instant
confirmations, but it cannot steal or invent balances. Correctness needs only
one honest watcher, and anyone can run one.

## What exists today

None of this is a mock-up. Each item is running code with tests.

- **A live testnet** settling on Aptos testnet, with a faucet and an
  [explorer](/explorer).
- **Keyless sign-in** verified against Aptos's audited circuit and mainnet
  ceremony key.
- **Fees in four stablecoins**, each paying its own fee, with exact balances
  on a live node.
- **Pay by email, phone or username**, through attestations from any OpenID
  Connect or OAuth provider, or an SMS code.
- **A forged transaction disputed and rejected by Aptos itself**, Groth16
  proof and all: 4,833 gas units from post to rejection.
- **Wallets**: a web wallet, a browser extension, and MetaMask through a Snap.
- **331 Rust tests and 78 Move tests**, including conformance tests that the
  L1 contracts and the node agree on every instruction.

The [status page](/docs/status) is the line-by-line account, including what
does not work yet.

## How it makes money

The protocol has a fee market like Ethereum's, priced in dollars:

- **The base fee** rises and falls with demand and goes to a fee vault. A
  governed **fee split** pays it out to named beneficiaries, as Celo's
  `FeeHandler` does. That split can fund the network's operation and its
  treasury.
- **Tips** go to the sequencer that includes the transaction.
- **Issuers** can charge for verification, as Celo's attestation providers
  do.

Fees are paid in stablecoins, so revenue is in dollars, not a volatile
token.

## Roadmap

1. **Testnet, complete**: disputes and withdrawals played on Aptos testnet,
   not only on a local network; deposits from Aptos credited on SENA.
2. **Private identifiers**: an ODIS-style rate-limited service, so linked
   phone numbers cannot be found by guessing.
3. **Independent audit** of the dispute contracts, the L1 compiler and keyless
   verification.
4. **Account recovery** and more sign-in providers (Apple, and others through
   Aptos Keyless).
5. **Mainnet**, with independent watchers and a council that is not one
   company.

## Risks, plainly

- **Not audited.** Until it is, no real money belongs on it.
- **One sequencer.** It cannot steal, but it can stop including
  transactions. Forced inclusion through Aptos is designed, not finished.
- **Dependence on Aptos's keyless services.** If Aptos's prover is down, new
  sign-ins wait.
- **Issuers are trusted for identities.** A dishonest issuer could misattest
  an email. Wallets choose which issuers they trust.

[Read the docs →](/docs/) · [Try the testnet →](/testnet)
