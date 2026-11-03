# Is my money safe on SENA?

Plain answers for people using a SENA wallet. The technical account is in
[`STATUS.md`](../STATUS.md).

**Short version: not yet.** SENA is beta software, and it has not been
audited. It runs on Aptos testnet and on devnets. Use test coins only.

## Your account

**You sign in with Google (or another provider). There is no seed phrase.**
Your address comes from your Google account and a secret number called the
pepper. To spend, your browser makes a short-lived key, Google signs you in,
and a zero-knowledge proof shows the chain you did. The chain never sees your
Google token or your email.

- **Google cannot spend your coins.** It never holds your key. Neither can the
  wallet's developers.
- **Someone who gets into your Google account can.** Protect it with two-step
  verification.
- **Someone with access to your browser can, for two days.** The short-lived
  key stays in your browser until it expires. Sign out on shared computers.
- **If you lose your Google account, you lose the coins.** There is no
  recovery yet.

## Paying an email or a phone number

When you send to `bob@gmail.com`, the wallet asks the chain which account an
**issuer** has confirmed that email belongs to. An issuer is a service that
checked Bob owns it, for example by having him sign in with Google or enter an
SMS code. Only issuers your wallet trusts count. If two of them disagree, the
wallet refuses to send.

- **Only Bob can link his email to his account.** An issuer cannot link it to
  someone else without that account agreeing, and nobody else can submit it.
- **You are trusting the issuer.** A dishonest or hacked issuer could confirm
  Bob's email for the wrong account. The wallet shows the address before you
  send. The first time you pay someone, check it with them.
- **Your email and number are not on the chain in plain text.** They are
  stored scrambled (hashed). But someone who already has your number can check
  whether it is linked, and phone numbers can be guessed one by one. If that
  matters to you, don't link your phone yet.
- **You can unlink at any time.** Unlinking removes the link from the chain.

## Fees

You pay fees in the coin you send: USDT fees in USDT, EURC fees in EURC.
Before you send, the wallet shows the most the fee can be. You never pay more,
and the unused part comes back.

## The chain

One company, the **sequencer**, puts transactions in order. It cannot take
your coins:

- The sequencer regularly publishes the state of every balance to
  Aptos, with all the transactions behind it.
- Anyone can re-run those transactions. If the sequencer publishes something
  false, anyone can challenge it on Aptos, and Aptos itself decides who is
  right.
- If the sequencer disappears, the plan is for you to withdraw directly on
  Aptos. Withdrawals have not yet been tested on a live network.

All of this depends on **at least one honest person watching**. SENA ships
the watcher, but someone has to run it.

## What is not finished

- No security audit.
- Coins deposited from Aptos do not appear on SENA yet. Coins come from
  genesis and faucets only.
- No account recovery.
- No protection against guessing linked phone numbers. Celo uses a
  rate-limited service, ODIS, for this.
- The devnet issuer and faucet keep their keys in plain files.

## Found a problem?

Open an issue on [GitHub](https://github.com/MusieTesfaye/SENA/issues). For a
problem that could put funds at risk, ask the maintainers for a private
contact first, rather than posting details publicly.
