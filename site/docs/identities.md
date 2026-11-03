# Pay an email or phone

On SENA you can send to `bob@gmail.com`, `+1 555 010 1234` or `github:bob`
instead of a 66-character address. The design is Celo's **SocialConnect**.

## How it works

Nothing on chain decides who owns an email. **Issuers** vouch for it:

1. **An issuer checks you own the identifier.** You sign in with the provider
   (Google, Apple, GitHub, X, Discord, Twitch…) or enter a code sent by SMS.
2. **It signs an attestation**: this identifier belongs to this account, on
   this chain, as of now.
3. **Your account puts it on chain.** That is your consent to be found by it.
   Nobody else can submit it for you.
4. **A sender looks it up.** Their wallet hashes the identifier and asks the
   chain what the issuers *it trusts* have attested. If two trusted issuers
   disagree, the wallet refuses to pay.

```text
 you ── sign in ──▶ issuer ── signed attestation ──▶ you ── register ──▶ SENA
                                                                          │
 sender: hash("mailto", "bob@gmail.com", salt) ── lookup(trusted issuers) ┘
```

## Link yours

In the wallet, open **Find me by** and pick a provider. When you come back,
the wallet submits the attestation; once it is in a block, people can pay you
by it. **Unlink** revokes it on chain.

## What goes on chain

Only a hash of the identifier, its type and the network salt, never the
email or the number itself. Each attestation records the issuer, the
account, and when it was issued; a newer attestation replaces an older one.

## Identifier types

Types are Celo's prefixes, and the list is open: an issuer can verify a new
platform without any change to the chain.

| Prefix | Identifier | Example |
|---|---|---|
| `mailto` | email address | `bob@gmail.com` |
| `tel` | phone number, international format | `+15550101234` |
| `twit` | X (Twitter) | `twit:bob` |
| `github`, `discord`, `telegram`, `twitch`, … | that platform's username | `github:bob` |

## Limits, today

- **You trust the issuers you pick.** A dishonest issuer could attest
  someone's email to the wrong account. Check the address the first time you
  pay someone.
- **Hashes can be guessed.** The salt is public, so someone who already has
  your number can check whether it is linked, and phone numbers can be tried
  one by one. Celo solves this with ODIS, a rate-limited pepper service; it
  is on SENA's roadmap.
