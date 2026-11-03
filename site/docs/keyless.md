# Keyless accounts

SENA accounts can be controlled by a Google sign-in instead of a private key,
using **Aptos Keyless**.

## How a sign-in becomes a signature

1. The wallet makes a fresh **ephemeral key** in the browser, valid for two
   days.
2. It signs you in with Google, with a **nonce** that commits to that key.
   Google's ID token now names the key.
3. Aptos's **pepper service** returns a secret pepper for your Google
   account. Your address is derived from Google's `sub`, the app's client
   id and the pepper, so nobody can link the address to your email.
4. Aptos's **prover** makes a Groth16 proof that a token signed by Google
   names this key and this address. It does this without revealing the
   token.
5. Each transaction is signed by the ephemeral key and carries the proof.
   SENA checks both.

## What SENA verifies

SENA uses Aptos's audited keyless circuit (`circuit-v1.0.1`) with the Aptos
mainnet ceremony's verifying key, point for point the key Aptos uses on
testnet and mainnet. The same verification runs in Move on Aptos if a
transaction is disputed.

## Google's key rotations

Google signs ID tokens with keys it rotates every few weeks. The chain
accepts only keys its council has approved. On the testnet, a process
(`sena-node jwk-sync`) watches Google's published keys and approves new ones
by a council-signed governance transaction. It retires keys Google has
withdrawn.

## Limits

- If Aptos's prover is down, new sign-ins wait; sessions already open keep
  working until their key expires.
- Aptos's training-wheels co-signature is not checked; SENA relies on the
  circuit and the ceremony.
- There is no recovery if you lose the Google account.
