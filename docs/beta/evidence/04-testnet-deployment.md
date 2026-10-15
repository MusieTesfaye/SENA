# Evidence — Aptos testnet deployment, assertion lifecycle and bridge deposit

**Date:** 2026-10-15
**Network:** Aptos testnet (chain id 2)
**Toolchain:** Aptos CLI `7.9.0`; framework pinned to `46d871fa1feb61ffafb73353a0755e8cc3aaed9d`.
The package's Move tests also pass under CLI `9.0.0` and `9.6.0`.
**Source revision:** the commit that added this file; the package is the one
from `6947c5f` onward (published batch data, real bonds, keyless adjudication).

Every transaction below can be inspected at
`https://explorer.aptoslabs.com/txn/<hash>?network=testnet`.

## 1. Assertion lifecycle — `scripts/chain-lifecycle.sh testnet`

Package account (proposer): `0x7377e573a92a10ac23fcaa3d238756085118eea62a3cf450546c8edfa70dab5b`
Challenger: `0xb4b8f02ce4d7f83103da564402d28aae8ff64e5dd477256830768b5d4c326573`

Result: **11 passed, 0 failed.**

| Step | Outcome | Gas | Transaction |
|---|---|---|---|
| Publish (5 staged chunks + publish) | success | 2,242,712 total | final: `0x231aec8909b49991e3f52117404d10733da68ab72525ad6ae004ae39011b64d5` |
| `assertions::initialize` (APT bonds, 7-day window) | success | 16,312 | `0xd8c61638ddc8c848c9582a05eaef293e992da9ec739af82e55b1ae5175e230a3` |
| `disputes::initialize` (keyless setup 1, mainnet ceremony) | success | 9,105 | `0xcdf83d8d94a885630f698c779e00039590ae79b8bc8fbc65e3b90bbdf8b81079` |
| `assertions::post` with batch data, bonded | success | 5,551 | `0xc3297ab36c70ad15aa72883194702412586a28475a5bfbc71120cb088aca562a` |
| underbonded `post` | **refused** `E_BOND_TOO_SMALL` | 53 | `0x79beb37fd1a25a1b103e90941ffa28ff9baa12a1c8ce2099424441523d14b901` |
| `finalize` inside the window | **refused** `E_WINDOW_OPEN` | 71 | `0x4a05c2c3a2e18e74526d91ca6aa894156a77e6b409ccd7da9f02dc5f7432392d` |
| proposer challenges itself | **refused** `E_SELF_CHALLENGE` | 52 | `0xe3e6deb26d07d333b135328aa845a6550298a69f1c32588fe3189a54809694ba` |
| `open_challenge` by a second account, bonded | success | 9,482 | `0x109d8aaf3e395459b5da5028b532c9f0cd42b87840f0404780d799cd9423e47e` |
| `finalize` while challenged | **refused** `E_WRONG_STATUS` | 52 | `0x5f0a3339a7ada195680eb777c5f48f1cdd9e3a1335f2a96e9f47aa69fbd7c978` |

The assertion id the contract accepted
(`0x05fa4044b12a3d2bde020a6a9d6fd2f591a238614a3568d91fe81cf4ad5fb95f`) was
computed independently by the script from the canonical encoding, including the
batch root over the published transaction, so the Rust/Python and Move hashing
agree on a live network.

## 2. Bridge — `scripts/bridge-test.sh setup` and `deposit`

Account: `0xa6271e9a726282f4afb38b7bfd117ec2643f1e26b2fd02f13791d0a243258a74`
Asset: Circle USDC on Aptos testnet,
`0x69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832`
(a dispatchable fungible asset).

| Step | Outcome | Gas | Transaction |
|---|---|---|---|
| Publish | success | 2,247,633 total | final: `0xf8b63be70236e39a4c1d39f80800c37a1e3a62ca004e3c7a4a0bca8c904daba8` |
| `assertions::initialize` | success | 16,312 | `0x7835abb655f482f09f14e8256260fc03bb8f2910e59448a682636ec36405316e` |
| `disputes::initialize` | success | 9,105 | `0x6038b429573dcf329d4cefa8bf461fe27a38bc3457e695876ad42e2554dc4faa` |
| `bridge::initialize`, custodying USDC | success | 10,764 | `0x712c3633760fb1703e66ebab2918c9fe3fb8ae7eb6472474ed50bf1164da555c` |
| `bridge::deposit` of 1.000000 USDC | success | 158 | `0xe59d52e49b03d2b7e9b1913da997bd69f127b36f00cb335816bfafb67fdb51fa` |

After the deposit the account held 19 USDC (from 20) and
`bridge::custody_balance` reported 1,000,000 units across 1 deposit.

## What this does not show

- **No withdrawal.** A withdrawal needs an assertion that has finalized, and the
  window floor is 24 hours; it also needs a sequencer-produced balance proof.
  Not attempted.
- **No dispute played on testnet.** The full keyless dispute has run only on a
  localnet (`scripts/localnet-dispute.sh`).
- **The relayer and watcher have not run against testnet.**

## Deployment notes

Two things differed from a localnet, both now handled by the scripts:

- **Chunked publishing needs `--large-packages-module-address 0x7`.** CLI 7.9.0
  defaults to the module's old testnet address, where it no longer exists; the
  first staging transaction failed with `LINKER_ERROR`
  (`0xd81679ffa4c4dd51487b8e2ddb88a6665bd430313a2f701ae055c2fdd620edf7`).
- **Publishing costs about 2.25 APT on testnet**, far more than on a localnet,
  mostly in storage fees, and the final publish transaction alone uses about
  1.12 million gas units. A first attempt with a 500,000-unit ceiling ran out of
  gas (`0x6ea09d7919eb9e7ad2ba2ba7a56f1c1fde1d0dc25b6fafd3983d3ffc8167dbab`);
  the staging area was cleared
  (`0xc673844626c70c499b7be972863dc7d259814ecc610e8b8ca8aaa8f3db001eb0`) and the
  publish repeated with a 2,000,000-unit ceiling. A publishing account should
  hold at least 4 APT.
