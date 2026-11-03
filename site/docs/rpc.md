# JSON-RPC

The node takes JSON over HTTP POST: `{"method": "...", "params": {...}}`.
Responses carry a `result` naming their kind, or `"result": "error"` with a
`message`. Amounts are decimal strings, because JSON numbers cannot carry a
`u128`.

```sh
curl -s https://rpc.<testnet-host> -d '{"method":"sena_getChainInfo"}'
```

## Methods

| Method | Params | Returns |
|---|---|---|
| `sena_getChainInfo` | — | chain name, `transaction_chain_id`, `network_salt`, height, finalized height, window, state root, mempool size |
| `sena_getAccount` | `address` | nonce and balances |
| `sena_getAccountTransactions` | `address`, `limit` (50) | sent and received transactions, newest first, with the fee each paid |
| `sena_getBlock` | `height` | header, transactions and their `hashes`, trace length, assertion |
| `sena_getConfirmation` | `hash` | `pending`, `soft_confirmed` or `finalized`, with the height |
| `sena_submitTransaction` | a signed transaction | its hash |
| `sena_gasPrice` | `asset` | rate, intrinsic gas, base fee, a suggested max fee |
| `sena_getFeeAssets` | — | each fee stablecoin: symbol, rate, intrinsic gas, enabled |
| `sena_lookupAttestations` | `identifier`, `trusted_issuers` (≤ 16) | each trusted issuer's attestation: `issuer`, `account`, `issued_on` |
| `sena_getCouncil` | — | members, thresholds, the next governance epoch |
| `sena_getJwk` | `iss`, `n` | whether keyless proofs over that provider key are accepted |
| `sena_getAssertion` | `id` | status and time left in its challenge window |
| `sena_getAccountProof` | `address`, `height` | a Merkle proof, for light clients |
| `sena_getWithdrawalProof` | `address` | a proof against the latest finalized root |
| `sena_getDaBlob` | `height` | the block's data, as published on Aptos |
| `sena_getTraceCommitments` | `height`, `steps` | machine-state commitments, for disputes |

## Building transactions

Don't hand-assemble transactions. Use SENA's own code:

- **Browsers and Node/Bun:** the `sena-wasm` package, SENA's Rust wallet logic
  compiled to WebAssembly: `buildTransfer`, `buildTransaction`,
  `signEd25519`, `signKeyless`, `hashIdentifier`, `submitRequest`. The
  [wallet repository](https://github.com/MusieTesfaye/wallet) uses it.
- **Rust:** the `sena-wallet` crate.

Every transaction signs the chain's `transaction_chain_id`. Read it from
`sena_getChainInfo`.

## Limits

The public testnet RPC allows 300 requests per minute per client IP and
1 MiB bodies.
