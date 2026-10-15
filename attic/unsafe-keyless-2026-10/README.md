# Quarantined: unsafe keyless / ZK code (do not use)

This directory holds code moved out of the build in October 2026. It is kept
only for history; it is not part of the Cargo workspace or the Move package,
and nothing links against it. Delete it whenever you like.

Why it was removed:

- `sena-stf/src/groth16.rs` — the "canonical" verification key was built from
  known small scalars with beta = gamma = delta = G2, and
  `create_canonical_proof` produced a valid proof for any sender without a
  witness. Every keyless account could be drained.
- `sena-prover/` — the "ceremony" hard-coded its toxic waste and had no
  circuit; the "prover" assembled proofs from public data; the JWK manager
  accepted any `kid` starting with `sena_test` and fell through to success on
  unknown keys; pepper/ODIS hashed to the curve as `h·G` with known `h`, so
  peppers were computable from public keys; `/pepper/get` needed no JWT and
  silently fell back to a master secret derived from a public string.
- `prover-params/` — output of that fake ceremony.
- `move/groth16.move` — never called; its only test used all-zero points.

Keyless accounts are being rebuilt on the audited Aptos Keyless circom circuit
and its ceremony verification key. See STATUS.md.
