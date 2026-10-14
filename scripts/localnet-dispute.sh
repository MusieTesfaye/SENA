#!/usr/bin/env bash
#
# Sets up fresh accounts on an Aptos localnet, publishes the package, and runs
# scripts/localnet-dispute.py: a forged keyless credit, disputed through real
# transactions until L1 verifies the Groth16 proof and rejects the assertion.
#
# Prerequisites: `aptos node run-localnet` on 127.0.0.1:8080 (faucet :8081).
#
# Usage: scripts/localnet-dispute.sh

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
cd "$WORK"   # Aptos CLI profiles live in ./.aptos, kept out of the repo
echo "working in $WORK"

for p in admin proposer challenger; do
  aptos init --network local --profile "$p" --assume-yes </dev/null >/dev/null 2>&1
  aptos account fund-with-faucet --profile "$p" --amount 50000000000 >/dev/null
done
ADMIN=0x$(aptos config show-profiles --profile admin | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["Result"]["admin"]["account"])')

aptos move publish --package-dir "$REPO/move/sena" --named-addresses "sena=$ADMIN" \
  --chunked-publish --profile admin --max-gas 2000000 --assume-yes >publish.log 2>&1 \
  || { tail -5 publish.log; exit 1; }
echo "package published at $ADMIN"

# The batch time must be fresh by L1's clock.
now=$(curl -s http://127.0.0.1:8080/v1 | python3 -c \
  'import json,sys; print(int(json.load(sys.stdin)["ledger_timestamp"]) // 1000000)')
(cd "$REPO" && cargo run -q -p sena-fraudproof --example dispute_plan -- "$now") >plan.json
python3 "$REPO/scripts/localnet-dispute.py" plan.json
