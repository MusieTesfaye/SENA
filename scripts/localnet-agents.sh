#!/usr/bin/env bash
#
# Runs the real `sena-node relay` and `sena-node watch` against an Aptos
# localnet: a sequencer produces a block, the relayer posts it to L1 with its
# batch data, and an independent watcher -- reading only L1 and its own
# genesis file -- re-executes it and verifies it without challenging.
#
# Where scripts/localnet-dispute.py proves L1 rejects fraud, this proves the
# agents an operator runs actually talk to Aptos: the CLI invocations, the
# view decoding, and the batch data read back from L1 events.
#
# Prerequisites: `aptos node run-localnet` on 127.0.0.1:8080 (faucet :8081)
# and `cargo build -p sena-node`.
#
# Usage: scripts/localnet-agents.sh [path/to/sena-node]

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
NODE="${1:-$REPO/target/debug/sena-node}"
REST=http://127.0.0.1:8080/v1
PORT=18545
BOND=1000000
WORK=$(mktemp -d)
cd "$WORK"   # Aptos CLI profiles live in ./.aptos, kept out of the repo
echo "working in $WORK"

profile() {
  aptos init --network local --profile "$1" --assume-yes </dev/null >/dev/null 2>&1
  aptos account fund-with-faucet --profile "$1" --amount 2000000000 >/dev/null
  aptos config show-profiles --profile "$1" | python3 -c \
    'import json,sys; print("0x"+json.load(sys.stdin)["Result"][sys.argv[1]]["account"])' "$1"
}
PROPOSER=$(profile proposer)
CHALLENGER=$(profile challenger)
echo "proposer $PROPOSER, challenger $CHALLENGER"

aptos move publish --package-dir "$REPO/move/sena" --named-addresses "sena=$PROPOSER" \
  --chunked-publish --profile proposer --max-gas 2000000 --assume-yes >publish.log 2>&1 \
  || { tail -5 publish.log; exit 1; }
echo "package published"

# An L2 account to transact with, funded at genesis.
read -r SECRET ALICE < <("$NODE" keygen | awk '/^secret/{s=$2} /^address/{a=$2} END{print s, a}')
BOB=$("$NODE" keygen | awk '/^address/{print $2}')
GENESIS_ROOT=$("$NODE" genesis --data-dir data --fund "$ALICE:1000000000" | awk '/^  state root/{print $3; exit}')
echo "genesis root $GENESIS_ROOT"

run() {
  local fn="$1"; shift
  aptos move run --function-id "$PROPOSER::$fn" --args "$@" --profile proposer \
    --max-gas 200000 --assume-yes >>init.log 2>&1 || { tail -5 init.log; exit 1; }
}
run assertions::initialize "hex:0x${GENESIS_ROOT#0x}" u64:86400 "u128:$BOND" address:0xa \
  "address:$PROPOSER" u64:3600
run disputes::initialize "address:$PROPOSER" u8:0
echo "contracts initialised"

"$NODE" run --data-dir data --listen "127.0.0.1:$PORT" --block-interval 1 --run-for 120 >node.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true' EXIT
for _ in $(seq 30); do
  curl -s -m 1 "http://127.0.0.1:$PORT" >/dev/null 2>&1 && break
  sleep 1
done
for nonce in 0 1; do
  "$NODE" send --rpc "http://127.0.0.1:$PORT" --secret "$SECRET" --to "$BOB" \
    --amount $((10 + nonce)) --nonce "$nonce" >/dev/null
done
for _ in $(seq 30); do
  height=$("$NODE" query --rpc "http://127.0.0.1:$PORT" info | python3 -c \
    'import json,sys; print(json.load(sys.stdin).get("height", 0))')
  [ "$height" -ge 1 ] && break
  sleep 1
done
echo "L2 height $height"

aptos_args=(--aptos-url "$REST" --contract "$PROPOSER" --poll-interval 3)
timeout 45 "$NODE" relay --rpc "http://127.0.0.1:$PORT" "${aptos_args[@]}" \
  --profile proposer --account "$PROPOSER" --bond "$BOND" --state relayer.json >relay.log 2>&1 || true
timeout 45 "$NODE" watch --data-dir data "${aptos_args[@]}" \
  --profile challenger --account "$CHALLENGER" --bond "$BOND" --state watcher.json >watch.log 2>&1 || true

echo "--- relayer"; cat relay.log
echo "--- watcher"; cat watch.log
grep -q "posted: \[1" relay.log || { echo "FAIL: the relayer did not post block 1"; exit 1; }
grep -q "verified: [1-9]" watch.log || { echo "FAIL: the watcher verified nothing"; exit 1; }
if grep -q 'challenged: \[(' watch.log; then
  echo "FAIL: the watcher challenged an honest assertion"; exit 1
fi
echo "OK: posted by the relayer, verified from L1 data by the watcher, no challenge"
