#!/usr/bin/env bash
#
# Deposits and withdrawals through Aptos, on a localnet, with the real agents:
#
#   1. a user deposits APT into the bridge on Aptos, naming an L2 account;
#   2. the sequencer reads the deposit from Aptos and credits it on SENA;
#   3. the L2 account withdraws part of it, burning it on SENA and leaving a
#      withdrawal record;
#   4. the relayer posts both blocks to Aptos; an independent watcher re-reads
#      the deposit from Aptos, re-executes both blocks and challenges nothing;
#   5. the record is proven against the posted root, and Aptos refuses to pay
#      the claim because the assertion has not finalized.
#
# The challenge window cannot be shorter than 24 hours, so a paid claim does
# not fit in one run; `move/sena/tests/bridge_test.move` pays one against a
# finalized root, once, and refuses it twice.
#
# Prerequisites: `aptos node run-localnet` on 127.0.0.1:8080 (faucet :8081)
# and `cargo build -p sena-node`.
#
# Usage: scripts/localnet-bridge.sh [path/to/sena-node]

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
NODE="${1:-$REPO/target/debug/sena-node}"
# The first Python that runs (python3 can be a stub that only opens a store).
PY=$(for p in python3 python; do "$p" -c "" 2>/dev/null && { echo "$p"; break; }; done)
REST=http://127.0.0.1:8080/v1
PORT=18546
BOND=1000000
DEPOSIT=500000000    # 5 APT
WITHDRAW=100000000   # 1 APT
WORK=$(mktemp -d)
cd "$WORK"   # Aptos CLI profiles live in ./.aptos, kept out of the repo
echo "working in $WORK"

fail() { echo "FAIL: $*"; exit 1; }
json() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

profile() {
  aptos init --network local --profile "$1" --assume-yes </dev/null >/dev/null 2>&1
  aptos account fund-with-faucet --profile "$1" --amount 2000000000 >/dev/null
  aptos config show-profiles --profile "$1" | json "'0x'+d['Result']['$1']['account']"
}
PROPOSER=$(profile proposer)
CHALLENGER=$(profile challenger)
USER=$(profile user)
echo "proposer $PROPOSER, challenger $CHALLENGER, depositor $USER"

aptos move publish --package-dir "$REPO/move/sena" --named-addresses "sena=$PROPOSER" \
  --chunked-publish --profile proposer --max-gas 2000000 --assume-yes >publish.log 2>&1 \
  || { tail -5 publish.log; exit 1; }
echo "package published"

# An L2 account with nothing at genesis: everything it holds comes from Aptos.
read -r SECRET ALICE < <("$NODE" keygen | awk '/^secret/{s=$2} /^address/{a=$2} END{print s, a}')
# Genesis needs one allocation; a throwaway account gets one unit.
GENESIS_OUT=$("$NODE" genesis --data-dir data --fund "$("$NODE" keygen | awk '/^address/{print $2}'):1")
GENESIS_ROOT=$(awk '/^  state root/{print $3; exit}' <<<"$GENESIS_OUT")
CHAIN_ID=$(awk '/^  chain id/{print $3; exit}' <<<"$GENESIS_OUT")
echo "L2 account $ALICE, genesis root $GENESIS_ROOT"

run() {
  local who="$1" fn="$2"; shift 2
  aptos move run --function-id "$PROPOSER::$fn" --args "$@" --profile "$who" \
    --max-gas 200000 --assume-yes >>run.log 2>&1 || { tail -8 run.log; return 1; }
}
view() {
  local fn="$1"; shift
  aptos move view --function-id "$PROPOSER::$fn" --args "$@" --url "$REST" 2>/dev/null | json "json.dumps(d['Result'])"
}

run proposer assertions::initialize "hex:0x${GENESIS_ROOT#0x}" u64:86400 "u128:$BOND" address:0xa \
  "address:$PROPOSER" u64:3600
run proposer disputes::initialize "address:$PROPOSER" u8:0 "u64:$CHAIN_ID"
# The bridge custodies APT (metadata 0xa) as L2 asset 1, and the chain's owner
# registers it -- an unregistered bridge cannot credit anything.
run proposer bridge::initialize "address:$PROPOSER" address:0xa u32:1
run proposer deposits::register_bridge "address:$PROPOSER" u32:1
echo "contracts initialised; bridge registered for asset 1"

"$NODE" run --data-dir data --listen "127.0.0.1:$PORT" --block-interval 1 --run-for 240 \
  --deposits-from "$REST" --deposits-contract "$PROPOSER" >node.log 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null || true' EXIT
for _ in $(seq 30); do
  curl -s -m 1 "http://127.0.0.1:$PORT" >/dev/null 2>&1 && break
  sleep 1
done
RPC="http://127.0.0.1:$PORT"
balance() {
  "$NODE" query --rpc "$RPC" account "$ALICE" | json \
    "next((int(b['amount']) for b in d.get('balances', []) if b['asset'] == 1), 0)"
}

# --- 1-2. Deposit on Aptos, credited on SENA ------------------------------------
run user bridge::deposit_to "address:$PROPOSER" "hex:$ALICE" "u64:$DEPOSIT"
echo "deposited $DEPOSIT on Aptos"
for _ in $(seq 40); do
  [ "$(balance)" = "$DEPOSIT" ] && break
  sleep 1
done
[ "$(balance)" = "$DEPOSIT" ] || { tail -20 node.log; fail "deposit not credited on L2 (balance $(balance))"; }
echo "OK: credited $DEPOSIT to $ALICE on SENA"
grep -q "read 1 new L1 deposit" node.log || fail "the node did not log reading the deposit"

# --- 3. Withdraw on SENA --------------------------------------------------------
out=$("$NODE" withdraw --rpc "$RPC" --secret "$SECRET" --to "$USER" --amount "$WITHDRAW" --nonce 0 --asset 1)
hash=$("$PY" -c "import json,sys; t=sys.stdin.read(); print(json.JSONDecoder().raw_decode(t[t.index('{'):])[0].get('hash',''))" <<<"$out")
[ -n "$hash" ] || fail "withdrawal not accepted: $out"
for _ in $(seq 30); do
  status=$("$NODE" query --rpc "$RPC" confirmation "$hash" | json "d['status']")
  [ "$status" != pending ] && break
  sleep 1
done
left=$(balance)
[ "$left" -le $((DEPOSIT - WITHDRAW)) ] || fail "withdrawal did not burn: balance $left"
echo "OK: withdrew $WITHDRAW on SENA; $left left after the fee"

# --- 4. Relayer posts; watcher verifies from Aptos alone --------------------------
height=$("$NODE" query --rpc "$RPC" info | json "d['height']")
echo "L2 height $height"
aptos_args=(--aptos-url "$REST" --contract "$PROPOSER" --poll-interval 3)
timeout 60 "$NODE" relay --rpc "$RPC" "${aptos_args[@]}" \
  --profile proposer --account "$PROPOSER" --bond "$BOND" --state relayer.json >relay.log 2>&1 || true
timeout 60 "$NODE" watch --data-dir data "${aptos_args[@]}" \
  --profile challenger --account "$CHALLENGER" --bond "$BOND" --state watcher.json >watch.log 2>&1 || true
echo "--- relayer"; tail -4 relay.log
echo "--- watcher"; tail -4 watch.log
grep -q "posted: \[1" relay.log || fail "the relayer did not post the deposit block"
grep -qE "verified: [2-9]" watch.log || fail "the watcher did not verify both blocks"
if grep -q 'challenged: \[(' watch.log; then fail "the watcher challenged an honest assertion"; fi
echo "OK: both blocks posted, and verified by a watcher that read the deposit from Aptos"

# --- 5. The claim: proven, and refused until final --------------------------------
count=$(view assertions::assertion_count "address:$PROPOSER" | json 'd[0]')
latest=$(view assertions::assertion_at "address:$PROPOSER" "u64:$((count - 1))" | json 'd[0]')
root=$(view assertions::record "address:$PROPOSER" "hex:$latest" | json 'd[3]')
status=$(view assertions::record "address:$PROPOSER" "hex:$latest" | json 'd[10]')
"$NODE" query --rpc "$RPC" withdrawal "$ALICE" 0 --state-root "$root" >proof.json
"$PY" - "$PROPOSER" "$latest" "$ALICE" <<'EOF' >claim.json
import json, sys
contract, assertion, sender = sys.argv[1:]
p = json.load(open("proof.json"))
assert p["result"] == "withdrawalProof", p
hx = lambda h: "0x" + h.removeprefix("0x")
print(json.dumps({
    "function_id": f"{contract}::bridge::claim",
    "type_args": [],
    "args": [
        {"type": "address", "value": contract},
        {"type": "hex", "value": assertion},
        {"type": "hex", "value": hx(sender)},
        {"type": "u64", "value": "0"},
        {"type": "hex", "value": hx(p["record"])},
        {"type": "hex", "value": [hx(s) for s in p["siblings"]]},
        {"type": "hex", "value": hx(p["terminal_key"])},
        {"type": "hex", "value": hx(p["terminal_value_hash"])},
    ],
}))
EOF
amount=$(json "d['amount']" <proof.json)
[ "$amount" = "$WITHDRAW" ] || fail "the proven record is for $amount"
echo "OK: the withdrawal record ($amount to $USER) is proven under the posted root, status $status"
if aptos move run --json-file claim.json --profile user --max-gas 200000 --assume-yes >claim.log 2>&1 \
   && grep -q '"success": true' claim.log; then
  fail "Aptos paid a claim against an assertion that has not finalized"
fi
# `finalized_root` is the first thing a claim checks: the arguments decoded and
# the refusal is finality, not a malformed call.
grep -q "assertions: E_WRONG_STATUS" claim.log || { cat claim.log; fail "the claim failed for an unexpected reason"; }
spent=$(view bridge::is_spent "address:$PROPOSER" "hex:0x$(json "d['terminal_key']" <proof.json)" | json 'd[0]')
custody=$(view bridge::custody_balance "address:$PROPOSER" | json 'd[0]')
[ "$spent" = "False" ] && [ "$custody" = "$DEPOSIT" ] || fail "custody moved: spent $spent, custody $custody"
echo "OK: Aptos refused the early claim; custody still holds $custody"
echo "PASS: deposit credited, withdrawal recorded and verified, early claim refused"
