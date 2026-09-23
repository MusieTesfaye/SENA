#!/usr/bin/env bash
#
# Exercises the bridge against real Circle USDC on Aptos testnet.
#
#   scripts/bridge-test.sh setup      publish and initialise
#   scripts/bridge-test.sh deposit    deposit USDC into custody
#   scripts/bridge-test.sh status     balances and custody
#   scripts/bridge-test.sh withdraw   withdraw against a finalized assertion
#
# Testnet has no programmatic faucet, so funding is manual and one-off:
#
#   APT  https://aptos.dev/network/faucet?address=<your address>
#   USDC https://faucet.circle.com  (choose Aptos testnet)
#
# A withdrawal needs an assertion that has *finalized*, and the challenge window
# floor is 24 hours. There is no way to demonstrate a same-day withdrawal, and
# that is the design working rather than a limitation of the script.

set -uo pipefail

CMD="${1:-status}"
PROFILE="${SENA_PROFILE:-sena-testnet}"
NETWORK=testnet
API="https://fullnode.${NETWORK}.aptoslabs.com/v1"

# Circle USDC on Aptos testnet: 6 decimals, a dispatchable fungible asset.
USDC_METADATA=0x69091fbab5f7d635ee7ac5098cf0c1efbe31d68fec0f2cd565e8d168daf52832
L2_ASSET_ID=1
DEPOSIT_AMOUNT="${DEPOSIT_AMOUNT:-1000000}"   # 1.000000 USDC
GENESIS_ROOT=0x1111111111111111111111111111111111111111111111111111111111111111
WINDOW=86400        # the floor; the shortest wait a withdrawal can require
BOND=1000000

GAS=(--max-gas 100000 --gas-unit-price 100 --assume-yes --profile "$PROFILE")
PUBLISH_GAS=(--max-gas 500000 --gas-unit-price 100 --assume-yes --profile "$PROFILE")

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

ADDR=0x$(aptos config show-profiles --profile "$PROFILE" 2>/dev/null | python3 -c '
import json,sys
try: print(json.load(sys.stdin)["Result"].get(sys.argv[1],{}).get("account",""))
except Exception: print("")' "$PROFILE")

if [ "$ADDR" = "0x" ]; then
  echo "No profile '$PROFILE'. Create one:"
  echo "  aptos init --network $NETWORK --profile $PROFILE --assume-yes </dev/null"
  exit 1
fi

# Output is captured before matching, never piped. `aptos move run` exits
# non-zero on a deliberate abort, and under pipefail that would report a
# correctly-refused transaction as a failure.
run() { aptos move run --function-id "$1" --args "${@:2}" "${GAS[@]}" 2>&1; }

view() {
  aptos move view --function-id "$1" --args "${@:2}" --profile "$PROFILE" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["Result"][0])
except Exception: print("")'
}

apt_balance() {
  timeout 25 curl -sS "$API/accounts/$ADDR/resource/0x1::coin::CoinStore%3C0x1::aptos_coin::AptosCoin%3E" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["data"]["coin"]["value"])
except Exception: print(0)'
}

usdc_balance() {
  aptos move view --function-id 0x1::primary_fungible_store::balance \
    --type-args 0x1::fungible_asset::Metadata \
    --args "address:$ADDR" "address:$USDC_METADATA" --profile "$PROFILE" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["Result"][0])
except Exception: print(0)'
}

step "Account"
echo "  $ADDR  ($NETWORK)"
apt=$(apt_balance); usdc=$(usdc_balance)
echo "  APT   $apt octas"
echo "  USDC  $usdc  (6 decimals — $((usdc / 1000000)).$(printf '%06d' $((usdc % 1000000))) USDC)"

if [ "$apt" -eq 0 ] 2>/dev/null; then
  bad "no APT for gas"
  echo "     fund at https://aptos.dev/network/faucet?address=$ADDR"
  exit 1
fi

case "$CMD" in
  setup)
    step "Publish"
    out=$(aptos move publish --package-dir move/sena --named-addresses "sena=$ADDR" "${PUBLISH_GAS[@]}" 2>&1)
    echo "$out" | grep -q '"success": true' && ok "published" || { bad "publish failed"; echo "$out" | grep Error | head -2; exit 1; }

    step "Initialise"
    echo "$(run "${ADDR}::assertions::initialize" "hex:$GENESIS_ROOT" "u64:$WINDOW" "u128:$BOND")" \
      | grep -q '"success": true' && ok "assertion chain (window ${WINDOW}s)" || bad "assertions::initialize"
    echo "$(run "${ADDR}::disputes::initialize" "address:$ADDR")" \
      | grep -q '"success": true' && ok "dispute registry" || bad "disputes::initialize"
    echo "$(run "${ADDR}::bridge::initialize" "address:$ADDR" "address:$USDC_METADATA" "u32:$L2_ASSET_ID")" \
      | grep -q '"success": true' && ok "bridge, custodying USDC" || bad "bridge::initialize"
    ;;

  deposit)
    if [ "$usdc" -lt "$DEPOSIT_AMOUNT" ] 2>/dev/null; then
      bad "not enough USDC (need $DEPOSIT_AMOUNT, have $usdc)"
      echo "     get testnet USDC at https://faucet.circle.com  (select Aptos testnet)"
      exit 1
    fi
    step "Deposit $DEPOSIT_AMOUNT USDC into custody"
    out=$(run "${ADDR}::bridge::deposit" "address:$ADDR" "u64:$DEPOSIT_AMOUNT")
    if echo "$out" | grep -q '"success": true'; then
      ok "deposited"
      echo "$out" | grep -oE '"transaction_hash": "[^"]*"' | head -1 | sed 's/^/     /'
    else
      bad "deposit failed"; echo "$out" | grep Error | head -2
    fi
    ;;

  withdraw)
    step "Withdraw"
    echo "  A withdrawal needs an assertion that has finalized, and the window"
    echo "  floor is ${WINDOW}s. It also needs a Merkle proof of your L2 balance,"
    echo "  which the sequencer produces — see docs/TESTING.md."
    bad "not automated yet: needs a sequencer-produced inclusion proof"
    ;;

  status)
    step "Bridge"
    custody=$(view "${ADDR}::bridge::custody_balance" "address:$ADDR")
    deposits=$(view "${ADDR}::bridge::deposit_count" "address:$ADDR")
    if [ -n "$custody" ]; then
      ok "custody holds $custody USDC units across $deposits deposit(s)"
    else
      bad "bridge not initialised — run: $0 setup"
    fi
    ;;

  *) echo "usage: $0 [setup|deposit|status|withdraw]"; exit 1 ;;
esac
