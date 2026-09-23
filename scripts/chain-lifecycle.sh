#!/usr/bin/env bash
#
# Deploys SENA to an Aptos network and exercises the assertion lifecycle,
# checking that the chain refuses what it must refuse.
#
# This is a test, not a demo: every step asserts an expected outcome, and the
# two that matter are the *failures*. If Aptos ever lets a challenged assertion
# finalize, this script fails loudly.
#
# Usage:
#   scripts/chain-lifecycle.sh [devnet|testnet|local]
#
# Requires the Aptos CLI 7.9.0 (later releases abort on CPUs without AVX2; see
# move/README.md).

set -uo pipefail

NETWORK="${1:-devnet}"

# A fresh account per run, unless one is named.
#
# Reusing an account makes every step fail for the wrong reason: `initialize`
# aborts because the resource already exists, `post` aborts because the
# assertion id is already in the table, and `finalize` reports the previous
# run's Challenged status instead of the window check. Those are the contract
# behaving correctly and the script asking the wrong question.
PROFILE="${SENA_PROFILE:-sena-${NETWORK}-$(date +%Y%m%d-%H%M%S)}"
# Gas is specified rather than estimated: the devnet simulate endpoint times out
# from some connections, and passing these skips that call. Publishing needs
# substantially more than an entry-function call -- the first successful publish
# used 184,594 -- so the two budgets are separate.
GAS_ARGS=(--max-gas 100000 --gas-unit-price 100 --assume-yes)
PUBLISH_GAS_ARGS=(--max-gas 500000 --gas-unit-price 100 --assume-yes)

# Distinct roots so a mistake shows up as a mismatch rather than a coincidence.
GENESIS_ROOT="0x1111111111111111111111111111111111111111111111111111111111111111"
PRE_ROOT="$GENESIS_ROOT"
POST_ROOT="0x2222222222222222222222222222222222222222222222222222222222222222"
BATCH="0x3333333333333333333333333333333333333333333333333333333333333333"
WINDOW=604800   # 7 days
BOND=1000000
TRACE_LEN=10

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }
need aptos
need python3

step "0. Toolchain"
cli_version=$(aptos --version 2>&1 | head -1)
echo "  $cli_version"
case "$cli_version" in
  *" 7.9."*|*" 7.1"[0-3]*|*" 7."[0-8]*|*" "[1-6]".") ;;
  *) echo "  note: versions from 7.14.2 abort on CPUs without AVX2" ;;
esac

step "1. Account on $NETWORK"

# `show-profiles --profile X` exits 0 with an empty Result for a profile that
# does not exist, so presence has to be read from the payload, not the status.
profile_account() {
  aptos config show-profiles --profile "$PROFILE" 2>/dev/null | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["Result"].get(sys.argv[1], {}).get("account", ""))
except Exception:
    print("")
' "$PROFILE"
}

if [ -z "$(profile_account)" ]; then
  echo "  creating and funding profile $PROFILE"
  # stdin comes from /dev/null deliberately. `aptos init` prompts for a private
  # key even under --assume-yes and treats EOF as "generate one". Without this
  # it blocks forever with no terminal attached -- from a script, from CI, from
  # anything backgrounded. It hung for twenty minutes before this was added.
  aptos init --network "$NETWORK" --profile "$PROFILE" --assume-yes </dev/null 2>&1 | tail -3
fi

account=$(profile_account)
if [ -z "$account" ]; then
  echo "  could not create or read profile $PROFILE"
  exit 1
fi
ADDR="0x$account"
echo "  $ADDR"

step "2. Publish the package"
publish_out=$(aptos move publish --package-dir move/sena --named-addresses "sena=$ADDR" \
  --profile "$PROFILE" "${PUBLISH_GAS_ARGS[@]}" 2>&1)
if echo "$publish_out" | grep -q '"success": true'; then
  ok "package published"
else
  bad "publish failed"
  echo "$publish_out" | grep -E '"Error"|Out of gas' | head -3
  echo "  cannot continue"
  exit 1
fi

step "3. Initialise"

# Output is captured before being matched, never piped. `aptos move run` exits
# non-zero when a transaction aborts, and under `pipefail` that marks the whole
# pipeline failed even when grep found what it was looking for -- which would
# report every correctly-refused transaction as a safety failure.
run() {
  aptos move run --function-id "$1" --args "${@:2}" \
    --profile "$PROFILE" "${GAS_ARGS[@]}" 2>&1
}

# Asserts a transaction succeeded.
expect_ok() {
  local label="$1"; shift
  local out; out=$(run "$@")
  if printf '%s' "$out" | grep -q '"success": true'; then
    ok "$label"
  else
    bad "$label"
    printf '%s' "$out" | grep -E '"Error"|Move abort' | head -2 | sed 's/^/        /'
  fi
}

# Asserts a transaction was refused, with a specific abort.
expect_abort() {
  local label="$1" code="$2"; shift 2
  local out; out=$(run "$@")
  if printf '%s' "$out" | grep -q "$code"; then
    ok "$label"
  else
    bad "$label"
    printf '%s' "$out" | grep -E '"Error"|success' | head -2 | sed 's/^/        /'
  fi
}

expect_ok "assertion chain initialised" \
  "${ADDR}::assertions::initialize" "hex:$GENESIS_ROOT" "u64:$WINDOW" "u128:$BOND"
expect_ok "dispute registry initialised" \
  "${ADDR}::disputes::initialize" "address:$ADDR"

step "4. Derive assertion ids independently"
# Computed from the canonical encoding rather than read back from the chain, so
# a mismatch between the Move and Rust hashing shows up as a rejected argument.
read -r GENESIS_ID CHILD_ID < <(python3 - "$GENESIS_ROOT" "$POST_ROOT" "$BATCH" "$TRACE_LEN" "$BOND" <<'PY'
import hashlib, struct, sys
def framed(b): return struct.pack(">I", len(b)) + b
def aid(parent, tag, pre, post, batch, tl, bond):
    buf  = framed(b"SENA:v1:assertion") + framed(parent) + framed(struct.pack(">Q", tag))
    buf += framed(pre) + framed(post) + framed(batch)
    buf += framed(struct.pack(">Q", tl)) + framed(bond.to_bytes(16, "big"))
    return hashlib.sha256(buf).digest()
g_root = bytes.fromhex(sys.argv[1][2:]); post = bytes.fromhex(sys.argv[2][2:])
batch = bytes.fromhex(sys.argv[3][2:]); tl = int(sys.argv[4]); bond = int(sys.argv[5])
Z = bytes(32)
g = aid(Z, 0, Z, g_root, Z, 0, 0)
c = aid(g, 0, g_root, post, batch, tl, bond)
print("0x"+g.hex(), "0x"+c.hex())
PY
)
echo "  genesis $GENESIS_ID"
echo "  child   $CHILD_ID"

step "5. Post a bonded assertion"
expect_ok "assertion accepted (ids agree with the contract)" \
  "${ADDR}::assertions::post" "address:$ADDR" "hex:$GENESIS_ID" "hex:$PRE_ROOT" \
  "hex:$POST_ROOT" "hex:$BATCH" "u64:$TRACE_LEN" "u128:$BOND"

status() {
  aptos move view --function-id "${ADDR}::assertions::status" \
    --args "address:$ADDR" "hex:$CHILD_ID" --profile "$PROFILE" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["Result"][0])
except Exception: print("?")'
}
[ "$(status)" = "0" ] && ok "status is Pending" || bad "expected Pending, got $(status)"

step "6. Underbonded assertion must be refused"
expect_abort "underbonded assertion rejected" "E_BOND_TOO_SMALL" \
  "${ADDR}::assertions::post" "address:$ADDR" "hex:$GENESIS_ID" "hex:$PRE_ROOT" \
  "hex:$POST_ROOT" "hex:$BATCH" "u64:$TRACE_LEN" "u128:$((BOND-1))"

step "7. Safety: finalization must fail inside the challenge window"
expect_abort "early finalization refused (E_WINDOW_OPEN)" "E_WINDOW_OPEN" \
  "${ADDR}::assertions::finalize" "address:$ADDR" "hex:$CHILD_ID"

step "8. Challenge (permissionless)"
expect_ok "challenge opened" \
  "${ADDR}::assertions::open_challenge" "address:$ADDR" "hex:$CHILD_ID"
[ "$(status)" = "1" ] && ok "status is Challenged" || bad "expected Challenged, got $(status)"

step "9. Safety: a challenged assertion must never finalize"
expect_abort "challenged assertion refused finalization (E_WRONG_STATUS)" "E_WRONG_STATUS" \
  "${ADDR}::assertions::finalize" "address:$ADDR" "hex:$CHILD_ID"

printf '\n\033[1mResult:\033[0m %d passed, %d failed\n' "$pass" "$fail"
printf 'Profile: %s (account %s)\n' "$PROFILE" "$ADDR"
printf 'Re-running creates a new account. To reuse one: SENA_PROFILE=%s %s %s\n' \
  "$PROFILE" "$0" "$NETWORK"
[ "$fail" -eq 0 ] || exit 1
