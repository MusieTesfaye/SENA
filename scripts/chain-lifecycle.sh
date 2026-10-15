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
# One published transaction. Posting does not compile it -- that is what a
# dispute is for -- so any bytes do; their Merkle root is computed on chain.
TX="0x5e4a"
WINDOW=604800   # 7 days
BOND=1000000
TRACE_LEN=10
MAX_BATCH_AGE=3600
KEYLESS_SETUP=1  # aptos-keyless-mainnet-2025-01
APT_METADATA=0xa
BATCH_TIME=$(date +%s)

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
  local p="${1:-$PROFILE}"
  aptos config show-profiles --profile "$p" 2>/dev/null | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["Result"].get(sys.argv[1], {}).get("account", ""))
except Exception:
    print("")
' "$p"
}

if [ -z "$(profile_account)" ]; then
  echo "  creating and funding profile $PROFILE"
  # stdin comes from /dev/null deliberately. `aptos init` prompts for a private
  # key even under --assume-yes and treats EOF as "generate one". Without this
  # it blocks forever with no terminal attached -- from a script, from CI, from
  # anything backgrounded. It hung for twenty minutes before this was added.
  aptos init --network "$NETWORK" --profile "$PROFILE" --assume-yes </dev/null 2>&1 | tail -3
fi

# The challenger needs its own account: the contract refuses a proposer
# challenging its own assertion.
CHALLENGER="${PROFILE}-challenger"
if [ -z "$(profile_account "$CHALLENGER")" ]; then
  aptos init --network "$NETWORK" --profile "$CHALLENGER" --assume-yes </dev/null 2>&1 | tail -1
fi

account=$(profile_account)
if [ -z "$account" ]; then
  echo "  could not create or read profile $PROFILE"
  exit 1
fi
ADDR="0x$account"
echo "  $ADDR"
# `aptos init` grants 1 APT; a chunked publish needs more. Testnet has no
# programmatic faucet -- fund the account by hand there.
if [ "$NETWORK" = "local" ] || [ "$NETWORK" = "devnet" ]; then
  for p in "$PROFILE" "$CHALLENGER"; do
    aptos account fund-with-faucet --profile "$p" --amount 2000000000 >/dev/null 2>&1 \
      || echo "  note: could not top up $p from the faucet"
  done
fi

# Stop before spending anything if either account cannot pay its way. The
# publisher needs its 0.5 APT gas ceiling to be covered plus what publishing
# spends; the challenger, the bond plus gas.
apt_of() {
  aptos move view --function-id 0x1::coin::balance --type-args 0x1::aptos_coin::AptosCoin \
    --args "address:$1" --profile "$PROFILE" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(int(json.load(sys.stdin)["Result"][0]))
except Exception: print(0)'
}
CHALLENGER_ADDR="0x$(profile_account "$CHALLENGER")"
short=0
for pair in "$ADDR:100000000" "$CHALLENGER_ADDR:30000000"; do
  a="${pair%%:*}"; need="${pair##*:}"; have=$(apt_of "$a")
  if [ "$have" -lt "$need" ]; then
    echo "  $a holds $have octas; needs at least $need ($((need / 100000000)).$(printf '%08d' $((need % 100000000))) APT)"
    short=1
  fi
done
if [ "$short" -eq 1 ]; then
  echo "  fund at https://aptos.dev/network/faucet?address=<address>, then rerun with:"
  echo "    SENA_PROFILE=$PROFILE $0 $NETWORK"
  exit 1
fi

step "2. Publish the package"
# The package is over the 64 KiB transaction limit, so it goes up in chunks.
publish_out=$(aptos move publish --package-dir move/sena --named-addresses "sena=$ADDR" \
  --chunked-publish --profile "$PROFILE" "${PUBLISH_GAS_ARGS[@]}" 2>&1)
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
# Arguments are passed as `type:value` pairs and written to a --json-file,
# which (unlike --args) takes vectors of byte vectors.
run_as() {
  local profile="$1" fn="$2"; shift 2
  local file; file=$(mktemp)
  python3 - "$fn" "$@" >"$file" <<'PY'
import json, sys
def arg(a):
    t, v = a.split(":", 1)
    if v.startswith("["):
        v = json.loads(v)
    return {"type": t, "value": v}
print(json.dumps({"function_id": sys.argv[1], "type_args": [], "args": [arg(a) for a in sys.argv[2:]]}))
PY
  aptos move run --json-file "$file" --profile "$profile" "${GAS_ARGS[@]}" 2>&1
  rm -f "$file"
}
run() { run_as "$PROFILE" "$@"; }
challenger_run() { run_as "$CHALLENGER" "$@"; }

# Asserts a transaction succeeded. RUNNER selects the signer.
expect_ok() {
  local label="$1"; shift
  local out; out=$(${RUNNER:-run} "$@")
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
  "${ADDR}::assertions::initialize" "hex:$GENESIS_ROOT" "u64:$WINDOW" "u128:$BOND" \
  "address:$APT_METADATA" "address:$ADDR" "u64:$MAX_BATCH_AGE"
expect_ok "dispute registry initialised (keyless setup $KEYLESS_SETUP)" \
  "${ADDR}::disputes::initialize" "address:$ADDR" "u8:$KEYLESS_SETUP"

step "4. Derive assertion ids independently"
# Computed from the canonical encoding rather than read back from the chain, so
# a mismatch between the Move and Rust hashing shows up as a rejected argument.
read -r GENESIS_ID CHILD_ID < <(python3 - "$GENESIS_ROOT" "$POST_ROOT" "$TX" "$TRACE_LEN" "$BOND" "$BATCH_TIME" <<'PY'
import hashlib, struct, sys
def framed(b): return struct.pack(">I", len(b)) + b
def commit(domain, *fields): return hashlib.sha256(framed(domain) + b"".join(framed(f) for f in fields)).digest()
u64 = lambda v: struct.pack(">Q", v)
def aid(parent, pre, post, batch, tl, bond):
    return commit(b"SENA:v1:assertion", parent, u64(0), pre, post, batch, u64(tl), bond.to_bytes(16, "big"))
g_root = bytes.fromhex(sys.argv[1][2:]); post = bytes.fromhex(sys.argv[2][2:])
tx = bytes.fromhex(sys.argv[3][2:]); tl = int(sys.argv[4]); bond = int(sys.argv[5]); ts = int(sys.argv[6])
# A one-leaf batch tree: the root is the leaf.
root = commit(b"SENA:v1:batch-leaf", u64(0), u64(0), tx)
batch = commit(b"SENA:v1:batch", u64(ts), u64(1), root)
Z = bytes(32)
g = aid(Z, Z, g_root, Z, 0, 0)
c = aid(g, g_root, post, batch, tl, bond)
print("0x"+g.hex(), "0x"+c.hex())
PY
)
echo "  genesis $GENESIS_ID"
echo "  child   $CHILD_ID"

step "5. Post a bonded assertion"
expect_ok "assertion accepted (ids agree with the contract)" \
  "${ADDR}::assertions::post" "address:$ADDR" "hex:$GENESIS_ID" "hex:$PRE_ROOT" \
  "hex:$POST_ROOT" "u64:$BATCH_TIME" "hex:[\"$TX\"]" "u64:[\"0\"]" "u64:$TRACE_LEN" "u128:$BOND"

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
  "hex:$POST_ROOT" "u64:$BATCH_TIME" "hex:[\"$TX\"]" "u64:[\"0\"]" "u64:$TRACE_LEN" "u128:$((BOND-1))"

step "7. Safety: finalization must fail inside the challenge window"
expect_abort "early finalization refused (E_WINDOW_OPEN)" "E_WINDOW_OPEN" \
  "${ADDR}::assertions::finalize" "address:$ADDR" "hex:$CHILD_ID"

step "8. Challenge (permissionless)"
expect_abort "self-challenge refused (E_SELF_CHALLENGE)" "E_SELF_CHALLENGE" \
  "${ADDR}::assertions::open_challenge" "address:$ADDR" "hex:$CHILD_ID" "u128:$BOND"
RUNNER=challenger_run expect_ok "challenge opened by a second account" \
  "${ADDR}::assertions::open_challenge" "address:$ADDR" "hex:$CHILD_ID" "u128:$BOND"
[ "$(status)" = "1" ] && ok "status is Challenged" || bad "expected Challenged, got $(status)"

step "9. Safety: a challenged assertion must never finalize"
expect_abort "challenged assertion refused finalization (E_WRONG_STATUS)" "E_WRONG_STATUS" \
  "${ADDR}::assertions::finalize" "address:$ADDR" "hex:$CHILD_ID"

printf '\n\033[1mResult:\033[0m %d passed, %d failed\n' "$pass" "$fail"
printf 'Profile: %s (account %s)\n' "$PROFILE" "$ADDR"
printf 'Re-running creates a new account. To reuse one: SENA_PROFILE=%s %s %s\n' \
  "$PROFILE" "$0" "$NETWORK"
[ "$fail" -eq 0 ] || exit 1
