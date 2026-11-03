#!/usr/bin/env bash
# Sets up a public SENA testnet on this machine, settling on Aptos testnet.
#
#   git clone https://github.com/MusieTesfaye/SENA && cd SENA
#   deploy/setup.sh
#
# Safe to re-run: each step is skipped once done, so after funding the Aptos
# accounts, or after a reboot, run it again and it carries on. What it does:
#
#   1. installs Docker if missing, and opens ports 80 and 443 in the firewall;
#   2. builds the images (the node with the Aptos CLI, the faucet and issuer);
#   3. creates two Aptos accounts: the proposer (publishes the contracts, posts
#      blocks) and the challenger (the watcher's), and waits for you to fund
#      them;
#   4. creates the L2 keys and genesis (four stablecoins, Google sign-in, a
#      council that follows Google's key rotations);
#   5. publishes the SENA package to Aptos and initialises it with that genesis;
#   6. starts everything behind HTTPS on rpc., faucet. and issuer.<host>.
#
# Settings, all optional, as environment variables:
#   SENA_HOST         public host name (default <public-ip>.sslip.io)
#   SENA_CHAIN_NAME   L2 chain name (default sena-testnet-1)
#   WALLET_ORIGINS    comma-separated web origins the issuer may return to
#   APTOS_NETWORK     testnet (default), or custom with APTOS_URL/APTOS_FAUCET_URL
#   WALLET_DIR        the wallet repository (default ../../wallet, cloned if absent)
set -euo pipefail
cd "$(dirname "$0")"

CHAIN_NAME=${SENA_CHAIN_NAME:-sena-testnet-1}
APTOS_NETWORK=${APTOS_NETWORK:-testnet}
APTOS_URL=${APTOS_URL:-https://api.testnet.aptoslabs.com/v1}
WALLET_DIR=${WALLET_DIR:-../../wallet}
PROPOSER_NEEDS=400000000   # octas: ~2.3 APT to publish, the rest for bonds and gas
CHALLENGER_NEEDS=30000000
export WALLET_DIR

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

bold "1. Prerequisites"
if ! command -v docker >/dev/null; then
  note "installing Docker"
  curl -fsSL https://get.docker.com | $SUDO sh
  $SUDO usermod -aG docker "$(id -un)" || true
fi
DOCKER="docker"; docker info >/dev/null 2>&1 || DOCKER="$SUDO docker"
# Oracle's Ubuntu images ship iptables rules that reject everything but SSH,
# in addition to the cloud's security list. Open 80 and 443 here; the
# security list is done in the Oracle console (see deploy/README.md).
if command -v iptables >/dev/null && $SUDO iptables -S INPUT 2>/dev/null | grep -q -- "-j REJECT"; then
  for port in 80 443; do
    if ! $SUDO iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
      $SUDO iptables -I INPUT 1 -p tcp --dport $port -j ACCEPT
      note "opened port $port in iptables"
    fi
  done
  if command -v netfilter-persistent >/dev/null; then $SUDO netfilter-persistent save >/dev/null 2>&1 || true; fi
fi
if [ ! -d "$WALLET_DIR" ]; then
  git clone https://github.com/MusieTesfaye/wallet "$WALLET_DIR"
fi

# A re-run keeps the settings of the last one unless given new ones.
if [ -f .env ]; then
  prev() { grep "^$1=" .env | cut -d= -f2- || true; }
  SENA_HOST=${SENA_HOST:-$(prev SENA_HOST)}
  WALLET_ORIGINS=${WALLET_ORIGINS:-$(prev WALLET_ORIGINS)}
fi
if [ -z "${SENA_HOST:-}" ]; then
  ip=$(curl -fsS https://api.ipify.org)
  SENA_HOST="$(echo "$ip" | tr . -).sslip.io"
fi
note "host: $SENA_HOST"

# Compose reads .env; the values it needs before anything exists are placeholders.
write_env() {
  cat > .env <<EOF
SENA_HOST=$SENA_HOST
APTOS_URL=$APTOS_URL
CONTRACT=${CONTRACT:-0x0}
CHALLENGER=${CHALLENGER:-0x0}
SEQUENCER_ADDRESS=${SEQUENCER_ADDRESS:-0x0000000000000000000000000000000000000000000000000000000000000000}
WALLET_ORIGINS=${WALLET_ORIGINS:-http://localhost:5173}
WALLET_DIR=$WALLET_DIR
EOF
}
write_env
compose() { $DOCKER compose --progress quiet "$@"; }
# One-off commands in the node image, with data/ mounted at /data.
tool() { compose run --rm --no-deps -T "$@"; }
# A field of a JSON file under data/. Read in the container: the keys are
# root's, mode 0600, as the services that use them run as root.
field() { tool node python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "/data/$1" "$2"; }

bold "2. Build"
# SENA_SKIP_BUILD=1 uses images built already (sena-node:local, sena-services:local).
[ "${SENA_SKIP_BUILD:-}" = 1 ] || compose build

bold "3. Aptos accounts"
mkdir -p data/aptos
network_args=(--network "$APTOS_NETWORK")
[ "$APTOS_NETWORK" = custom ] && network_args+=(--rest-url "$APTOS_URL" --faucet-url "${APTOS_FAUCET_URL:-}")
account_of() {
  tool -w /data/aptos node python3 -c '
import re, sys
try: text = open(".aptos/config.yaml").read()
except OSError: sys.exit()
m = re.search(r"^  %s:\n(?:    .*\n)*?    account: ([0-9a-f]+)" % sys.argv[1], text, re.M)
print("0x" + m.group(1) if m else "")' "$1"
}
for p in proposer challenger; do
  if [ -z "$(account_of $p)" ]; then
    # stdin from /dev/null: `aptos init` then generates a key instead of prompting.
    tool -w /data/aptos node sh -c "aptos init --profile $p ${network_args[*]} --skip-faucet --assume-yes </dev/null >/dev/null 2>&1"
  fi
done
CONTRACT=$(account_of proposer); CHALLENGER=$(account_of challenger)
note "proposer   $CONTRACT  (publishes the contracts and posts blocks)"
note "challenger $CHALLENGER  (the watcher)"

balance() {
  tool -w /data/aptos node sh -c "aptos move view --function-id 0x1::coin::balance \
    --type-args 0x1::aptos_coin::AptosCoin --args address:$1 --profile proposer 2>/dev/null" \
    | tool node python3 -c 'import json,sys
try: print(int(json.load(sys.stdin)["Result"][0]))
except Exception: print(0)'
}
if [ ! -f data/.published ]; then
  while :; do
    p=$(balance "$CONTRACT"); c=$(balance "$CHALLENGER")
    [ "$p" -ge $PROPOSER_NEEDS ] && [ "$c" -ge $CHALLENGER_NEEDS ] && break
    apt() { printf '%d.%02d APT' $(($1 / 100000000)) $(($1 % 100000000 / 1000000)); }
    note "waiting for testnet APT: proposer has $(apt "$p") of $(apt $PROPOSER_NEEDS), challenger $(apt "$c") of $(apt $CHALLENGER_NEEDS)"
    note "  fund them at https://aptos.dev/network/faucet (sign in; mint several times),"
    note "  or send testnet APT from a wallet such as Petra. Checking again in 30s; Ctrl-C to stop."
    sleep 30
  done
  note "both accounts funded"
fi

bold "4. L2 keys and genesis"
if [ ! -f data/chain/genesis.json ]; then
  tool node python3 /opt/sena/deploy/make-genesis.py /data "$CHAIN_NAME"
fi
tool node sh -c 'mkdir -p /data/watcher && cp /data/chain/genesis.json /data/watcher/genesis.json'
STATE_ROOT=$(field chain/info.json state_root)
CHAIN_ID=$(field chain/info.json transaction_chain_id)
SEQUENCER_ADDRESS=$(field keys/sequencer.json address)
note "chain $CHAIN_NAME, id $CHAIN_ID, genesis root $STATE_ROOT"

bold "5. Publish and initialise on Aptos"
run_fn() {
  tool -w /data/aptos node sh -c "aptos move run --profile proposer --max-gas 200000 --gas-unit-price 100 --assume-yes \
    --function-id $CONTRACT::$1 --args ${*:2}" 2>&1
}
if [ ! -f data/.published ]; then
  out=$(tool -w /data/aptos node sh -c "aptos move publish --package-dir /opt/sena/move/sena \
    --named-addresses sena=$CONTRACT --chunked-publish --large-packages-module-address 0x7 \
    --profile proposer --max-gas 2000000 --gas-unit-price 100 --assume-yes" 2>&1) || true
  if ! echo "$out" | grep -q '"success": true'; then
    echo "$out" | tail -20; echo "publish failed"; exit 1
  fi
  touch data/.published
  note "package published at $CONTRACT"
fi
if [ ! -f data/.initialised ]; then
  # Genesis root, 24-hour challenge window, 0.01 APT minimum bond in APT
  # (0xa), the proposer as treasury, batches at most an hour behind L1.
  out=$(run_fn assertions::initialize "hex:0x$STATE_ROOT" u64:86400 u128:1000000 address:0xa "address:$CONTRACT" u64:3600)
  echo "$out" | grep -q '"success": true' || { echo "$out" | tail -8; echo "assertions::initialize failed"; exit 1; }
  # Keyless setup 1: the Aptos Keyless mainnet ceremony, which Aptos's prover proves for.
  out=$(run_fn disputes::initialize "address:$CONTRACT" u8:1 "u64:$CHAIN_ID")
  echo "$out" | grep -q '"success": true' || { echo "$out" | tail -8; echo "disputes::initialize failed"; exit 1; }
  touch data/.initialised
  note "initialised"
fi

bold "6. Start"
write_env
profiles=()
if [ -f data/issuer/issuer.config.json ]; then profiles=(--profile issuer); else
  note "no data/issuer/issuer.config.json: the identity issuer stays off (see deploy/README.md)"
fi
compose "${profiles[@]}" up -d
FAUCET=$(field keys/faucet.json address)
ISSUER=$(field keys/issuer.json address)

cat > data/testnet.json <<EOF
{
  "chain": "$CHAIN_NAME",
  "transaction_chain_id": $CHAIN_ID,
  "genesis_state_root": "$STATE_ROOT",
  "rpc": "https://rpc.$SENA_HOST",
  "faucet": "https://faucet.$SENA_HOST",
  "issuer": "https://issuer.$SENA_HOST",
  "issuer_address": "$ISSUER",
  "faucet_address": "$FAUCET",
  "aptos_contract": "$CONTRACT",
  "aptos_network": "$APTOS_NETWORK"
}
EOF

bold "Done"
cat data/testnet.json
cat <<EOF

For the wallet and the site on Vercel, set:
  VITE_SENA_RPC_URL=https://rpc.$SENA_HOST
  VITE_FAUCET_URL=https://faucet.$SENA_HOST
  VITE_ISSUER_URL=https://issuer.$SENA_HOST
  VITE_TRUSTED_ISSUERS=$ISSUER
  VITE_APTOS_CONTRACT=$CONTRACT

Check it:   curl -s https://rpc.$SENA_HOST -d '{"method":"sena_getChainInfo"}'
Logs:       docker compose -f deploy/docker-compose.yml logs -f
Contracts:  https://explorer.aptoslabs.com/account/$CONTRACT?network=$APTOS_NETWORK
EOF
