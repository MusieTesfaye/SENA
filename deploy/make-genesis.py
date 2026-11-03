#!/usr/bin/env python3
"""Creates the keys and genesis of a public SENA testnet.

Run once, by deploy/setup.sh, inside the node image. Writes into DATA:

  keys/faucet.json     the faucet's account, holding each stablecoin
  keys/sequencer.json  where the sequencer's tips are paid
  keys/council.json    the council (threshold 1) and jwk-sync's sender
  keys/issuer.json     the attestation issuer
  chain/genesis.json   the chain: four stablecoins, Google's keys, the council
  chain/info.json      its state root and transaction chain id

Keys are plain JSON files readable only by their owner. That is a test
network's standard, not a production one.

Usage: make-genesis.py DATA CHAIN_NAME
"""

import json
import os
import re
import subprocess
import sys
import urllib.request

NODE = os.environ.get("SENA_NODE", "sena-node")
GOOGLE_ISS = "https://accounts.google.com"
GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs"
# asset id, symbol, rate (per native unit, x 1e6), intrinsic gas
STABLECOINS = [
    (1, "USDC", 1_000_000, 10_000),
    (2, "USDT", 1_000_000, 10_000),
    (3, "EURC", 925_000, 15_000),
    (4, "DAI", 1_000_000, 10_000),
]
FAUCET_FUNDS = 100_000_000 * 10**6  # 100,000,000.000000 of each
COUNCIL_FUNDS = 10_000 * 10**6  # USDC for jwk-sync's fees


def keygen():
    out = subprocess.run([NODE, "keygen"], capture_output=True, text=True, check=True).stdout
    fields = dict(re.split(r"\s+", line.strip(), maxsplit=1) for line in out.splitlines()
                  if re.match(r"^(secret|public|address)\s", line))
    return {"secret": fields["secret"], "address": fields["address"]}


def write_key(path, key):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(key, f, indent=2)


def main():
    data, name = sys.argv[1], sys.argv[2]
    chain = os.path.join(data, "chain")
    keys = os.path.join(data, "keys")
    if os.path.exists(os.path.join(chain, "genesis.json")):
        sys.exit(f"{chain}/genesis.json exists; refusing to replace a chain")
    os.makedirs(keys, exist_ok=True)
    os.makedirs(chain, exist_ok=True)

    made = {k: keygen() for k in ("faucet", "sequencer", "council", "issuer")}
    for k, v in made.items():
        write_key(os.path.join(keys, f"{k}.json"), v)

    with urllib.request.urlopen(GOOGLE_JWKS, timeout=20) as r:
        google = [k for k in json.load(r)["keys"]
                  if k.get("kty") == "RSA" and k.get("alg", "RS256") == "RS256"]

    # `genesis` writes the layout; the sections below replace its defaults.
    subprocess.run([NODE, "genesis", "--data-dir", chain, "--dev",
                    "--fund", f"{made['faucet']['address']}:1"], check=True, capture_output=True)
    path = os.path.join(chain, "genesis.json")
    with open(path) as f:
        genesis = json.load(f)
    genesis["chain_id"] = name
    genesis["network_salt"] = f"{name}-salt"
    genesis["gas_assets"] = [
        {"asset": a, "symbol": s, "rate": str(r), "intrinsic_gas": g, "enabled": True}
        for a, s, r, g in STABLECOINS
    ]
    genesis["allocations"] = [
        {"address": made["faucet"]["address"], "asset": a, "amount": str(FAUCET_FUNDS)}
        for a, *_ in STABLECOINS
    ] + [{"address": made["council"]["address"], "asset": 1, "amount": str(COUNCIL_FUNDS)}]
    genesis["council"] = {"members": [made["council"]["address"].removeprefix("0x")], "threshold": 1}
    genesis["keyless"] = {
        "setup": "aptos-keyless-mainnet-2025-01",
        "jwks": [{"iss": GOOGLE_ISS, "kid": k["kid"], "n": k["n"]} for k in google],
    }
    with open(path, "w") as f:
        json.dump(genesis, f, indent=2)

    # The state root and chain id come from the node itself, from the final
    # file: `genesis` on an existing file would refuse, so read them back by
    # loading it in a scratch directory.
    scratch = os.path.join(data, ".genesis-check")
    os.makedirs(scratch, exist_ok=True)
    with open(os.path.join(scratch, "genesis.json"), "w") as f:
        json.dump(genesis, f)
    out = subprocess.run([NODE, "inspect-genesis", "--data-dir", scratch],
                         capture_output=True, text=True, check=True).stdout
    info = json.loads(out)
    with open(os.path.join(chain, "info.json"), "w") as f:
        json.dump(info, f, indent=2)
    print(json.dumps({**info, **{k: v["address"] for k, v in made.items()}}))


if __name__ == "__main__":
    main()
