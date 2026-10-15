#!/usr/bin/env python3
"""Starts a SENA devnet for the browser wallet (github.com/MusieTesfaye/wallet).

What it sets up, all real:

  * keyless accounts on the Aptos Keyless mainnet ceremony parameters, which
    are the ones Aptos's own prover proves for, accepting Google sign-ins
    signed by the keys Google publishes right now
    (https://www.googleapis.com/oauth2/v3/certs);
  * four stablecoins whitelisted for fees: USDC, USDT and DAI at par, EURC at
    0.925 with its own intrinsic gas;
  * a faucet: a fresh Ed25519 account holding 1,000,000.00 of each, whose
    secret key is written to <data-dir>/faucet.json for the wallet's faucet
    server. It hands out coins with ordinary signed transfers;
  * a sequencer that browsers at the wallet's origin may call (CORS), with
    tips paid to a sequencer account of its own.

The chain starts empty apart from the faucet. Sign in to the wallet and the
account's address comes from your Google identity and Aptos's pepper.

If Google rotates its signing keys, new sign-ins are refused until the devnet
is started again with --fresh (this resets the chain): rotating keys on a
running chain needs a council vote, which no tool sends yet.

Usage:
  scripts/wallet-devnet.py [--data-dir DIR] [--listen ADDR] [--origin URL]... [--fresh]

Needs the node built first: cargo build --release -p sena-node
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if os.name == "nt" else ""
NODE = os.path.join(ROOT, "target", "release", "sena-node" + EXE)
GOOGLE_ISS = "https://accounts.google.com"
GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs"

# asset id, symbol, rate (per native unit, x 1e6), intrinsic gas
STABLECOINS = [
    (1, "USDC", 1_000_000, 10_000),
    (2, "USDT", 1_000_000, 10_000),
    (3, "EURC", 925_000, 15_000),
    (4, "DAI", 1_000_000, 10_000),
]
FAUCET_FUNDS = 1_000_000 * 10**6  # 1,000,000.000000 of each


def keygen():
    out = subprocess.run([NODE, "keygen"], capture_output=True, text=True, check=True).stdout
    fields = dict(line.split(None, 1) for line in out.splitlines() if line.strip())
    return {"secret": fields["secret"].strip(), "address": fields["address"].strip()}


def google_jwks():
    with urllib.request.urlopen(GOOGLE_JWKS, timeout=20) as r:
        keys = json.load(r)["keys"]
    return [{"iss": GOOGLE_ISS, "kid": k["kid"], "n": k["n"]}
            for k in keys if k.get("kty") == "RSA" and k.get("alg", "RS256") == "RS256"]


def create(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    faucet = keygen()
    sequencer = keygen()
    # `genesis` writes the file and its layout; the sections below replace the
    # development defaults.
    subprocess.run([NODE, "genesis", "--data-dir", data_dir, "--dev",
                    "--fund", f"{faucet['address']}:1"], check=True, capture_output=True)
    path = os.path.join(data_dir, "genesis.json")
    with open(path) as f:
        genesis = json.load(f)
    jwks = google_jwks()
    genesis["chain_id"] = "sena-wallet-devnet-1"
    genesis["network_salt"] = "sena-wallet-devnet-1-salt"
    genesis["gas_assets"] = [
        {"asset": a, "symbol": s, "rate": str(r), "intrinsic_gas": g, "enabled": True}
        for a, s, r, g in STABLECOINS
    ]
    genesis["allocations"] = [
        {"address": faucet["address"], "asset": a, "amount": str(FAUCET_FUNDS)}
        for a, *_ in STABLECOINS
    ]
    genesis["keyless"] = {"setup": "aptos-keyless-mainnet-2025-01", "jwks": jwks}
    with open(path, "w") as f:
        json.dump(genesis, f, indent=2)
    with open(os.path.join(data_dir, "faucet.json"), "w") as f:
        json.dump(faucet, f, indent=2)
    with open(os.path.join(data_dir, "sequencer.json"), "w") as f:
        json.dump(sequencer, f, indent=2)
    print(f"new chain in {data_dir}")
    print(f"  Google keys      {', '.join(j['kid'][:12] for j in jwks)}")
    print(f"  faucet           {faucet['address']}")
    print(f"  sequencer tips   {sequencer['address']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default=os.path.join(ROOT, "wallet-devnet"))
    ap.add_argument("--listen", default="127.0.0.1:8545")
    ap.add_argument("--origin", action="append",
                    help="browser origin allowed to call the node (default http://localhost:5173 "
                         "and http://127.0.0.1:5173)")
    ap.add_argument("--fresh", action="store_true", help="discard the chain and start a new one")
    args = ap.parse_args()

    if not os.path.exists(NODE):
        sys.exit(f"build the node first: cargo build --release -p sena-node  (looked for {NODE})")
    if args.fresh and os.path.isdir(args.data_dir):
        shutil.rmtree(args.data_dir)
    if not os.path.exists(os.path.join(args.data_dir, "genesis.json")):
        create(args.data_dir)
    else:
        print(f"resuming the chain in {args.data_dir} (--fresh starts a new one)")

    with open(os.path.join(args.data_dir, "sequencer.json")) as f:
        sequencer = json.load(f)
    origins = args.origin or ["http://localhost:5173", "http://127.0.0.1:5173"]
    faucet_path = os.path.abspath(os.path.join(args.data_dir, "faucet.json"))
    print()
    print("For the wallet's .env:")
    print(f"  VITE_SENA_RPC_URL=http://{args.listen}")
    print(f"  FAUCET_KEY_FILE={faucet_path}")
    print()
    cmd = [NODE, "run", "--data-dir", args.data_dir, "--listen", args.listen,
           "--block-interval", "1", "--fee-recipient", sequencer["address"]]
    for o in origins:
        cmd += ["--cors-origin", o]
    try:
        sys.exit(subprocess.call(cmd))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
