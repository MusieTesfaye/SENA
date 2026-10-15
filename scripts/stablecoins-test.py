#!/usr/bin/env python3
"""Pay fees in several stablecoins on a live node and check every balance.

Starts a sequencer whose genesis whitelists four stablecoins -- USDC and USDT
at par, EURC at a non-par rate with its own intrinsic gas, and DAI disabled --
then sends real transfers through `sena-node send` and checks, to the unit,
what each account holds in each asset afterwards:

  * a transfer in each enabled stablecoin, paying its fee in the same one;
  * a USDT transfer paying its fee in EURC (the fee asset is the payer's
    choice, independent of what moves);
  * a DAI transfer paying in DAI, which must be refused: DAI is whitelisted
    but disabled for fees;
  * a DAI transfer paying in USDC, which must go through: disabling an asset
    for fees does not freeze it;
  * a fee in an asset that is not whitelisted at all, which the node will not
    quote.

The expected amounts are computed here, independently of the node, from the
rules in docs/FEES.md.

Usage: scripts/stablecoins-test.py [path/to/sena-node]
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target/release/sena-node")
PORT = 18745
RPC = f"http://127.0.0.1:{PORT}"

RATE_SCALE = 10**6
PRICE_SCALE = 10**12
FEE_VAULT = "0x" + "fe" * 32
TIP = 10**9  # 0.001 units per gas

# asset id, symbol, rate (fee-asset units per native unit, x RATE_SCALE),
# intrinsic gas, enabled. EURC at 0.925 is one euro-cent stablecoin per
# 1.081 US dollars.
ASSETS = [
    (1, "USDC", 1_000_000, 10_000, True),
    (2, "USDT", 1_000_000, 10_000, True),
    (3, "EURC", 925_000, 15_000, True),
    (4, "DAI", 1_000_000, 10_000, False),
]
RATES = {a: (rate, gas) for a, _, rate, gas, _ in ASSETS}
SYMBOL = {a: s for a, s, *_ in ASSETS}
FUNDED = 100_000_000  # 100.000000 of each

passed = failed = 0


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FAIL  {name} {detail}")


def rpc(method, params=None):
    body = {"method": method}
    if params is not None:
        body["params"] = params
    req = urllib.request.Request(
        RPC, json.dumps(body).encode(), {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def keygen():
    out = subprocess.run([NODE, "keygen"], capture_output=True, text=True, check=True).stdout
    fields = dict(line.split(None, 1) for line in out.splitlines() if line.strip())
    return fields["secret"].strip(), fields["address"].strip()


def balances(address):
    r = rpc("sena_getAccount", {"address": address})
    return {b["asset"]: int(b["amount"]) for b in r.get("balances", [])}


def send(secret, to, amount, nonce, asset, fee_asset):
    cmd = [NODE, "send", "--rpc", RPC, "--secret", secret, "--to", to,
           "--amount", str(amount), "--nonce", str(nonce), "--asset", str(asset),
           "--fee-asset", str(fee_asset), "--tip", str(TIP)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr
    tx = next((l.split()[1] for l in out.splitlines() if l.startswith("transaction ")), None)
    return p.returncode, out, tx


def wait_confirmed(tx, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = rpc("sena_getConfirmation", {"hash": tx})
        if r.get("status") == "soft_confirmed":
            return r["height"]
        time.sleep(0.5)
    return None


def expected_fee(fee_asset, base_fee):
    """(gas, tip, base) a plain transfer pays in `fee_asset` at `base_fee`."""
    rate, intrinsic = RATES[fee_asset]
    gas = 21_000 + intrinsic + 2 * 5_000
    base_per_gas = base_fee * rate // RATE_SCALE
    max_fee = 2 * base_per_gas  # what `send` offers: twice the quoted base fee
    tip_per_gas = min(TIP, max_fee - base_per_gas)
    hold = gas * (base_per_gas + tip_per_gas) // PRICE_SCALE
    tip = gas * tip_per_gas // PRICE_SCALE
    return gas, tip, hold - tip


def main():
    work = tempfile.mkdtemp(prefix="sena-stablecoins-")
    data = os.path.join(work, "data")
    alice_secret, alice = keygen()
    _, bob = keygen()
    _, seq = keygen()

    subprocess.run([NODE, "genesis", "--data-dir", data, "--dev", "--fund", f"{alice}:1"],
                   capture_output=True, check=True)
    path = os.path.join(data, "genesis.json")
    with open(path) as f:
        genesis = json.load(f)
    genesis["gas_assets"] = [
        {"asset": a, "symbol": s, "rate": str(r), "intrinsic_gas": g, "enabled": e}
        for a, s, r, g, e in ASSETS
    ]
    genesis["allocations"] = [
        {"address": alice, "asset": a, "amount": str(FUNDED)} for a, *_ in ASSETS
    ]
    with open(path, "w") as f:
        json.dump(genesis, f, indent=2)

    log = open(os.path.join(work, "node.log"), "w")
    node = subprocess.Popen(
        [NODE, "run", "--data-dir", data, "--listen", f"127.0.0.1:{PORT}",
         "--block-interval", "1", "--fee-recipient", seq],
        stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                rpc("sena_getChainInfo")
                break
            except OSError:
                time.sleep(0.2)
        else:
            sys.exit("node did not start; see " + log.name)

        print("Quotes")
        for a, s, rate, gas, enabled in ASSETS:
            q = rpc("sena_gasPrice", {"asset": a})
            if not enabled:
                check(f"{s}: disabled, so no quote", q.get("result") == "error", q)
                continue
            check(f"{s}: rate {q.get('rate')} intrinsic {q.get('intrinsic_gas')} "
                  f"base/gas {q.get('base_fee_per_gas')}",
                  q.get("rate") == str(rate) and q.get("intrinsic_gas") == gas
                  and int(q.get("base_fee_per_gas", -1)) == int(q["base_fee_native"]) * rate // RATE_SCALE)
        q = rpc("sena_gasPrice", {"asset": 9})
        check("asset 9 (not whitelisted) gets no quote", q.get("result") == "error", q)

        # (description, moved asset, fee asset, amount, should be accepted)
        cases = [
            ("USDC transfer, fee in USDC", 1, 1, 5_000_000, True),
            ("USDT transfer, fee in USDT", 2, 2, 7_000_000, True),
            ("EURC transfer, fee in EURC", 3, 3, 3_000_000, True),
            ("USDT transfer, fee in EURC", 2, 3, 1_000_000, True),
            ("DAI transfer, fee in DAI (disabled for fees)", 4, 4, 2_000_000, False),
            ("DAI transfer, fee in USDC", 4, 1, 2_000_000, True),
            ("USDC transfer, fee in asset 9 (not whitelisted)", 1, 9, 1_000_000, False),
        ]
        expect = {who: {a: 0 for a in RATES} for who in (alice, bob, seq, FEE_VAULT)}
        for a in RATES:
            expect[alice][a] = FUNDED
        nonce = 0
        print("\nTransfers")
        for name, asset, fee_asset, amount, accept in cases:
            code, out, tx = send(alice_secret, bob, amount, nonce, asset, fee_asset)
            height = wait_confirmed(tx) if (code == 0 and tx and accept) else None
            if not accept:
                refused = code != 0 or '"rejected"' in out or '"error"' in out
                check(f"{name}: refused", refused, out.strip()[-300:])
                continue
            if height is None:
                check(f"{name}: confirmed", False, out.strip()[-300:])
                continue
            block = rpc("sena_getBlock", {"height": height})
            gas, tip, base = expected_fee(fee_asset, int(block["base_fee"]))
            expect[alice][asset] -= amount
            expect[bob][asset] += amount
            expect[alice][fee_asset] -= tip + base
            expect[seq][fee_asset] += tip
            expect[FEE_VAULT][fee_asset] += base
            check(f"{name}: block {height}, {gas} gas, tip {tip} + base {base} "
                  f"{SYMBOL[fee_asset]}", True)
            nonce += 1

        print("\nBalances (every account, every asset)")
        names = {alice: "Alice", bob: "Bob", seq: "Sequencer", FEE_VAULT: "Fee vault"}
        for who, label in names.items():
            got = balances(who)
            for a in RATES:
                check(f"{label:9} {SYMBOL[a]:4} {got.get(a, 0):>11}",
                      got.get(a, 0) == expect[who][a], f"expected {expect[who][a]}")
        for a in RATES:
            total = sum(balances(w).get(a, 0) for w in names)
            check(f"{SYMBOL[a]} supply conserved ({total})", total == FUNDED)
    finally:
        node.terminate()
        node.wait()
        log.close()

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("node log:", log.name)
        sys.exit(1)
    shutil.rmtree(work)


if __name__ == "__main__":
    main()
