#!/usr/bin/env python3
"""Plays a real fraud dispute against a running Aptos localnet.

Prerequisites: `aptos node run-localnet` running, the `sena` package published
under the `admin` profile (`aptos move publish --chunked-publish`), and funded
profiles `admin`, `proposer` and `challenger` in the current directory's
.aptos/config.yaml.

The plan comes from `cargo run -p sena-fraudproof --example dispute_plan`: a
batch whose keyless transfer the proposer forges. This script initialises the
contracts, posts the forged assertion with its batch data, challenges it,
plays the bisection, submits the one-step proof — which makes Aptos verify the
keyless transaction's Groth16 proof on chain — and checks the assertion ends
rejected. It prints the gas every transaction used.

Usage: localnet-dispute.py <plan.json> [aptos binary]
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.request

APTOS = sys.argv[2] if len(sys.argv) > 2 else "aptos"
BOND = 1_000_000
WINDOW = 86_400
MAX_BATCH_AGE = 3_600
DEVNET_SETUP = 2
# Poseidon schedule steps per transaction; the most expensive steps (full
# rounds, ~450 field operations each) must fit Aptos's execution budget.
STEPS_PER_TX = int(__import__("os").environ.get("SENA_STEPS_PER_TX", "12"))


def profile_address(name):
    out = subprocess.run([APTOS, "config", "show-profiles", "--profile", name],
                         capture_output=True, text=True, check=True).stdout
    return "0x" + json.loads(out)["Result"][name]["account"]


def frame(b):
    return len(b).to_bytes(4, "big") + b


def commit(domain, *fields):
    return hashlib.sha256(frame(domain) + b"".join(frame(f) for f in fields)).digest()


def u64(v):
    return v.to_bytes(8, "big")


def batch_root(txs, starts):
    level = [commit(b"SENA:v1:batch-leaf", u64(i), u64(s), t) for i, (t, s) in enumerate(zip(txs, starts))]
    width = 1
    while width < len(level):
        width *= 2
    level += [bytes(32)] * (width - len(level))
    while len(level) > 1:
        level = [commit(b"SENA:v1:batch-node", level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def assertion_id(parent, pre, post, commitment, trace, bond):
    return commit(b"SENA:v1:assertion", parent, u64(0), pre, post, commitment, u64(trace), bond.to_bytes(16, "big"))


def run(profile, function, args, gas_log):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"function_id": function, "type_args": [], "args": args}, f)
        path = f.name
    out = subprocess.run([APTOS, "move", "run", "--json-file", path, "--profile", profile,
                          "--assume-yes", "--max-gas", "2000000"],
                         capture_output=True, text=True)
    try:
        result = json.loads(out.stdout)["Result"]
    except (ValueError, KeyError):
        sys.exit(f"{function} failed:\n{out.stdout}\n{out.stderr}")
    if not result.get("success"):
        sys.exit(f"{function} failed: {result.get('vm_status')}")
    gas_log.append((function.split("::", 1)[1], int(result["gas_used"])))
    return result


def view(function, args):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"function_id": function, "type_args": [], "args": args}, f)
        path = f.name
    out = subprocess.run([APTOS, "move", "view", "--json-file", path, "--url", "http://127.0.0.1:8080"],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["Result"]


def h(b):
    return "0x" + b.hex()


def main():
    plan = json.load(open(sys.argv[1]))
    admin, proposer, challenger = (profile_address(p) for p in ("admin", "proposer", "challenger"))
    m = f"{admin}::"
    gas = []

    run("admin", m + "assertions::initialize", [
        {"type": "hex", "value": plan["genesis_root"]},
        {"type": "u64", "value": str(WINDOW)},
        {"type": "u128", "value": str(BOND)},
        {"type": "address", "value": "0xa"},           # APT's fungible-asset metadata
        {"type": "address", "value": admin},           # treasury
        {"type": "u64", "value": str(MAX_BATCH_AGE)},
    ], gas)
    run("admin", m + "disputes::initialize", [
        {"type": "address", "value": admin},
        {"type": "u8", "value": DEVNET_SETUP},
    ], gas)

    txs = [bytes.fromhex(t[2:]) for t in plan["txs"]]
    starts = plan["starts"]
    genesis_root = bytes.fromhex(plan["genesis_root"][2:])
    zero = bytes(32)
    genesis_id = assertion_id(zero, zero, genesis_root, zero, 0, 0)
    commitment = commit(b"SENA:v1:batch", u64(plan["timestamp"]), u64(len(txs)), batch_root(txs, starts))
    fraud_root = bytes.fromhex(plan["fraud_post_root"][2:])
    aid = assertion_id(genesis_id, genesis_root, fraud_root, commitment, plan["trace_length"], BOND)

    run("proposer", m + "assertions::post", [
        {"type": "address", "value": admin},
        {"type": "hex", "value": h(genesis_id)},
        {"type": "hex", "value": plan["genesis_root"]},
        {"type": "hex", "value": plan["fraud_post_root"]},
        {"type": "u64", "value": str(plan["timestamp"])},
        {"type": "hex", "value": plan["txs"]},
        {"type": "u64", "value": [str(s) for s in starts]},
        {"type": "u64", "value": str(plan["trace_length"])},
        {"type": "u128", "value": str(BOND)},
    ], gas)
    run("challenger", m + "assertions::open_challenge", [
        {"type": "address", "value": admin},
        {"type": "hex", "value": h(aid)},
        {"type": "u128", "value": str(BOND)},
    ], gas)
    run("challenger", m + "disputes::open", [
        {"type": "address", "value": admin},
        {"type": "hex", "value": h(aid)},
    ], gas)
    did = h(aid + bytes.fromhex(challenger[2:].rjust(64, "0")))
    for r in plan["rounds"]:
        run("proposer", m + "disputes::dissect", [
            {"type": "address", "value": admin},
            {"type": "hex", "value": did},
            {"type": "hex", "value": r["commitments"]},
        ], gas)
        run("challenger", m + "disputes::select", [
            {"type": "address", "value": admin},
            {"type": "hex", "value": did},
            {"type": "u64", "value": str(r["select"])},
        ], gas)
    o = plan["one_step"]
    # The disputed step is inside the keyless transaction: compute its verdict
    # first, spread over transactions that each fit Aptos's execution budget.
    run("challenger", m + "keyless_jobs::start", [
        {"type": "address", "value": admin},
        {"type": "hex", "value": o["leaf_tx"]},
        {"type": "u64", "value": str(plan["timestamp"])},
        {"type": "u8", "value": DEVNET_SETUP},
    ], gas)
    job = commit(b"SENA:v1:keyless-job", bytes.fromhex(o["leaf_tx"][2:]), u64(plan["timestamp"]), u64(DEVNET_SETUP))
    remaining = 69
    while remaining > 0:
        chunk = min(STEPS_PER_TX, remaining)
        run("challenger", m + "keyless_jobs::advance", [
            {"type": "address", "value": admin},
            {"type": "hex", "value": h(job)},
            {"type": "u64", "value": str(chunk)},
        ], gas)
        remaining -= chunk
    run("challenger", m + "keyless_jobs::finish", [
        {"type": "address", "value": admin},
        {"type": "hex", "value": h(job)},
    ], gas)
    run("challenger", m + "disputes::one_step", [
        {"type": "address", "value": admin},
        {"type": "hex", "value": did},
        {"type": "u64", "value": str(o["leaf_index"])},
        {"type": "u64", "value": str(o["leaf_start"])},
        {"type": "hex", "value": o["leaf_tx"]},
        {"type": "hex", "value": o["leaf_siblings"]},
        {"type": "hex", "value": o["pre_root"]},
        {"type": "hex", "value": o["slot"]},
        {"type": "bool", "value": o["present"]},
        {"type": "hex", "value": o["value"]},
        {"type": "hex", "value": o["trie_siblings"]},
        {"type": "bool", "value": o["terminal_is_leaf"]},
        {"type": "hex", "value": o["terminal_key"]},
        {"type": "hex", "value": o["terminal_value_hash"]},
    ], gas)

    status = view(m + "assertions::status", [{"type": "address", "value": admin}, {"type": "hex", "value": h(aid)}])
    print("gas used per transaction:")
    for name, used in gas:
        print(f"  {used:>8}  {name}")
    print(f"assertion status: {status[0]} (3 = rejected)")
    if int(status[0]) != 3:
        sys.exit("the forged assertion was not rejected")
    print("OK: the forged keyless credit was rejected on chain")


if __name__ == "__main__":
    main()
