// End-to-end test of the browser bindings against a live node.
//
// Loads the WebAssembly package exactly as a wallet does, starts a sequencer,
// and moves real stablecoins: a faucet (an Ed25519 account) funds a keyless
// account, which then sends each stablecoin on, paying its fee in that same
// stablecoin. The keyless account is Aptos's published sample: its proof is
// Aptos's real circuit proof, for the insecure devnet parameters, since no
// identity provider can sign in here. Everything else is what a browser does.
//
//   scripts/build-wasm.sh
//   cargo build --release -p sena-node
//   cargo run -q -p sena-wasm --example keyless_sample > target/keyless-sample.json
//   node crates/sena-wasm/tests/e2e.mjs

import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const NODE = join(ROOT, "target", "release", "sena-node");
const PORT = 18_945;
const RPC = `http://127.0.0.1:${PORT}`;
const ORIGIN = "http://localhost:5173";

const wasm = await import(join(ROOT, "target", "sena-wasm", "sena_wasm.js"));
wasm.initSync({ module: readFileSync(join(ROOT, "target", "sena-wasm", "sena_wasm_bg.wasm")) });
const sample = JSON.parse(readFileSync(join(ROOT, "target", "keyless-sample.json"), "utf8"));

const COINS = [
  [1, "USDC", 1_000_000n, 10_000],
  [2, "USDT", 1_000_000n, 10_000],
  [3, "EURC", 925_000n, 15_000],
  [4, "DAI", 1_000_000n, 10_000],
];
const TIP = 1_000_000_000n;
let passed = 0;
let failed = 0;
const check = (name, ok, detail = "") => {
  if (ok) { passed++; console.log(`  ok    ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} ${detail}`); }
};

async function rpc(method, params) {
  const body = params === undefined ? { method } : { method, params };
  const r = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return r.json();
}

async function submit(signed) {
  const r = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: wasm.submitRequest(signed) });
  return r.json();
}

async function confirmed(hash) {
  for (let i = 0; i < 40; i++) {
    const c = await rpc("sena_getConfirmation", { hash });
    if (c.status === "soft_confirmed") return c.height;
    await new Promise((r) => setTimeout(r, 250));
  }
  return null;
}

async function balances(address) {
  const a = await rpc("sena_getAccount", { address });
  return Object.fromEntries((a.balances ?? []).map((b) => [b.asset, BigInt(b.amount)]));
}

let CHAIN_ID = 0n;

// What a wallet does to send: quote, build, sign, submit.
async function transfer(from, sign, to, asset, amount) {
  const q = await rpc("sena_gasPrice", { asset });
  const account = await rpc("sena_getAccount", { address: from });
  const tx = wasm.buildTransfer(CHAIN_ID, from, BigInt(account.nonce), to, asset, amount.toString(), asset,
    q.rate, BigInt(q.intrinsic_gas), q.suggested_max_fee_per_gas, TIP.toString());
  const signed = sign(tx);
  const response = await submit(signed);
  return { signed, response, hash: wasm.transactionHash(signed), quote: q };
}

// ------------------------------------------------------------------------------

const dir = mkdtempSync(join(tmpdir(), "sena-wasm-e2e-"));
const data = join(dir, "data");
const faucetSecret = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
const faucet = wasm.ed25519Address(faucetSecret);
const bob = wasm.ed25519Address(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"));

execFileSync(NODE, ["genesis", "--data-dir", data, "--dev", "--fund", `${faucet}:1`]);
const genesis = JSON.parse(readFileSync(join(data, "genesis.json"), "utf8"));
genesis.gas_assets = COINS.map(([asset, symbol, rate, intrinsic_gas]) =>
  ({ asset, symbol, rate: rate.toString(), intrinsic_gas, enabled: true }));
genesis.allocations = COINS.map(([asset]) => ({ address: faucet, asset, amount: "1000000000000" }));
genesis.keyless = { setup: "aptos-keyless-devnet-insecure", allow_insecure_test_setup: true, jwks: [sample.jwk] };
writeFileSync(join(data, "genesis.json"), JSON.stringify(genesis, null, 2));

const node = spawn(NODE, ["run", "--data-dir", data, "--listen", `127.0.0.1:${PORT}`,
  "--block-interval", "1", "--cors-origin", ORIGIN], { stdio: "ignore" });
try {
  for (let i = 0; ; i++) {
    try { await rpc("sena_getChainInfo"); break; } catch {
      if (i > 50) throw new Error("node did not start");
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  const info = await rpc("sena_getChainInfo");
  CHAIN_ID = BigInt(info.transaction_chain_id);
  console.log(`Chain ${info.chain_id}, transaction chain id ${CHAIN_ID}`);

  console.log("\nBrowser access");
  const pre = await fetch(RPC, { method: "OPTIONS", headers: { Origin: ORIGIN, "Access-Control-Request-Method": "POST" } });
  check(`preflight from ${ORIGIN} allowed`, pre.headers.get("access-control-allow-origin") === ORIGIN);
  const other = await fetch(RPC, { method: "OPTIONS", headers: { Origin: "http://evil.example" } });
  check("preflight from another origin gets no CORS headers", other.headers.get("access-control-allow-origin") === null);

  console.log("\nFee assets");
  const fa = await rpc("sena_getFeeAssets");
  check(`listed: ${fa.assets.map((a) => a.symbol).join(", ")}`,
    fa.assets.length === 4 && fa.assets.every((a, i) => a.symbol === COINS[i][1] && a.rate === COINS[i][2].toString()));

  console.log("\nKeyless sign-in (Aptos sample)");
  const session = wasm.newSession(BigInt(sample.exp_date_secs), Buffer.from(sample.random, "hex"));
  const claims = JSON.parse(wasm.decodeJwt(sample.jwt)).claims;
  check("JWT nonce commits to the session", claims.nonce === JSON.parse(session).nonce);
  const pepperBody = JSON.parse(wasm.pepperRequest(sample.jwt, session));
  check("pepper request carries the session's key and blinder",
    pepperBody.epk === "0020" + JSON.parse(session).public_key && pepperBody.epk_blinder === "07".repeat(31));
  const address = wasm.keylessAddress(sample.jwt, sample.pepper);
  check(`address ${address.slice(0, 18)}… is the sample's`, address === sample.address);
  const proverBody = JSON.parse(wasm.proverRequest(sample.jwt, session, sample.pepper, BigInt(sample.exp_horizon_secs), sample.extra_field));
  check("prover request names the revealed field", proverBody.extra_field === "family_name");
  const signature = wasm.assembleSignature(sample.jwt, session, sample.pepper, BigInt(sample.exp_horizon_secs),
    sample.jwk.n, sample.extra_field, JSON.stringify(sample.prover_response));
  check("signature assembled, public-inputs hash agrees", wasm.signatureAddress(signature) === address);
  let refused = false;
  try {
    const wrong = JSON.parse(JSON.stringify(sample.prover_response));
    wrong.public_inputs_hash = "0x" + "11".repeat(32);
    wasm.assembleSignature(sample.jwt, session, sample.pepper, BigInt(sample.exp_horizon_secs), sample.jwk.n, sample.extra_field, JSON.stringify(wrong));
  } catch { refused = true; }
  check("a proof for other public inputs is refused", refused);

  const signFaucet = (tx) => wasm.signEd25519(tx, faucetSecret);
  const signKeyless = (tx) => wasm.signKeyless(tx, session, signature);

  console.log("\nFaucet → keyless account, each coin paying its own fee");
  const expect = {};
  for (const [asset, symbol] of COINS) {
    const t = await transfer(faucet, signFaucet, address, asset, 10_000_000n);
    const h = t.response.result === "submitted" ? await confirmed(t.hash) : null;
    check(`${symbol}: 10.00 to the keyless account, block ${h}`, h !== null, JSON.stringify(t.response));
    expect[asset] = 10_000_000n;
  }

  console.log("\nKeyless account → Bob, each coin paying its own fee");
  for (const [asset, symbol, rate, intrinsic] of COINS) {
    const t = await transfer(address, signKeyless, bob, asset, 1_500_000n);
    const tx = JSON.parse(t.signed);
    check(`${symbol}: signed by the keyless account, gas ${tx.gas_limit}`,
      tx.sender === address && tx.authenticator.scheme === "keyless" && tx.gas_limit === 21_000 + intrinsic + 10_000 + 100_000);
    const h = t.response.result === "submitted" ? await confirmed(t.hash) : null;
    check(`${symbol}: 1.50 to Bob, block ${h}`, h !== null, JSON.stringify(t.response));
    // Fee: gas × (base + tip), the base fee converted at the coin's rate.
    const block = await rpc("sena_getBlock", { height: h });
    const basePerGas = BigInt(block.base_fee) * rate / 1_000_000n;
    const tip = TIP < basePerGas ? TIP : basePerGas; // capped by max fee = 2 × base
    const fee = BigInt(tx.gas_limit) * (basePerGas + tip) / 1_000_000_000_000n;
    expect[asset] -= 1_500_000n + fee;
    const hist = await rpc("sena_getAccountTransactions", { address });
    const entry = hist.transactions.find((e) => e.hash === t.hash);
    check(`${symbol}: history shows it, fee ${fee}`, entry && BigInt(entry.fee_paid) === fee, JSON.stringify(entry));
  }

  console.log("\nBalances");
  const mine = await balances(address);
  const bobs = await balances(bob);
  for (const [asset, symbol] of COINS) {
    check(`keyless ${symbol} ${mine[asset]}`, mine[asset] === expect[asset], `expected ${expect[asset]}`);
    check(`Bob     ${symbol} ${bobs[asset]}`, bobs[asset] === 1_500_000n);
  }
  const bobHist = await rpc("sena_getAccountTransactions", { address: bob });
  check(`Bob's history lists the 4 he received`, bobHist.transactions.length === 4);

  console.log("\nRefusals");
  const replay = await transfer(address, (tx) => {
    const t = JSON.parse(signKeyless(tx));
    t.nonce = 0; // already used
    return JSON.stringify(t);
  }, bob, 1, 1n);
  check("a replayed nonce is refused", replay.response.result === "error", JSON.stringify(replay.response));
  const tampered = await transfer(address, (tx) => {
    const t = JSON.parse(signKeyless(tx));
    t.payload.amount = "999999";
    return JSON.stringify(t);
  }, bob, 1, 1n);
  check("a transfer altered after signing is refused", tampered.response.result === "error", JSON.stringify(tampered.response));
  const otherChain = await transfer(address, (tx) => {
    const t = JSON.parse(tx);
    t.chain_id = 12345; // signed for another chain
    return signKeyless(JSON.stringify(t));
  }, bob, 1, 1n);
  check("a transfer signed for another chain is refused", otherChain.response.result === "error", JSON.stringify(otherChain.response));

  console.log("\nAttestations (Celo SocialConnect)");
  const issuerSecret = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const issuer = wasm.ed25519Address(issuerSecret);
  const identifier = wasm.hashIdentifier("email", "Alice@Example.com", info.network_salt);
  check("identifiers normalise", identifier === wasm.hashIdentifier("email", "alice@example.com", info.network_salt));
  const register = async (signer, account, issuedOn) => {
    const signature = wasm.signAttestation(signer, CHAIN_ID, identifier, account, BigInt(issuedOn));
    const payload = JSON.stringify({ kind: "register_attestation", identifier, issuer, account, issued_on: issuedOn, signature });
    const q = await rpc("sena_gasPrice", { asset: 1 });
    const nonce = (await rpc("sena_getAccount", { address })).nonce;
    const tx = wasm.buildTransaction(CHAIN_ID, address, BigInt(nonce), payload, 1, q.rate, BigInt(q.intrinsic_gas), q.suggested_max_fee_per_gas, "0");
    const signed = signKeyless(tx);
    return { response: await submit(signed), hash: wasm.transactionHash(signed) };
  };
  const lookup = async (issuers) =>
    (await rpc("sena_lookupAttestations", { identifier, trusted_issuers: issuers })).attestations ?? [];

  let builderRefused = false;
  try { await register(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex"), address, 100); }
  catch (e) { builderRefused = /does not verify/.test(String(e)); }
  check("an attestation the issuer did not sign does not even build", builderRefused);
  // Built with the real signature, then the signature swapped: the node refuses it.
  {
    const signature = wasm.signAttestation(issuerSecret, CHAIN_ID, identifier, address, 100n);
    const payload = JSON.stringify({ kind: "register_attestation", identifier, issuer, account: address, issued_on: 100, signature });
    const q = await rpc("sena_gasPrice", { asset: 1 });
    const nonce = (await rpc("sena_getAccount", { address })).nonce;
    const t = JSON.parse(wasm.buildTransaction(CHAIN_ID, address, BigInt(nonce), payload, 1, q.rate, BigInt(q.intrinsic_gas), q.suggested_max_fee_per_gas, "0"));
    t.payload.signature = "11".repeat(64);
    const response = await submit(signKeyless(JSON.stringify(t)));
    check("a tampered attestation is refused by the node", response.result === "error", JSON.stringify(response));
  }
  const real = await register(issuerSecret, address, 100);
  const height = real.response.result === "submitted" ? await confirmed(real.hash) : null;
  check(`the issuer's attestation is recorded, block ${height}`, height !== null, JSON.stringify(real.response));
  const found = await lookup([issuer]);
  check("lookup through the trusted issuer finds the keyless account", found.length === 1 && found[0].account === address, JSON.stringify(found));
  check("lookup through an untrusted issuer finds nothing", (await lookup([bob])).length === 0);
} finally {
  node.kill();
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
