// Where the public testnet lives. Set at build time on Vercel; the defaults
// are a local devnet.
export const network = {
  rpc: import.meta.env.VITE_SENA_RPC_URL || 'http://127.0.0.1:8545',
  faucet: import.meta.env.VITE_FAUCET_URL || '',
  issuer: import.meta.env.VITE_ISSUER_URL || '',
  wallet: import.meta.env.VITE_WALLET_URL || '',
  extension: import.meta.env.VITE_EXTENSION_URL || '',
  snap: import.meta.env.VITE_SNAP_ID || 'npm:@sena-network/snap',
  aptosContract: import.meta.env.VITE_APTOS_CONTRACT || '',
  aptosNetwork: import.meta.env.VITE_APTOS_NETWORK || 'testnet',
}

export async function rpc<T = any>(method: string, params?: unknown): Promise<T> {
  const r = await fetch(network.rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params === undefined ? { method } : { method, params }),
  })
  const out = await r.json()
  if (out.result === 'error') throw new Error(out.message)
  return out
}

/** A six-decimal stablecoin amount, for display. */
export function amount(units: string | number | bigint): string {
  const v = BigInt(units)
  const whole = v / 1_000_000n
  const frac = (v % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '')
  return whole.toLocaleString('en-US') + (frac ? '.' + frac : '')
}

export const short = (s: string, a = 8, b = 6) => (s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s)

export function ago(unix: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unix))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
