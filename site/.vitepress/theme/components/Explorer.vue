<script setup lang="ts">
// A block explorer that reads the node's JSON-RPC directly; nothing indexed,
// nothing cached. The view lives in the URL (?block=, ?tx=, ?address=) so
// every page can be linked to.
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ago, amount, rpc, short } from '../network'

type View = { kind: 'home' } | { kind: 'block'; height: number } | { kind: 'tx'; hash: string } | { kind: 'address'; address: string }

const view = ref<View>({ kind: 'home' })
const query = ref('')
const error = ref('')
const loading = ref(false)
const symbols = ref<Record<number, string>>({})
const latest = ref<any[]>([])
const block = ref<any>(null)
const tx = ref<any>(null)
const account = ref<any>(null)
let timer: ReturnType<typeof setInterval> | undefined

// The base fee is in 10⁻¹² native units (micro-dollars) per gas.
const transferCost = (baseFee: string) => (Number(BigInt(baseFee) * 41_000n) / 1e18).toFixed(6)
const symbol = (id: number) => symbols.value[id] ?? `asset ${id}`
const kinds: Record<string, string> = {
  transfer: 'Transfer',
  register_attestation: 'Link identity',
  revoke_attestation: 'Unlink identity',
  governance: 'Governance',
  distribute_fees: 'Distribute fees',
}
const kind = (t: any) => kinds[t.payload.kind] ?? t.payload.kind
const signer = (t: any) => (t.authenticator?.scheme === 'keyless' ? 'Keyless (Google)' : t.authenticator?.scheme === 'ed25519' ? 'Ed25519 key' : t.authenticator?.scheme ?? '—')

function readUrl(): View {
  const p = new URLSearchParams(location.search)
  if (p.get('block')) return { kind: 'block', height: Number(p.get('block')) }
  if (p.get('tx')) return { kind: 'tx', hash: p.get('tx')! }
  if (p.get('address')) return { kind: 'address', address: p.get('address')! }
  return { kind: 'home' }
}
function go(v: View) {
  const p = new URLSearchParams()
  if (v.kind === 'block') p.set('block', String(v.height))
  if (v.kind === 'tx') p.set('tx', v.hash)
  if (v.kind === 'address') p.set('address', v.address)
  history.pushState(null, '', p.size ? `?${p}` : location.pathname)
  show(v)
}

async function loadLatest() {
  const info = await rpc('sena_getChainInfo')
  const heights = Array.from({ length: Math.min(12, info.height) }, (_, i) => info.height - i)
  latest.value = (await Promise.all(heights.map((height) => rpc('sena_getBlock', { height }).catch(() => null)))).filter(Boolean)
}

async function show(v: View) {
  view.value = v
  error.value = ''
  loading.value = true
  try {
    if (v.kind === 'home') await loadLatest()
    if (v.kind === 'block') block.value = await rpc('sena_getBlock', { height: v.height })
    if (v.kind === 'tx') {
      const hash = v.hash.replace(/^0x/, '')
      const c = await rpc('sena_getConfirmation', { hash })
      if (c.status === 'pending') {
        tx.value = { hash, confirmation: c }
      } else {
        const b = await rpc('sena_getBlock', { height: c.height })
        const i = (b.hashes ?? []).indexOf(hash)
        if (i < 0) throw new Error('no transaction with that hash')
        tx.value = { hash, confirmation: c, block: b, transaction: b.transactions[i] }
      }
    }
    if (v.kind === 'address') {
      const [a, h] = await Promise.all([
        rpc('sena_getAccount', { address: v.address }),
        rpc('sena_getAccountTransactions', { address: v.address, limit: 50 }),
      ])
      account.value = { ...a, history: h.transactions }
    }
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

function search() {
  const q = query.value.trim()
  if (/^\d+$/.test(q)) return go({ kind: 'block', height: Number(q) })
  if (/^0x[0-9a-fA-F]{64}$/.test(q)) return go({ kind: 'address', address: q.toLowerCase() })
  if (/^[0-9a-fA-F]{64}$/.test(q)) return go({ kind: 'tx', hash: q.toLowerCase() })
  error.value = 'Enter a block number, an address (0x and 64 hex digits) or a transaction hash (64 hex digits).'
}

const status = (c: any) => (c.status === 'finalized' ? 'Final on Aptos' : c.status === 'soft_confirmed' ? 'Confirmed' : 'Pending')
const txCount = computed(() => latest.value.reduce((n, b) => n + b.transactions.length, 0))

onMounted(async () => {
  try {
    const { assets } = await rpc('sena_getFeeAssets')
    symbols.value = Object.fromEntries(assets.map((a: any) => [a.asset, a.symbol]))
  } catch (e) {
    error.value = `The node is not answering: ${(e as Error).message}`
  }
  show(readUrl())
  window.addEventListener('popstate', () => show(readUrl()))
  timer = setInterval(() => view.value.kind === 'home' && loadLatest().catch(() => {}), 5000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="explorer">
    <form class="search" @submit.prevent="search">
      <input v-model="query" placeholder="Block number, address or transaction hash" spellcheck="false" />
      <button type="submit">Search</button>
    </form>
    <p v-if="error" class="err">{{ error }}</p>
    <p v-if="loading" class="sena-muted">Loading…</p>

    <template v-if="view.kind === 'home' && latest.length">
      <h2>Latest blocks</h2>
      <p class="sena-muted">{{ txCount }} transactions in the last {{ latest.length }} blocks. Blocks are sealed only when there is something to include.</p>
      <table class="wide">
        <thead><tr><th>Block</th><th>Age</th><th>Transactions</th><th>State root</th></tr></thead>
        <tbody>
          <tr v-for="b in latest" :key="b.height">
            <td><a href="#" @click.prevent="go({ kind: 'block', height: b.height })">#{{ b.height }}</a></td>
            <td>{{ ago(b.timestamp) }}</td>
            <td>{{ b.transactions.length }}</td>
            <td class="sena-mono">{{ short(b.post_state_root, 10, 8) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <p v-else-if="view.kind === 'home' && !loading && !error" class="sena-muted">No blocks yet.</p>

    <template v-if="view.kind === 'block' && block">
      <h2>Block #{{ block.height }}</h2>
      <table>
        <tbody>
          <tr><td>Time</td><td>{{ new Date(block.timestamp * 1000).toLocaleString() }} ({{ ago(block.timestamp) }})</td></tr>
          <tr><td>State root</td><td class="sena-mono">{{ block.post_state_root }}</td></tr>
          <tr><td>Previous root</td><td class="sena-mono">{{ block.pre_state_root }}</td></tr>
          <tr><td>Assertion on Aptos</td><td class="sena-mono">{{ block.assertion ?? 'not yet posted' }}</td></tr>
          <tr><td>Execution steps</td><td>{{ block.trace_length }} (each one can be disputed on Aptos)</td></tr>
          <tr><td>Base fee</td><td>≈ ${{ transferCost(block.base_fee) }} for a plain 41,000-gas transfer</td></tr>
        </tbody>
      </table>
      <h3>Transactions</h3>
      <table class="wide">
        <thead><tr><th>Hash</th><th>Kind</th><th>From</th><th>Details</th></tr></thead>
        <tbody>
          <tr v-for="(t, i) in block.transactions" :key="i">
            <td class="sena-mono"><a href="#" @click.prevent="go({ kind: 'tx', hash: block.hashes[i] })">{{ short(block.hashes[i]) }}</a></td>
            <td>{{ kind(t) }}</td>
            <td class="sena-mono"><a href="#" @click.prevent="go({ kind: 'address', address: t.sender })">{{ short(t.sender) }}</a></td>
            <td><template v-if="t.payload.kind === 'transfer'">{{ amount(t.payload.amount) }} {{ symbol(t.payload.asset) }}</template></td>
          </tr>
        </tbody>
      </table>
      <p><a href="#" @click.prevent="go({ kind: 'block', height: block.height - 1 })" v-if="block.height > 1">← #{{ block.height - 1 }}</a>
        &nbsp; <a href="#" @click.prevent="go({ kind: 'block', height: block.height + 1 })">#{{ block.height + 1 }} →</a></p>
    </template>

    <template v-if="view.kind === 'tx' && tx">
      <h2>Transaction</h2>
      <table>
        <tbody>
          <tr><td>Hash</td><td class="sena-mono">{{ tx.hash }}</td></tr>
          <tr><td>Status</td><td>{{ status(tx.confirmation) }}<template v-if="tx.block"> in <a href="#" @click.prevent="go({ kind: 'block', height: tx.block.height })">block #{{ tx.block.height }}</a></template></td></tr>
          <template v-if="tx.transaction">
            <tr><td>Kind</td><td>{{ kind(tx.transaction) }}</td></tr>
            <tr><td>From</td><td class="sena-mono"><a href="#" @click.prevent="go({ kind: 'address', address: tx.transaction.sender })">{{ tx.transaction.sender }}</a></td></tr>
            <tr><td>Signed by</td><td>{{ signer(tx.transaction) }}</td></tr>
            <template v-if="tx.transaction.payload.kind === 'transfer'">
              <tr><td>To</td><td class="sena-mono"><a href="#" @click.prevent="go({ kind: 'address', address: tx.transaction.payload.to })">{{ tx.transaction.payload.to }}</a></td></tr>
              <tr><td>Amount</td><td>{{ amount(tx.transaction.payload.amount) }} {{ symbol(tx.transaction.payload.asset) }}</td></tr>
            </template>
            <tr><td>Fee paid in</td><td>{{ symbol(tx.transaction.fee_asset) }}, at most {{ tx.transaction.gas_limit.toLocaleString() }} gas</td></tr>
            <tr><td>Nonce</td><td>{{ tx.transaction.nonce }}</td></tr>
          </template>
        </tbody>
      </table>
      <details v-if="tx.transaction"><summary>Raw transaction</summary><pre class="raw">{{ JSON.stringify(tx.transaction, null, 2) }}</pre></details>
    </template>

    <template v-if="view.kind === 'address' && account">
      <h2>Account</h2>
      <p class="sena-mono">{{ (view as any).address }}</p>
      <div class="sena-grid">
        <div v-for="[asset, value] in account.balances" :key="asset" class="sena-tile">
          <div class="label">{{ symbol(asset) }}</div><div class="value">{{ amount(value) }}</div>
        </div>
        <div class="sena-tile"><div class="label">Transactions sent</div><div class="value">{{ account.nonce }}</div></div>
      </div>
      <p v-if="!account.balances.length" class="sena-muted">No balance.</p>
      <h3>History</h3>
      <table class="wide" v-if="account.history.length">
        <thead><tr><th>Hash</th><th>Kind</th><th>Details</th><th>Status</th></tr></thead>
        <tbody>
          <tr v-for="h in account.history" :key="h.hash">
            <td class="sena-mono"><a href="#" @click.prevent="go({ kind: 'tx', hash: h.hash })">{{ short(h.hash) }}</a></td>
            <td>{{ kind(h.transaction) }}</td>
            <td>
              <template v-if="h.transaction.payload.kind === 'transfer'">
                {{ h.transaction.sender === (view as any).address ? 'Sent' : 'Received' }}
                {{ amount(h.transaction.payload.amount) }} {{ symbol(h.transaction.payload.asset) }}
              </template>
            </td>
            <td>{{ status(h.confirmation) }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="sena-muted">No transactions.</p>
    </template>
  </div>
</template>

<style scoped>
.search { display: flex; gap: 8px; margin: 16px 0; }
.search input { flex: 1; min-width: 0; padding: 10px 14px; border: 1px solid var(--vp-c-divider); border-radius: 10px; background: var(--vp-c-bg-soft); font-family: var(--vp-font-family-mono); font-size: 0.9rem; }
.search button { padding: 10px 18px; border-radius: 10px; background: var(--vp-c-brand-1); color: #fff; font-weight: 600; }
.err { color: var(--vp-c-danger-1); }
table.wide { display: table; width: 100%; }
.raw { font-size: 0.78rem; overflow-x: auto; max-height: 420px; }
</style>
