<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { network, rpc } from '../network'

const info = ref<any>(null)
const assets = ref<any[]>([])
const down = ref(false)
let timer: ReturnType<typeof setInterval> | undefined

async function load() {
  try {
    info.value = await rpc('sena_getChainInfo')
    if (!assets.value.length) assets.value = (await rpc('sena_getFeeAssets')).assets
    down.value = false
  } catch {
    down.value = true
  }
}
onMounted(() => { load(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="stats">
    <p class="sena-muted">
      <span class="sena-dot" :class="down ? 'down' : 'up'" />
      <template v-if="down">The testnet node at <span class="sena-mono">{{ network.rpc }}</span> is not answering.</template>
      <template v-else-if="info">Live from the testnet: <b>{{ info.chain_id }}</b></template>
      <template v-else>Connecting to the testnet…</template>
    </p>
    <div v-if="info" class="sena-grid">
      <div class="sena-tile"><div class="label">Blocks</div><div class="value">{{ info.height.toLocaleString() }}</div></div>
      <div class="sena-tile"><div class="label">Final on Aptos</div><div class="value">{{ info.finalized_height.toLocaleString() }}</div></div>
      <div class="sena-tile"><div class="label">Fee coins</div><div class="value">{{ assets.map((a) => a.symbol).join(' · ') || '—' }}</div></div>
      <div class="sena-tile"><div class="label">Queued</div><div class="value">{{ info.mempool_size }}</div></div>
    </div>
  </div>
</template>

<style scoped>
.stats { max-width: 1152px; margin: 0 auto; padding: 0 24px 8px; }
</style>
