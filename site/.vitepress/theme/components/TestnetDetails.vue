<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { network, rpc } from '../network'

const info = ref<any>(null)
const error = ref('')
onMounted(async () => {
  try { info.value = await rpc('sena_getChainInfo') } catch (e) { error.value = (e as Error).message }
})
const aptosLink = network.aptosContract
  ? `https://explorer.aptoslabs.com/account/${network.aptosContract}/modules?network=${network.aptosNetwork}`
  : ''
</script>

<template>
  <table>
    <tbody>
      <tr><td>Network</td><td><b>{{ info?.chain_id ?? '…' }}</b> <span v-if="error" class="sena-muted">(unreachable: {{ error }})</span></td></tr>
      <tr><td>Chain id (signed by every transaction)</td><td class="sena-mono">{{ info?.transaction_chain_id ?? '…' }}</td></tr>
      <tr><td>RPC</td><td class="sena-mono">{{ network.rpc }}</td></tr>
      <tr v-if="network.faucet"><td>Faucet</td><td class="sena-mono">{{ network.faucet }}</td></tr>
      <tr v-if="network.issuer"><td>Identity issuer</td><td class="sena-mono">{{ network.issuer }}</td></tr>
      <tr><td>Challenge window</td><td>{{ info ? info.challenge_window_secs / 3600 + ' hours' : '…' }}</td></tr>
      <tr><td>Settles on</td><td>Aptos {{ network.aptosNetwork }}<template v-if="aptosLink"> · <a :href="aptosLink" target="_blank" rel="noopener">contracts</a></template></td></tr>
      <tr v-if="network.wallet"><td>Web wallet</td><td><a :href="network.wallet">{{ network.wallet }}</a></td></tr>
      <tr v-if="network.extension"><td>Browser extension</td><td><a :href="network.extension">Download (Chrome, Edge, Brave)</a></td></tr>
      <tr><td>MetaMask Snap</td><td class="sena-mono">{{ network.snap }}</td></tr>
    </tbody>
  </table>
</template>
