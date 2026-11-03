import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import NetworkStats from './components/NetworkStats.vue'
import Explorer from './components/Explorer.vue'
import TestnetDetails from './components/TestnetDetails.vue'
import './style.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('NetworkStats', NetworkStats)
    app.component('Explorer', Explorer)
    app.component('TestnetDetails', TestnetDetails)
  },
} satisfies Theme
