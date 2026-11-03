import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'SENA',
  description: 'Stablecoin payments that feel like Web2, settled on Aptos.',
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', href: '/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#10b981' }],
  ],
  themeConfig: {
    logo: '/logo.svg',
    nav: [
      { text: 'Vision', link: '/vision' },
      { text: 'Docs', link: '/docs/' },
      { text: 'Testnet', link: '/testnet' },
      { text: 'Explorer', link: '/explorer' },
    ],
    sidebar: {
      '/docs/': [
        {
          text: 'Use SENA',
          items: [
            { text: 'Overview', link: '/docs/' },
            { text: 'Get a wallet', link: '/docs/wallets' },
            { text: 'Pay an email or phone', link: '/docs/identities' },
            { text: 'Fees in stablecoins', link: '/docs/fees' },
            { text: 'Is it safe?', link: '/docs/security' },
          ],
        },
        {
          text: 'How it works',
          items: [
            { text: 'Architecture', link: '/docs/architecture' },
            { text: 'Fraud proofs on Aptos', link: '/docs/fraud-proofs' },
            { text: 'Keyless accounts', link: '/docs/keyless' },
          ],
        },
        {
          text: 'Build on SENA',
          items: [
            { text: 'JSON-RPC', link: '/docs/rpc' },
            { text: 'Run a node', link: '/docs/run-a-node' },
          ],
        },
        {
          text: 'Project',
          items: [
            { text: 'Status and roadmap', link: '/docs/status' },
          ],
        },
      ],
    },
    socialLinks: [{ icon: 'github', link: 'https://github.com/MusieTesfaye/SENA' }],
    footer: {
      message: 'Beta software on Aptos testnet. Not audited. Use test funds only.',
      copyright: 'Apache-2.0',
    },
    search: { provider: 'local' },
  },
})
