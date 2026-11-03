---
layout: home

hero:
  name: SENA
  text: Stablecoin payments that feel like Web2
  tagline: Sign in with Google. Pay an email address or a phone number. Pay fees in the dollars you send. Every balance settles on Aptos, and anyone can prove a wrong one wrong.
  image:
    src: /logo.svg
    alt: SENA
  actions:
    - theme: brand
      text: Try the testnet
      link: /docs/wallets
    - theme: alt
      text: The vision
      link: /vision
    - theme: alt
      text: Explorer
      link: /explorer

features:
  - icon: 🔑
    title: No seed phrase
    details: Accounts are Aptos Keyless. Sign in with Google; a zero-knowledge proof shows the chain you did, without revealing who you are. Nobody holds your key, us included.
  - icon: ✉️
    title: Pay a person, not a hex string
    details: Send to bob@gmail.com or +1 555 010 1234. Issuers vouch that an identifier belongs to an account, as in Celo's SocialConnect, and only salted hashes go on chain.
  - icon: 💵
    title: Fees in the coin you send
    details: Send USDT and pay the fee in USDT; EURC in EURC. No gas token to buy first. Metered gas, a demand-driven base fee and refunds, as on Celo.
  - icon: 🛡️
    title: Settled on Aptos, provable by anyone
    details: Every block is posted to Aptos with its data. If the sequencer lies, anyone can challenge it, and Aptos itself replays the disputed step and decides.
---

<NetworkStats />
