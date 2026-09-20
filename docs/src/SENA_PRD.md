# Product Requirements Document (PRD) for SENA Network

Document Version: 1.1.0

## 1. Introduction

### 1.1 Purpose

This Product Requirements Document (PRD) outlines the features, functionalities, and user experience for the SENA Network, a Layer 2 (L2) modular infrastructure. It serves as a guiding document for product managers, designers, engineers, and other stakeholders, ensuring a shared understanding of what needs to be built and why. This PRD complements the previously created Project Proposal, Software Requirements Specification (SRS), and Software Design Description (SDD) by focusing on the product from a market and user perspective.

### 1.2 Scope

The SENA Network aims to deliver a high-performance, secure, and user-friendly L2 blockchain solution that abstracts away Web3 complexities for consumer applications. This PRD covers the product vision, target users, key features, and success metrics for the initial launch and subsequent iterations. It specifically addresses the core L2 protocol, its key modules (Keyless Authentication, Social Connect, Multi-Asset Gas Paymaster, Optimistic Governance, Fraud Proofs), and the integration of the "Aptos-Level Secure" model.

### 1.3 Definitions, Acronyms, and Abbreviations

Refer to Section 1.3 of the Software Requirements Specification (SRS) for a comprehensive list of definitions, acronyms, and abbreviations.

### 1.4 References

- [1] SENA Network: Layer 2 Modular Infrastructure Documentation (Stakeholder Document)
- [2] Software Requirements Specification (SRS) for SENA Network
- [3] Software Design Description (SDD) for SENA Network
- [4] Aptos Keyless Accounts. Aptos Docs. Available at: https://aptos.dev/concepts/accounts/#keyless-accounts

## 2. Product Vision

SENA Network envisions a future where blockchain technology is seamlessly integrated into everyday consumer applications, making decentralized services as accessible and intuitive as their Web2 counterparts. We aim to be the foundational L2 infrastructure that empowers developers to build next-generation dApps without compromising on user experience, security, or scalability.

Crucially, the Web2-like experience SENA offers is not purchased with Web2-like trust. A user who logs in with Google and pays gas in USDC should still hold assets that no operator — including SENA's own — can take, and that no operator's failure can strand. Keeping that promise is what the fraud proof system exists to do.

## 3. Target Users and Use Cases

### 3.1 Target Users

- **Web2 Developers:** Developers familiar with traditional web development paradigms (e.g., JavaScript, Python) who want to build on blockchain without deep Web3 expertise.
- **Consumer Application Developers:** Teams building social media, gaming, fintech, or e-commerce applications that require high transaction throughput, low latency, and a frictionless user experience.
- **End-Users:** Everyday consumers who expect simple onboarding, familiar authentication methods (e.g., Google, Apple login), and predictable transaction costs.
- **Verifiers and Ecosystem Watchdogs:** Exchanges, custodians, large application operators, security firms, and public-good watchtower services who run verifier nodes to independently police the chain's correctness. They are not incidental users; the security of everyone else depends on some of them existing.

### 3.2 Use Cases

- **Social dApps:** Users can log in with their existing social accounts, connect with friends using human-readable identifiers, and engage in on-chain activities without managing private keys or gas tokens.
- **Gaming:** Players can interact with in-game assets and economies with instant transactions and predictable fees, using their preferred stablecoins.
- **Fintech & Payments:** Applications can offer seamless, low-cost global payments and financial services, leveraging stablecoins and familiar authentication methods.
- **Decentralized Identity:** Users can manage their digital identities and data with enhanced privacy and control, linked to their Web2 credentials via ZKPs.
- **Treasury and Institutional Custody:** Organisations holding significant balances can run their own verifier node and rely on their own verification rather than on trust in the sequencer operator — a prerequisite for many institutional mandates.

## 4. Key Features and Functionality

SENA Network will provide the following core product features:

### 4.1 Frictionless Onboarding & Keyless Accounts

- **Feature:** Users can create and access self-custodial blockchain accounts using their existing Web2 identities (e.g., Google, Apple ID) via OpenID Connect (OIDC).
- **Benefit:** Eliminates the need for seed phrases and complex private key management, drastically reducing onboarding friction and improving user adoption.
- **Technical Implementation:** Leverages Aptos Keyless accounts and Zero-Knowledge Proofs (ZKPs) for secure, privacy-preserving authentication, with ZKP generation offloaded to a decentralized prover network.

### 4.2 Human-Readable Social Identifiers

- **Feature:** An embedded system that maps human-readable identifiers (e.g., usernames, email addresses) to SENA network addresses.
- **Benefit:** Enables intuitive social connections and payment experiences, similar to Web2 platforms, without exposing sensitive personal data.
- **Technical Implementation:** Utilizes privacy-preserving cryptographic hashing (SHA-256 with network salt) for storing identifiers, with RPC endpoints for address resolution.

### 4.3 Multi-Asset Gas Abstraction

- **Feature:** Users can pay for transaction fees using a whitelist of stablecoins (e.g., USDC, USDT) instead of a native volatile token.
- **Benefit:** Provides predictable and stable transaction costs, removing a major barrier for mainstream users and simplifying application development.
- **Technical Implementation:** The L2 protocol includes a Gas Paymaster Engine that dynamically evaluates gas costs, converts them to stablecoin equivalents, and manages an L1 bridge for continuous funding of L1 commitments.

### 4.4 Robust Security via Aptos L1 Inheritance

- **Feature:** SENA L2 inherits the security and finality guarantees of the Aptos L1 blockchain.
- **Benefit:** Ensures that user funds are safe and recoverable even in the event of an L2 server compromise, providing an "Aptos-Level Secure" environment.
- **Technical Implementation:** Periodic submission of L2 State Roots to an Aptos L1 Move contract, enabling emergency withdrawals directly from L1.

### 4.5 Enforceable Correctness via Fraud Proofs

- **Feature:** Every state root SENA commits to Aptos L1 is a bonded claim that anyone may dispute. During a challenge window, any party running a verifier node can prove the claim wrong on L1 and have it thrown out, with the sequencer's bond slashed. Disputes are settled by Aptos L1 executing the contested computation itself, with no appeal to a trusted party.
- **Benefit:** This is what makes the security claim in 4.4 load-bearing. Committing a state root to L1 makes SENA's history permanent; fraud proofs make it *correct*. Without them, a compromised sequencer could commit a state root showing balances that no honest execution would produce, and users would withdraw against that false record. With them, a single honest verifier anywhere in the world can stop it. Users, applications, and institutions do not have to trust the operator of the SENA sequencer — including SENA itself.
- **Technical Implementation:** Bonded assertions with a challenge window; mandatory publication of batch data so that anyone can re-execute the chain; permissionless challenges resolved by an interactive bisection game that narrows the disagreement to a single instruction; and a one-step verifier written in Move that Aptos L1 runs to decide the outcome. Verifier mode ships in the standard node binary so that running one requires commodity hardware and no permission.

### 4.6 Efficient and Transparent Governance

- **Feature:** A low-overhead governance mechanism allowing $SENA token holders to propose and vote on network parameter changes.
- **Benefit:** Ensures decentralized control and adaptability of the network, with transparent and auditable decision-making.
- **Technical Implementation:** Off-chain aggregation of votes with on-chain validation via a Governance Multi-Signature Council, applying updates to system variables within the Sovereign SDK runtime. Governance authority stops at the dispute system: no council signature can finalize a challenged state root, dismiss a challenge, or shorten the challenge window below its floor.

## 5. User Stories

### 5.1 End-User Stories

- As a new user, I want to sign up for a dApp using my Google account so I don't have to manage a seed phrase.
- As a user, I want to send money to my friend using their social handle so I don't have to copy a long address.
- As a gamer, I want to buy an in-game item using USDC so I don't have to worry about volatile gas fees.
- As a user, I want to be confident that my funds are safe even if the L2 network experiences issues, knowing I can withdraw them from Aptos L1.
- As a user holding a meaningful balance, I want to know that nobody — not even the company running the network — can rewrite my balance, and that if they tried, someone could prove it and stop it.
- As a user withdrawing to Aptos L1, I want to understand clearly when my transaction is confirmed on SENA versus settled on L1, and I want the option to pay a small fee for an immediate withdrawal rather than waiting out the challenge window.

### 5.2 Developer Stories

- As a dApp developer, I want to integrate keyless authentication easily so I can onboard Web2 users without friction.
- As a dApp developer, I want to use human-readable identifiers for payments and social features so I can build intuitive user experiences.
- As a dApp developer, I want my users to pay gas fees in stablecoins so they don't need to acquire a native token.
- As a dApp developer, I want to build on a secure L2 that leverages the robust security of Aptos L1.
- As a developer handling significant value, I want my transaction receipts to tell me whether a transaction is soft-confirmed or L1-final, so I do not release goods against a state root that could still be reverted.
- As an exchange or institutional integrator, I want to run my own verifier node and challenge the chain myself, so my risk assessment rests on my own verification rather than on trusting the operator.

## 6. Success Metrics

- **User Adoption:** Number of unique active users and applications deployed on SENA.
- **Transaction Volume:** Total number and value of transactions processed on the L2.
- **Developer Engagement:** Number of developers building on SENA, SDK downloads, and community activity.
- **Security Audits:** Successful completion of independent security audits with minimal critical findings, with the fraud proof contracts and one-step verifier audited as a distinct, highest-priority scope.
- **Performance:** Consistent achievement of target transaction throughput and finality metrics.
- **L1 Commitments:** Regular and successful submission of State Roots to Aptos L1.
- **Verifier Decentralization:** Number of independent verifier nodes operated by parties unaffiliated with the SENA team, and the share of assertions independently re-executed. This is the metric that determines whether the security model holds in practice; a network with one verifier is functionally custodial regardless of what the protocol permits.
- **Dispute System Health:** Successful adjudication of every dispute raised in testnet adversarial exercises, and zero invalid assertions reaching finalization on mainnet.

## 7. Future Considerations

- **Decentralized Sequencer:** Explore options for decentralizing the sequencer to enhance censorship resistance and fault tolerance. Fraud proofs address what the sequencer may assert; decentralized sequencing addresses what it may include and in what order.
- **ZK One-Step Resolution:** Replace the interactive dispute game with a single validity proof of the disputed batch, collapsing the challenge window from days to proof-generation time and removing the withdrawal delay that is the main user-visible cost of the optimistic model.
- **Shortened Challenge Windows:** Reduce the challenge window as verifier participation and tooling maturity justify it.
- **Cross-Chain Interoperability:** Investigate integrations with other L1s and L2s to expand ecosystem reach.
- **Developer Tooling:** Enhance SDKs, documentation, and developer support to foster a thriving ecosystem, including turnkey verifier node deployment so that running one is a matter of minutes.

## 8. Conclusion

SENA Network is positioned to revolutionize the adoption of blockchain technology by providing a user-centric and developer-friendly L2 infrastructure. By prioritizing seamless user experience, robust security, and efficient governance, SENA will enable a new generation of decentralized applications that can compete with and surpass their Web2 counterparts.

The addition of an enforceable fraud proof system is what lets SENA make that case without an asterisk. Consumer-grade user experience and trust-minimised security are frequently traded against one another; SENA's position is that the first belongs at the application layer and the second at the settlement layer, and that neither has to be sacrificed for the other.

## References

[1] SENA Network: Layer 2 Modular Infrastructure Documentation. [2] Software Requirements Specification (SRS) for SENA Network. [3] Software Design Description (SDD) for SENA Network. [4] Aptos Keyless Accounts. Aptos Docs. Available at: https://aptos.dev/concepts/accounts/#keyless-accounts [5] Sovereign SDK. Sovereign Labs. Available at: https://www.sovereign.xyz/ [6] RocksDB. GitHub. Available at: https://github.com/facebook/rocksdb [7] Zero-Knowledge Proofs. Wikipedia. Available at: https://en.wikipedia.org/wiki/Zero-knowledge_proof [8] OIDC and ZKP in Aptos. Aptos Labs Blog. Available at: https://aptoslabs.com/blog/aptos-keyless-accounts-oidc-zkp
