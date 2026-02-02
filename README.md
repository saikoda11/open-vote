# Blockchain-Based Electronic Voting

Solve the "double-voting" and "transparency" problems in student government elections using zero-knowledge proofs (ZKP) for privacy.

## Project Overview
This project addresses the critical challenges of **transparency** and **privacy** in student government elections. Traditional electronic voting systems often require a trusted third party, while standard blockchain voting exposes user identities. 

**ZK-Vote** utilizes **Zero-Knowledge Proofs (specifically zk-SNARKs via the Semaphore protocol)** to allow students to prove they are eligible to vote and have not voted yet, without revealing *who* they are or *which* candidate they voted for.

---

## The Problem
1.  **Transparency:** Physical ballot boxes and centralized databases are opaque; students cannot verify if their vote was counted correctly.
2.  **Double-Voting:** In anonymous systems, it is difficult to prevent a user from voting multiple times without tracking their identity.
3.  **Privacy:** Public blockchains (like Ethereum) are transparent. If a student signs a transaction with their wallet, their vote is publicly linked to their address.

## The Solution
We implemented a decentralized application (dApp) that uses:
* **Merkle Trees** to store the group of eligible voters.
* **Zero-Knowledge Proofs** to verify eligibility off-chain.
* **Nullifiers** to prevent double-voting without revealing identity.
* **Smart Contracts** to publicly and immutably record the final tally.

---

## How It Works

### 1. Registration (The Commitment)
* A student connects their wallet.
* The system generates a secret **Identity** (Private Key).
* The system hashes this identity to create an **Identity Commitment**.
* This commitment is added to the Smart Contract's **Merkle Tree**. 
    * *Result: The blockchain knows "This hash belongs to a student," but not which specific student.*

### 2. Voting (The Proof)
* The student selects a candidate on the frontend.
* The application generates a **Zero-Knowledge Proof** locally in the browser.
* This proof asserts: *"I exist in the Merkle Tree"* AND *"I am generating a unique Nullifier."*
* The **Nullifier** is a unique hash derived from the user's secret. If the user tries to vote again, the Nullifier will be identical.

### 3. Verification (The Tally)
* The proof and the vote are submitted to the Smart Contract.
* The Contract verifies the proof and checks if the Nullifier has been used before.
* If valid, the vote is added to the candidate's total.
    * *Result: The vote is counted, double-voting is blocked, and no observer can link the vote to the student's wallet.*

---

## Tech Stack

* **Blockchain:** Ethereum (Sepolia Testnet / Hardhat Local)
* **Smart Contracts:** Solidity
* **ZK Protocol:** [Semaphore](https://semaphore.pse.dev/) (Privacy layer)
* **Frontend:** ...
* **Libraries:** `ethers.js`, `@semaphore-protocol/core`, `@semaphore-protocol/contracts`

---
