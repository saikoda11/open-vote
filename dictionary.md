# Glossary (ZK + Blockchain E-Voting)

## Zero-Knowledge Proof (ZKP)
A cryptographic protocol where a **prover** convinces a **verifier** that a statement is true **without revealing** any additional information beyond the truth of the statement.

## Prover / Verifier
- **Prover**: party that generates the proof for a claim.
- **Verifier**: party that checks the proof and accepts/rejects the claim.

## Completeness / Soundness / Zero-knowledge
Standard ZKP guarantees:
- **Completeness**: honest proofs for true statements verify.
- **Soundness**: false statements cannot be proven except with negligible probability.
- **Zero-knowledge**: the proof leaks no extra information.

## Non-Interactive Zero-Knowledge (NIZK)
A ZK proof that requires **no interaction** after setup: the prover posts a single proof that anyone can verify.

---

## Coercion-resistance
A voting security property ensuring a voter **cannot convincingly prove** to a coercer how they voted, even under pressure (including being forced to reveal secrets). The system provides a “safe strategy” (e.g., re-voting, fake credentials, hidden change) so coercion or bribery cannot be reliably enforced.

## Receipt-freeness
A related (usually weaker) property: the voter cannot produce a “receipt” that proves how they voted to a third party.

## Anti-collusion / Collusion-resistance
A system property that reduces the effectiveness of bribery and vote-buying by making it hard or impossible for outsiders to verify a voter’s choice.

---

## zk-SNARK
“Zero-Knowledge Succinct Non-Interactive Argument of Knowledge.”
A ZK proof system with **small proofs** and **fast verification**; many SNARK constructions require a **trusted setup** (a one-time parameter generation ceremony).

## Trusted setup
A one-time procedure that generates public parameters for some SNARK systems. If compromised, it may allow proof forgery (depending on the scheme). “Transparent” systems aim to avoid trusted setup.

## zk-STARK
“Zero-Knowledge Scalable Transparent Argument of Knowledge.”
A ZK proof system that is typically **transparent** (usually **no trusted setup**) and can scale well, often at the cost of **larger proofs** compared to SNARKs.

## ZKSpark (non-standard term)
“ZKSpark” is not a widely standard category name in the literature. In most contexts, people mean **zk-STARK**. If your course/project uses “ZKSpark,” define it explicitly as the exact proof system/library you use; otherwise rename this term to **zk-STARK**.

---

## Hash function
A deterministic function mapping arbitrary input to a fixed-length output, designed to be hard to invert and collision-resistant. Used for integrity, commitments, and Merkle trees.

## Merkle tree (hash tree)
A tree of hashes where:
- leaves are hashes of items (e.g., eligible voters),
- internal nodes hash their children.
Enables efficient **membership proofs** in **O(log n)** hashes.

## Merkle root
The top hash of a Merkle tree; acts as a compact **commitment** to the entire set of leaves.

## Commitment (cryptographic commitment)
A “sealed envelope” to a value:
- **Hiding**: the commitment does not reveal the value.
- **Binding**: the committer cannot change the value later without detection.

---

## Nullifier
A public value posted with a ZK proof to prevent **double-use** (e.g., double-voting) **without revealing identity**. The contract checks the nullifier has not appeared before; duplicates are rejected.

## Scope / Election ID (context)
A public identifier for the action context (election ID, question ID, etc.). Nullifiers are typically derived from *(secret identity, scope)* so a voter can act once per scope but still remain anonymous.

## Anonymous group membership proof
A ZK proof that “I belong to the eligible set” (e.g., registered students) without revealing which member. Often implemented via Merkle-tree membership.

## Sybil resistance
Ensuring “one person → one eligible identity” during registration. ZK can hide identity and prove eligibility, but it does not solve Sybil attacks by itself; you still need a correct eligibility process (SSO/registry).

---

## Eligibility
Only authorized/registered voters can cast an accepted ballot.

## Uniqueness (one-person-one-vote)
Each eligible voter can have **at most one counted** ballot (commonly enforced using nullifiers).

## Ballot secrecy
No one can link a voter’s identity to their vote choice.

## Public bulletin board
An append-only public log of election artifacts (a blockchain can serve as this), enabling auditability.

## End-to-End Verifiability (E2E-V)
Voters can verify their ballot is included, and anyone can verify the tally matches the posted cryptographic ballots—without learning individual votes.

---

## MACI (Minimal Anti-Collusion Infrastructure)
A smart-contract-based private voting framework using encryption and ZK proofs to provide privacy and reduce bribery/collusion effectiveness, aiming for publicly verifiable outcomes (often emphasizing receipt-freeness to outsiders).

## Coordinator (MACI)
An entity that processes encrypted messages and generates ZK proofs of correct processing/tallying. Some MACI properties depend on coordinator assumptions (or mitigations).
