# Global Talent Portfolio — Completed-Project Sequence

| # | Project | Technical domain | Status | Public repository |
|---:|---|---|---|---|
| 01 | **VeriRAG** | LLM/RAG evidence verification, retrieval, provenance and risk gating | Previously delivered and publicly published | https://github.com/sattipraveena3-sudo/veritrag |
| 02 | **AttestForge** | Software supply-chain cryptography, Ed25519 DSSE attestations, SBOMs, DevSecOps policy gates | Complete local implementation: 100 tests passed, 90.71% branch-aware coverage, CLI positive/negative smoke passed; publication, hosted CI and Docker runtime checks pending | Not yet published |

## Why Project #02 increases complexity

VeriRAG verifies model output against retrieved evidence. AttestForge addresses a **different trust boundary**: the cryptographic provenance and integrity of software release artifacts. It adds standards-inspired signing, local trust-root management, canonicalized signed manifests, dependency-inventory binding, time- and license-aware policy, strict parser defenses, an explicit distinction between full verification and envelope-only verification, and 100 automated tests. The complexity increase is architectural and security-related; it does not imply formal certification.

## Numbering policy

Project #02 follows the previous Global Talent sequence where VeriRAG was Project #01. Other public GitHub repositories remain part of the wider portfolio but are **not silently renumbered** into this new dedicated sequence. The next project should use another distinct domain and be assessed on real test evidence before being marked complete.
