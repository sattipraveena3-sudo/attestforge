# UK Global Talent (Digital Technology) — Evidence Notes

**Project:** AttestForge (Global Talent Portfolio Project #02)  
**Applicant/project author:** Praveena Satti  
**Evidence status:** Independently runnable local implementation; no independent recognition or external adoption yet.

## How this project could contribute to an application

AttestForge demonstrates technical implementation skills across modern cryptography, secure release engineering, reproducibility, policy-based verification, SBOMs, Docker and API security. It may support a narrative of **technical expertise** and **independent innovation or contribution**, especially if it acquires documented third-party users or contributions. It is **not by itself proof of exceptional talent/promise**, and neither an internal score nor a self-published GitHub repository is equivalent to external recognition.

The official UK Global Talent digital technology route distinguishes **exceptional talent** (leader) and **exceptional promise** (potential leader). The endorsing body assesses recognition and additional criteria, including innovation, sector contribution and research or significant technical contributions. The rules also require a CV and **three recommendation letters** from recognized experts with detailed knowledge of the applicant's work. Review the current official criteria before preparing an application:

- GOV.UK eligibility: https://www.gov.uk/global-talent-digital-technology/eligibility
- Immigration Rules, Appendix Global Talent (digital technology): https://www.gov.uk/guidance/immigration-rules/immigration-rules-appendix-global-talent
- GOV.UK documents for digital technology endorsement: https://www.gov.uk/global-talent-digital-technology/documents-youll-need-to-apply-for-endorsement

## Evidence pack to retain

| Evidence item | Current state | Why it matters |
|---|---|---|
| Source code and signed commits | Local ZIP delivered; GitHub commit pending | Authorship, scope, chronological development |
| Test logs and coverage | **100 tests passed, 90.71% branch-aware coverage** | Reproducibility and engineering rigor |
| Negative tampering demo | Local CLI smoke passed | Demonstrates meaningful fail-closed behavior |
| Architecture and threat model | Included in `docs/` | Shows original engineering decisions and boundaries |
| GitHub Actions history | **Pending** | Public time-stamped reproducibility once green |
| Docker build and smoke | **Pending** | Deployment evidence after execution |
| External pull requests/issues | **None established** | Independent interest or technical validation |
| Third-party integration/adoption | **None established** | Evidence of impact beyond self-authored code |
| Independent reviews/testimonials | **None established** | Credible external recognition, not self-assessment |
| Release notes, demos and downloads | **Pending publication** | Public evidence of delivery and distribution |

## Claim-safe wording

> "I designed and implemented AttestForge, an offline-first software supply-chain verification platform that uses Ed25519 DSSE attestations, signed file manifests, SBOM binding and fail-closed release policies. The initial implementation passed 100 local automated tests with 90.71% branch-aware coverage. Hosted CI, Docker smoke and independent adoption remain to be validated."

Avoid claiming certification, SLSA compliance, vulnerability scanning, cryptographically proven CI identity, commercial adoption, external awards, published research, or visa endorsement unless independently documented.

## Suggested screenshots (after publication)

1. README architecture and repository tree with date and GitHub URL.
2. CI run with matrix results, successful tests and coverage logs.
3. Valid release verification JSON (`release_verified: true`).
4. Tampered release verification JSON (`ARTIFACT_MISMATCH`, exit code 2).
5. Issue/PR discussions from unrelated developers, only when genuine.
6. Release page with version tag and changelog.

## Independent validation pathway

Seek review from maintainers in software supply-chain/security tooling communities, request concrete technical feedback, publish a reproducible benchmark of tamper-detection cases, and integrate the tool into a real external CI pipeline. Record **actual** links, dates, review comments, users, merged contributions and measurable results. Do not solicit fabricated endorsements, purchased stars or testimonial swaps.

**Legal caution:** This is portfolio evidence planning, not immigration legal advice. Rules and endorsement practices can change; use the current official guidance and a qualified adviser where appropriate.
