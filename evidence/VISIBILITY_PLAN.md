# Next-Step Visibility and Independent Impact Plan

No outreach, email, job application or publication has been initiated by this delivery. The steps below are optional future actions for the user to undertake when ready.

## Days 1–3: public reproducibility

Publish the new public `attestforge` repository; enable GitHub Actions; resolve any lint/CI issues; run the Docker smoke; add a `v0.1.0` release only after all checks pass. Add a short terminal demonstration recording showing both valid verification and a blocked tampered artifact. Update the project README status with actual CI and Docker results, and add AttestForge to the portfolio's Projects page with a working repository link.

## Days 4–10: technical explanation

Publish a detailed technical write-up: why plain checksums do not establish a trust boundary; DSSE PAE and Ed25519; how the signed manifest binds exact release bytes; SBOM binding; policy gates; why envelope-only verification cannot claim release integrity. Include a threat model and exact negative-test results, and link the public code and documentation.

## Days 11–21: independent review

When proactive outreach is resumed by the user, seek substantive, independent code reviews from security and release-engineering practitioners. Ask reviewers to identify weaknesses in trust distribution, builder identity, filesystem races, replay protection and SBOM completeness. Address issues publicly with linked commits and tests. Do not equate GitHub stars with validated impact.

## Days 22–45: evidence of use

Demonstrate an integration in a separate sample CI pipeline that blocks a modified artifact. Track genuinely external installations, integrations, issues, PRs, documentation references and accepted improvements. Measure policy false-accept/false-reject behavior on a fixed public adversarial test suite, with exact reproduction scripts.

## Days 46–90: stronger differentiation

Add independent timestamp/transparency integration, workload identity/OIDC-backed builder authentication, complete official CycloneDX schema validation, real dependency discovery, KMS-backed signing and revocation support. Benchmark the additional checks and publish limitations. Consider a technical talk or community tutorial if independently invited or accepted.

## Evidence tracker template

| Date | External person or organization | Evidence URL | What was independently verified? | Result | Follow-up |
|---|---|---|---|---|---|
| — | — | — | — | — | — |

## Suggested public metrics

Record release downloads, external unique contributors, issue-resolution time, accepted independent code reviews, actual integrations, documented security bugs fixed, and reproducible benchmark results. Report raw counts with dates and links; do not invent adoption figures.
