# LinkedIn Launch Post — publish after GitHub and CI are verified

I’ve built **AttestForge**, my second project in a focused technical portfolio, this time exploring a completely different challenge: **software supply-chain integrity**.

A release can pass its tests and still be modified before deployment. AttestForge addresses that gap with an offline-first verification workflow that binds release files and dependency metadata to a cryptographically signed attestation.

What I implemented:

🔐 Ed25519 signatures with DSSE pre-authentication encoding and in-toto Statements  
📦 Deterministic SHA-256 file manifests and CycloneDX SBOM binding  
🛡️ Trusted-key verification, release policy gates and tamper detection  
⚙️ Python CLI, a read-only FastAPI verification service, Docker and GitHub Actions configuration

**Local validation:** 100 automated tests passed, with 90.71% branch-aware coverage. A positive release check passed, and a modified release was correctly rejected. Hosted CI and Docker verification will be reported separately once run.

I also documented the security limitations clearly: a signed builder name is not proof of CI identity, an SBOM is only as complete as its inputs, and envelope-only verification is not the same as checking actual release bytes.

The goal is to build tools that are not only functional, but also **inspectable, reproducible and explicit about what they can—and cannot—guarantee**.

🔗 Repository: [add the actual published GitHub URL]  
📘 Architecture and threat model: [add the actual documentation URL]

I welcome technically specific feedback once the public release is available.

#SoftwareSupplyChain #DevSecOps #Python #CyberSecurity #OpenSource #SBOM #SoftwareEngineering
