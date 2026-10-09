# Threat Model and Security Limitations

## Protected assets

Release bytes, a canonical file inventory, dependency-inventory binding, the release policy, the trusted public-key set, and the private signing key. The intended security outcome is detection of post-signing artifact tampering **when the verifier receives the correct trusted public key and an independently controlled policy**.

## Attacker model

An attacker may edit, add or delete files after signing; substitute an unsigned SBOM; modify a DSSE payload or signature; supply an untrusted public key; attempt symlink/path traversal; exploit malformed JSON; or present an attestation that is stale, future-dated or from a non-allowlisted builder. The attacker is **not** assumed to control the trusted public-key directory, the verifier's local policy, the private key, or the verifier process itself.

## Threat-to-control matrix

| Threat | Control | Negative test |
|---|---|---|
| Modify signed release bytes | Re-hash every file and compare full manifest | `test_tampered_artifact_fails` |
| Add or remove a release file | Exact manifest equality | `test_added_artifact_fails`, `test_deleted_artifact_fails` |
| Replace DSSE payload/signature | Ed25519 over DSSE PAE | `test_tampered_payload_fails`, `test_tampered_signature_fails` |
| Sign with a different key | Independently configured trust directory | `test_wrong_trust_store_fails` |
| Substitute dependency inventory | Signed canonical SBOM digest | `test_wrong_sbom_fails` |
| Supply unknown/missing dependency licences | Policy checks on declared metadata | `test_missing_license_fails` |
| Use stale or future attestation | Timestamp policy with bounded clock skew | `test_expired_attestation_fails`, `test_future_attestation_fails` |
| Hide filesystem targets behind symlinks | Reject symlinked roots/files/directories; `O_NOFOLLOW` | `test_manifest_rejects_*symlink` |
| Duplicate JSON keys | Strict object-pair parser | `test_duplicate_json_key_rejected` |
| Oversized HTTP request | Request stream bound + length check | `test_api_rejects_large_payload` |
| Server misconfiguration | Readiness and verify fail closed | `test_api_fails_closed_without_trust` |

## Out-of-scope threats and residual risks

1. **Compromised signer or key:** If the signing key is stolen or the trusted builder is compromised, the attacker can sign malicious releases. Use HSM/KMS, rotation, incident response and independently controlled key trust in a real deployment.
2. **Self-asserted builder identity:** The signed `builder` field is an assertion by the key holder, not cryptographic proof that a named CI workflow actually ran. This project does **not** implement workload identity, OIDC binding, SLSA levels, or keyless signing.
3. **Timestamp authenticity and replay:** A signer supplies the UTC timestamp. Freshness policy limits accepted age but does not prevent replay of a still-valid release or provide an independent timestamp authority. No transparency log or revocation is included.
4. **Incomplete SBOM:** Requirements-based inventories can omit transitive, native or runtime dependencies; license metadata can be inaccurate. This tool does not scan vulnerabilities or establish software safety.
5. **Filesystem races:** Hashing a mutable directory is not an atomic snapshot. Although it checks file identity, size and mtime before/after reading, directory-level races remain possible. Sign immutable build outputs or use snapshotting filesystems.
6. **Trusted policy modification:** Policy is intentionally local and unsigned. An attacker who controls policy or trusted public keys controls acceptance. Keep those files independently managed and access-restricted.
7. **API verification scope:** HTTP endpoint has no release bytes and cannot verify artifact integrity. Its response always sets `release_verified=false`, even when `passed=true`.
8. **Network-facing controls:** The API does not implement TLS, authentication, rate limiting, multitenancy, monitoring or a persistent audit log. Run behind an authenticated, rate-limited reverse proxy if deployed.
9. **Full standards conformance:** Minimal CycloneDX 1.6 output is structurally compatible but has not been independently validated against the complete official schema. The custom in-toto predicate is not a SLSA provenance predicate.
10. **External assurance:** No external penetration test, independent security audit, reproducible build verification, Docker runtime smoke or hosted CI run is claimed in this initial delivery.

## Recommended production hardening

Require a trusted builder identity provider; use immutable build inputs and key custody controls; add independent timestamp/transparency verification and key revocation; generate SBOMs from the actual resolved environment; perform official CycloneDX schema validation; add structured audit events, OIDC identity binding, rate limiting, vulnerability feeds and deployment monitoring; run a third-party security review.
