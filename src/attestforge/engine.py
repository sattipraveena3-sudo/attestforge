"""Release attestations and independent verification with explicit assurance scope."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import (
    PREDICATE_TYPE, STATEMENT_TYPE, load_private_key, load_trust_store,
    sign_statement, verify_envelope,
)
from .errors import AttestForgeError
from .manifest import ManifestLimits, build_manifest, manifest_digest, validate_manifest
from .policy import check_policy
from .sbom import sbom_digest
from .util import contained_within


@dataclass(frozen=True)
class VerificationReport:
    passed: bool
    release_verified: bool
    artifact_integrity_checked: bool
    assurance_scope: str
    signer_keyids: list[str]
    artifact_sha256: str | None
    failures: list[str]
    checks: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def attest_release(
    artifact_dir: Path, private_key_path: Path, *, builder: str,
    sbom: dict[str, Any] | None = None,
    limits: ManifestLimits | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(builder, str) or not builder or len(builder) > 500:
        raise AttestForgeError("INVALID_BUILDER", "Builder identity must be nonempty")
    if contained_within(private_key_path, artifact_dir):
        raise AttestForgeError("KEY_INSIDE_ARTIFACT", "Signing key must be outside artifact root")
    manifest = build_manifest(artifact_dir, limits or ManifestLimits())
    digest = manifest_digest(manifest)
    sbom_info = None
    if sbom is not None:
        sbom_info = {"sha256": sbom_digest(sbom), "componentCount": len(sbom.get("components", []))}
    when = created_at or datetime.now(timezone.utc)
    if when.tzinfo is None:
        raise AttestForgeError("INVALID_TIMESTAMP", "Attestation timestamp requires a timezone")
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "release", "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "builder": builder,
            "createdAt": when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "manifest": manifest,
            "sbom": sbom_info,
        },
    }
    return sign_statement(statement, load_private_key(private_key_path))


def validate_statement(statement: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise AttestForgeError("INVALID_STATEMENT", "Unexpected statement fields")
    if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATE_TYPE:
        raise AttestForgeError("INVALID_STATEMENT", "Unsupported statement or predicate type")
    subject = statement["subject"]
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        raise AttestForgeError("INVALID_STATEMENT", "Exactly one release subject is required")
    predicate = statement["predicate"]
    if not isinstance(predicate, dict) or set(predicate) != {"builder", "createdAt", "manifest", "sbom"}:
        raise AttestForgeError("INVALID_STATEMENT", "Invalid release predicate")
    if not isinstance(predicate["builder"], str) or not predicate["builder"] or len(predicate["builder"]) > 500:
        raise AttestForgeError("INVALID_STATEMENT", "Invalid builder identity")
    if not isinstance(predicate["createdAt"], str) or len(predicate["createdAt"]) > 64:
        raise AttestForgeError("INVALID_STATEMENT", "Invalid creation timestamp")
    validate_manifest(predicate["manifest"])
    digest = manifest_digest(predicate["manifest"])
    if subject[0] != {"name": "release", "digest": {"sha256": digest}}:
        raise AttestForgeError("SUBJECT_MISMATCH", "Subject digest does not bind the signed manifest")
    sbom_info = predicate["sbom"]
    if sbom_info is not None:
        if (
            not isinstance(sbom_info, dict)
            or set(sbom_info) != {"sha256", "componentCount"}
            or not isinstance(sbom_info["sha256"], str)
            or len(sbom_info["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in sbom_info["sha256"])
            or type(sbom_info["componentCount"]) is not int
            or not 0 <= sbom_info["componentCount"] <= 10_000
        ):
            raise AttestForgeError("INVALID_STATEMENT", "Invalid SBOM binding")
    return predicate, digest


def verify_release(
    envelope: dict[str, Any], *, trust_dir: Path, policy: dict[str, Any],
    artifact_dir: Path | None = None, sbom: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> VerificationReport:
    checks: list[str] = []
    failures: list[str] = []
    signer_ids: list[str] = []
    digest: str | None = None
    integrity_checked = False
    try:
        trusted = load_trust_store(trust_dir)
        statement, signer_ids = verify_envelope(envelope, trusted)
        checks.append("trusted_ed25519_dsse_signature")
        predicate, digest = validate_statement(statement)
        checks.append("in_toto_statement_and_manifest_binding")
        signed_sbom = predicate["sbom"]
        if signed_sbom is None and sbom is not None:
            failures.append("UNBOUND_SBOM")
        elif signed_sbom is not None:
            if sbom is None:
                failures.append("SBOM_MISSING")
            elif signed_sbom != {"sha256": sbom_digest(sbom), "componentCount": len(sbom.get("components", []))}:
                failures.append("SBOM_DIGEST_MISMATCH")
            else:
                checks.append("sbom_digest_bound_to_signature")
        if artifact_dir is not None:
            actual = build_manifest(artifact_dir)
            integrity_checked = True
            if actual != predicate["manifest"]:
                failures.append("ARTIFACT_MISMATCH")
            else:
                checks.append("artifact_bytes_match_signed_manifest")
        failures.extend(check_policy(policy, statement, sbom, now=now))
        if not failures:
            checks.append("release_policy_passed")
    except AttestForgeError as exc:
        failures.append(exc.code)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        failures.append("INVALID_INPUT")
    failures = sorted(set(failures))
    passed = not failures
    return VerificationReport(
        passed=passed,
        release_verified=passed and integrity_checked,
        artifact_integrity_checked=integrity_checked,
        assurance_scope="full-artifact" if artifact_dir is not None else "envelope-and-policy-only",
        signer_keyids=signer_ids,
        artifact_sha256=digest,
        failures=failures,
        checks=checks,
    )
