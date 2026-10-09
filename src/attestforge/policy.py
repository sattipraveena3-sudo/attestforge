"""Strict release policy evaluation. Policies are local trusted inputs, not signed claims."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .errors import AttestForgeError
from .manifest import validate_manifest
from .sbom import validate_sbom

ALLOWED_FIELDS = {
    "allowed_builders", "max_age_hours", "max_future_skew_seconds", "max_files",
    "max_total_bytes", "require_sbom", "require_component_licenses", "denied_licenses",
    "required_paths", "forbidden_extensions",
}


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) - ALLOWED_FIELDS:
        raise AttestForgeError("INVALID_POLICY", "Unknown policy fields")
    result = {
        "allowed_builders": [], "max_age_hours": 720, "max_future_skew_seconds": 300,
        "max_files": 10_000, "max_total_bytes": 1_073_741_824,
        "require_sbom": True, "require_component_licenses": False,
        "denied_licenses": [], "required_paths": [], "forbidden_extensions": [],
    }
    result.update(policy)
    for name in ("allowed_builders", "denied_licenses", "required_paths", "forbidden_extensions"):
        if not isinstance(result[name], list) or len(result[name]) > 1_000 or any(
            not isinstance(v, str) or not v or len(v) > 500 for v in result[name]
        ):
            raise AttestForgeError("INVALID_POLICY", f"Invalid {name}")
    numeric_limits = {"max_age_hours": 24 * 365 * 10, "max_future_skew_seconds": 86_400,
                      "max_files": 10_000, "max_total_bytes": 1_073_741_824}
    for name, upper in numeric_limits.items():
        if type(result[name]) is not int or result[name] < 0 or result[name] > upper:
            raise AttestForgeError("INVALID_POLICY", f"Invalid {name}")
    for name in ("require_sbom", "require_component_licenses"):
        if type(result[name]) is not bool:
            raise AttestForgeError("INVALID_POLICY", f"Invalid {name}")
    if not result["allowed_builders"]:
        raise AttestForgeError("INVALID_POLICY", "At least one allowed builder is required")
    return result


def check_policy(
    policy: dict[str, Any], statement: dict[str, Any],
    sbom: dict[str, Any] | None, *, now: datetime | None = None
) -> list[str]:
    rules = validate_policy(policy)
    failures: list[str] = []
    predicate = statement["predicate"]
    builder = predicate["builder"]
    if builder not in rules["allowed_builders"]:
        failures.append("BUILDER_NOT_ALLOWED")
    try:
        created = datetime.fromisoformat(predicate["createdAt"].replace("Z", "+00:00"))
        if created.tzinfo is None:
            raise ValueError("Timezone missing")
        created = created.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        failures.append("INVALID_TIMESTAMP")
    else:
        now = now or datetime.now(timezone.utc)
        if created > now + timedelta(seconds=rules["max_future_skew_seconds"]):
            failures.append("FUTURE_ATTESTATION")
        if created < now - timedelta(hours=rules["max_age_hours"]):
            failures.append("EXPIRED_ATTESTATION")
    manifest = predicate["manifest"]
    validate_manifest(manifest)
    if len(manifest["files"]) > rules["max_files"]:
        failures.append("TOO_MANY_FILES")
    if manifest["totalBytes"] > rules["max_total_bytes"]:
        failures.append("ARTIFACT_TOO_LARGE")
    paths = {item["path"] for item in manifest["files"]}
    for required in rules["required_paths"]:
        if required not in paths:
            failures.append("REQUIRED_PATH_MISSING")
    for path in paths:
        if any(path.lower().endswith(ext.lower()) for ext in rules["forbidden_extensions"]):
            failures.append("FORBIDDEN_EXTENSION")
            break
    if rules["require_sbom"] and sbom is None:
        failures.append("SBOM_REQUIRED")
    if sbom is not None:
        components = validate_sbom(sbom)
        denied = set(rules["denied_licenses"])
        for component in components:
            ids = {
                entry["license"]["id"]
                for entry in component.get("licenses", [])
            }
            if rules["require_component_licenses"] and not ids:
                failures.append("UNKNOWN_LICENSE")
            if ids & denied:
                failures.append("DENIED_LICENSE")
    return sorted(set(failures))
