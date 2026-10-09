"""Minimal, deterministic CycloneDX 1.6 JSON for pinned Python dependencies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import AttestForgeError
from .util import canonical_json, sha256_bytes

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
LICENSE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def generate_sbom(requirements: Path, *, app_name: str = "release", licenses: dict[str, str] | None = None) -> dict[str, Any]:
    if not NAME.fullmatch(app_name):
        raise AttestForgeError("INVALID_COMPONENT", "Invalid application name")
    try:
        lines = requirements.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AttestForgeError("REQUIREMENTS_READ_FAILED", "Unable to read requirements") from exc
    if len(lines) > 10_000:
        raise AttestForgeError("INPUT_TOO_LARGE", "Too many requirements")
    if licenses is not None and not isinstance(licenses, dict):
        raise AttestForgeError("INVALID_LICENSE", "License map must be a JSON object")
    licenses = {normalized_name(k): v for k, v in (licenses or {}).items()}
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1:
            raise AttestForgeError("UNPINNED_DEPENDENCY", "Only exact package==version pins are supported")
        name, version = (part.strip() for part in line.split("=="))
        if not NAME.fullmatch(name) or not VERSION.fullmatch(version):
            raise AttestForgeError("INVALID_COMPONENT", "Unsupported requirement format")
        name = normalized_name(name)
        if name in seen:
            raise AttestForgeError("DUPLICATE_COMPONENT", "Duplicate dependency")
        seen.add(name)
        purl = f"pkg:pypi/{name}@{version}"
        component: dict[str, Any] = {
            "type": "library", "name": name, "version": version, "bom-ref": purl, "purl": purl
        }
        license_id = licenses.get(name)
        if license_id is not None:
            if not isinstance(license_id, str) or not LICENSE.fullmatch(license_id):
                raise AttestForgeError("INVALID_LICENSE", "License must be an SPDX identifier")
            component["licenses"] = [{"license": {"id": license_id}}]
        components.append(component)
    components.sort(key=lambda c: (c["name"], c["version"]))
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": app_name}},
        "components": components,
    }


def validate_sbom(sbom: Any) -> list[dict[str, Any]]:
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        raise AttestForgeError("INVALID_SBOM", "Only CycloneDX JSON 1.6 is supported")
    components = sbom.get("components", [])
    if not isinstance(components, list) or len(components) > 10_000:
        raise AttestForgeError("INVALID_SBOM", "Invalid component inventory")
    refs: set[str] = set()
    for comp in components:
        if not isinstance(comp, dict) or not isinstance(comp.get("name"), str) or not comp["name"]:
            raise AttestForgeError("INVALID_SBOM", "Invalid component")
        if not isinstance(comp.get("version"), str) or not comp["version"]:
            raise AttestForgeError("INVALID_SBOM", "Unversioned component")
        ref = comp.get("bom-ref")
        if ref is not None:
            if not isinstance(ref, str) or ref in refs:
                raise AttestForgeError("INVALID_SBOM", "Duplicate or invalid component reference")
            refs.add(ref)
        declared = comp.get("licenses", [])
        if not isinstance(declared, list):
            raise AttestForgeError("INVALID_SBOM", "Licenses must be a list")
        for item in declared:
            if not isinstance(item, dict) or not isinstance(item.get("license"), dict):
                raise AttestForgeError("INVALID_SBOM", "Malformed component license")
            license_id = item["license"].get("id")
            if not isinstance(license_id, str) or not LICENSE.fullmatch(license_id):
                raise AttestForgeError("INVALID_SBOM", "License must have an SPDX identifier")
    return components


def sbom_digest(sbom: dict[str, Any]) -> str:
    validate_sbom(sbom)
    return sha256_bytes(canonical_json(sbom))
