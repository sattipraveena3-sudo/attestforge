"""Canonical JSON, bounded decoding, and filesystem helpers."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .errors import AttestForgeError

MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
MAX_SBOM_BYTES = 4 * 1024 * 1024


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AttestForgeError("INVALID_JSON", "Value cannot be canonically serialized") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json_loads(data: bytes | str) -> Any:
    """Reject duplicate object keys rather than silently accepting last-value-wins."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AttestForgeError("DUPLICATE_JSON_KEY", "Duplicate JSON object key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(
        AttestForgeError("INVALID_JSON", "Non-finite JSON number")
    ))


def read_json(path: Path, *, max_bytes: int = MAX_SBOM_BYTES) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise AttestForgeError("INPUT_TOO_LARGE", f"JSON input exceeds {max_bytes} bytes")
        obj = strict_json_loads(data)
    except AttestForgeError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise AttestForgeError("INVALID_JSON", f"Cannot read JSON from {path.name}") from exc
    if not isinstance(obj, dict):
        raise AttestForgeError("INVALID_JSON", "Top-level JSON value must be an object")
    return obj


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise AttestForgeError("OUTPUT_EXISTS", f"Refusing to overwrite {path.name}")
    path.write_bytes(canonical_json(value) + b"\n")


def decode_b64(value: str, *, max_bytes: int) -> bytes:
    if not isinstance(value, str) or len(value) > (max_bytes * 4 // 3 + 8):
        raise AttestForgeError("INVALID_BASE64", "Invalid or oversized base64 field")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AttestForgeError("INVALID_BASE64", "Malformed base64 field") from exc
    if len(decoded) > max_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise AttestForgeError("INVALID_BASE64", "Non-canonical or oversized base64 field")
    return decoded


def contained_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
