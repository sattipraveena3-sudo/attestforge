"""Ed25519 DSSE signing and offline verification against a local trust store."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import AttestForgeError
from .util import MAX_ENVELOPE_BYTES, canonical_json, decode_b64, strict_json_loads

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://attestforge.dev/predicate/release/v1"


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(payload)).encode() + b" " + payload


def key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def create_keypair(private_path: Path, public_path: Path) -> str:
    if private_path.resolve() == public_path.resolve() or private_path.exists() or public_path.exists():
        raise AttestForgeError("OUTPUT_EXISTS", "Refusing to overwrite existing key material")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # O_EXCL and 0600 prevent accidentally exposing a private key via overwrite/race.
    import os

    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    public_created = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(private_pem)
        with public_path.open("xb") as stream:
            public_created = True
            stream.write(public_pem)
    except Exception:
        private_path.unlink(missing_ok=True)
        if public_created:
            public_path.unlink(missing_ok=True)
        raise
    return key_id(private_key.public_key())


def load_private_key(path: Path) -> Ed25519PrivateKey:
    import os

    if os.name == "posix" and path.exists() and (path.stat().st_mode & 0o077):
        raise AttestForgeError("INSECURE_PRIVATE_KEY", "Private key must not be readable by group or others")
    try:
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise AttestForgeError("INVALID_PRIVATE_KEY", "Unable to load Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AttestForgeError("INVALID_PRIVATE_KEY", "Signing key must use Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        data = path.read_bytes()
        key = serialization.load_pem_public_key(data)
    except (OSError, ValueError, TypeError) as exc:
        raise AttestForgeError("INVALID_TRUST_KEY", "Unable to load trusted Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AttestForgeError("INVALID_TRUST_KEY", "Trusted key must use Ed25519")
    return key


def load_trust_store(directory: Path) -> dict[str, Ed25519PublicKey]:
    if not directory.is_dir() or directory.is_symlink():
        raise AttestForgeError("TRUST_STORE_MISSING", "Trust store must be a real directory")
    keys: dict[str, Ed25519PublicKey] = {}
    paths = sorted(directory.glob("*.pem"))
    if not paths or len(paths) > 64:
        raise AttestForgeError("TRUST_STORE_EMPTY", "Trust store must contain 1–64 public PEM keys")
    for path in paths:
        if path.is_symlink():
            raise AttestForgeError("INVALID_TRUST_KEY", "Symlinked trust keys are not allowed")
        key = load_public_key(path)
        kid = key_id(key)
        if kid in keys:
            raise AttestForgeError("INVALID_TRUST_KEY", "Duplicate trusted public key")
        keys[kid] = key
    return keys


def sign_statement(statement: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonical_json(statement)
    signature = private_key.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": key_id(private_key.public_key()), "sig": base64.b64encode(signature).decode("ascii")}
        ],
    }


def verify_envelope(envelope: dict[str, Any], trusted: dict[str, Ed25519PublicKey]) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"}:
        raise AttestForgeError("INVALID_ENVELOPE", "Invalid DSSE envelope structure")
    if envelope["payloadType"] != PAYLOAD_TYPE:
        raise AttestForgeError("INVALID_ENVELOPE", "Unsupported payload type")
    payload = decode_b64(envelope["payload"], max_bytes=MAX_ENVELOPE_BYTES)
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= 8:
        raise AttestForgeError("INVALID_ENVELOPE", "Expected 1–8 signatures")
    verified: list[str] = []
    seen: set[str] = set()
    for entry in signatures:
        if not isinstance(entry, dict) or set(entry) != {"keyid", "sig"}:
            raise AttestForgeError("INVALID_ENVELOPE", "Malformed signature entry")
        kid = entry["keyid"]
        if not isinstance(kid, str) or len(kid) != 64 or any(c not in "0123456789abcdef" for c in kid):
            raise AttestForgeError("INVALID_ENVELOPE", "Malformed key ID")
        if kid in seen:
            raise AttestForgeError("INVALID_ENVELOPE", "Duplicate signature key ID")
        seen.add(kid)
        sig = decode_b64(entry["sig"], max_bytes=64)
        if len(sig) != 64:
            raise AttestForgeError("INVALID_ENVELOPE", "Incorrect Ed25519 signature size")
        key = trusted.get(kid)
        if key is None:
            continue
        try:
            key.verify(sig, pae(PAYLOAD_TYPE, payload))
        except InvalidSignature:
            continue
        verified.append(kid)
    if not verified:
        raise AttestForgeError("SIGNATURE_UNTRUSTED", "No valid signature from a trusted key")
    try:
        statement = strict_json_loads(payload)
    except AttestForgeError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AttestForgeError("INVALID_STATEMENT", "Signed payload is not valid JSON") from exc
    if not isinstance(statement, dict):
        raise AttestForgeError("INVALID_STATEMENT", "Signed statement must be an object")
    return statement, verified
