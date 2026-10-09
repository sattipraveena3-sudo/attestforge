"""Fail-closed, bounded, deterministic release artifact inventory."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import AttestForgeError
from .util import canonical_json, sha256_bytes

EXCLUDED_TOP_LEVEL = {".git"}


@dataclass(frozen=True)
class ManifestLimits:
    max_files: int = 10_000
    max_total_bytes: int = 1_073_741_824
    max_file_bytes: int = 134_217_728


def validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict) or set(manifest) != {"version", "files", "totalBytes"}:
        raise AttestForgeError("INVALID_MANIFEST", "Manifest structure is invalid")
    if manifest["version"] != 1 or not isinstance(manifest["files"], list):
        raise AttestForgeError("INVALID_MANIFEST", "Unsupported manifest version")
    if len(manifest["files"]) > 10_000:
        raise AttestForgeError("INVALID_MANIFEST", "Manifest has too many files")
    seen: set[str] = set()
    total = 0
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise AttestForgeError("INVALID_MANIFEST", "Malformed file entry")
        path = entry["path"]
        if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
            raise AttestForgeError("INVALID_MANIFEST", "Unsafe file path")
        parsed = PurePosixPath(path)
        if (
            parsed.is_absolute()
            or any(part in (".", "..", "") for part in path.split("/"))
            or parsed.as_posix() != path
            or path.split("/")[0] in EXCLUDED_TOP_LEVEL
        ):
            raise AttestForgeError("INVALID_MANIFEST", "Unsafe or excluded file path")
        if path in seen:
            raise AttestForgeError("INVALID_MANIFEST", "Duplicate file path")
        seen.add(path)
        size = entry["size"]
        digest = entry["sha256"]
        if type(size) is not int or size < 0 or size > 1_073_741_824:
            raise AttestForgeError("INVALID_MANIFEST", "Invalid file size")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise AttestForgeError("INVALID_MANIFEST", "Invalid SHA-256 digest")
        total += size
    if type(manifest["totalBytes"]) is not int or manifest["totalBytes"] != total:
        raise AttestForgeError("INVALID_MANIFEST", "Incorrect total byte count")
    if [entry["path"] for entry in manifest["files"]] != sorted(seen):
        raise AttestForgeError("INVALID_MANIFEST", "File list must be sorted")


def build_manifest(root: Path, limits: ManifestLimits | None = None) -> dict[str, Any]:
    limits = limits or ManifestLimits()
    if root.is_symlink() or not root.is_dir():
        raise AttestForgeError("INVALID_ROOT", "Artifact root must be a real directory")
    root = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    total = 0
    def walk_error(error: OSError) -> None:
        raise AttestForgeError("FILE_READ_FAILED", "Unable to traverse artifact directory") from error

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        current_path = Path(current)
        for dirname in dirs:
            target = current_path / dirname
            if target.is_symlink():
                raise AttestForgeError("SYMLINK_REJECTED", "Symlinked directories are not allowed")
        if current_path == root:
            dirs[:] = [name for name in dirs if name not in EXCLUDED_TOP_LEVEL]
        dirs.sort()
        for name in sorted(files):
            target = current_path / name
            if target.is_symlink():
                raise AttestForgeError("SYMLINK_REJECTED", "Symlinked files are not allowed")
            try:
                before = target.stat(follow_symlinks=False)
            except OSError as exc:
                raise AttestForgeError("FILE_READ_FAILED", "Unable to inspect artifact file") from exc
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise AttestForgeError("SPECIAL_FILE_REJECTED", "Only regular, non-hardlinked files are allowed")
            if before.st_size > limits.max_file_bytes:
                raise AttestForgeError("FILE_LIMIT", "File size exceeds the configured limit")
            total += before.st_size
            if total > limits.max_total_bytes or len(entries) >= limits.max_files:
                raise AttestForgeError("MANIFEST_LIMIT", "Artifact inventory exceeds limits")
            digest = hashlib.sha256()
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(target, flags)
                with os.fdopen(fd, "rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
            except OSError as exc:
                raise AttestForgeError("FILE_READ_FAILED", "Unable to hash artifact file") from exc
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise AttestForgeError("ARTIFACT_CHANGED", "Artifact changed while hashing")
            entries.append({"path": target.relative_to(root).as_posix(), "size": before.st_size, "sha256": digest.hexdigest()})
    entries.sort(key=lambda item: item["path"])
    manifest = {"version": 1, "files": entries, "totalBytes": total}
    validate_manifest(manifest)
    return manifest


def manifest_digest(manifest: dict[str, Any]) -> str:
    validate_manifest(manifest)
    return sha256_bytes(canonical_json(manifest))
