import os

import pytest

from attestforge.errors import AttestForgeError
from attestforge.manifest import ManifestLimits, build_manifest, manifest_digest, validate_manifest


def test_manifest_is_deterministic(bundle):
    one = build_manifest(bundle["release"])
    two = build_manifest(bundle["release"])
    assert one == two
    assert manifest_digest(one) == manifest_digest(two)
    assert [item["path"] for item in one["files"]] == ["README.md", "app.py"]


def test_manifest_rejects_file_symlink(bundle):
    (bundle["release"] / "link").symlink_to(bundle["release"] / "app.py")
    with pytest.raises(AttestForgeError, match="Symlink"):
        build_manifest(bundle["release"])


def test_manifest_rejects_directory_symlink(bundle):
    (bundle["release"] / "linkdir").symlink_to(bundle["tmp"], target_is_directory=True)
    with pytest.raises(AttestForgeError) as exc:
        build_manifest(bundle["release"])
    assert exc.value.code == "SYMLINK_REJECTED"


def test_manifest_rejects_root_symlink(bundle):
    link = bundle["tmp"] / "release-link"
    link.symlink_to(bundle["release"], target_is_directory=True)
    with pytest.raises(AttestForgeError) as exc:
        build_manifest(link)
    assert exc.value.code == "INVALID_ROOT"


def test_manifest_rejects_hardlinks(bundle):
    os.link(bundle["release"] / "app.py", bundle["release"] / "hardlink.py")
    with pytest.raises(AttestForgeError) as exc:
        build_manifest(bundle["release"])
    assert exc.value.code == "SPECIAL_FILE_REJECTED"


def test_manifest_rejects_file_limit(bundle):
    with pytest.raises(AttestForgeError) as exc:
        build_manifest(bundle["release"], ManifestLimits(max_files=1))
    assert exc.value.code == "MANIFEST_LIMIT"


def test_manifest_rejects_size_limit(bundle):
    with pytest.raises(AttestForgeError) as exc:
        build_manifest(bundle["release"], ManifestLimits(max_file_bytes=1))
    assert exc.value.code == "FILE_LIMIT"


def test_manifest_rejects_total_limit(bundle):
    with pytest.raises(AttestForgeError) as exc:
        build_manifest(bundle["release"], ManifestLimits(max_total_bytes=1))
    assert exc.value.code == "MANIFEST_LIMIT"


@pytest.mark.parametrize("bad_path", ["../escape", "/absolute", "dir/../file", "./file", "a\\b", "a//b", ".git/secret"])
def test_manifest_rejects_unsafe_paths(bad_path):
    manifest = {"version": 1, "files": [{"path": bad_path, "size": 1, "sha256": "0" * 64}], "totalBytes": 1}
    with pytest.raises(AttestForgeError) as exc:
        validate_manifest(manifest)
    assert exc.value.code == "INVALID_MANIFEST"


def test_manifest_rejects_duplicate_paths():
    item = {"path": "x", "size": 1, "sha256": "0" * 64}
    with pytest.raises(AttestForgeError):
        validate_manifest({"version": 1, "files": [item, item], "totalBytes": 2})


def test_git_metadata_not_included(bundle):
    git = bundle["release"] / ".git"
    git.mkdir()
    (git / "config").write_text("secret", encoding="utf-8")
    assert len(build_manifest(bundle["release"])["files"]) == 2
