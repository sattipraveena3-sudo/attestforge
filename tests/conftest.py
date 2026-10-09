from __future__ import annotations

from pathlib import Path

import pytest

from attestforge.crypto import create_keypair
from attestforge.engine import attest_release
from attestforge.sbom import generate_sbom


@pytest.fixture
def bundle(tmp_path: Path):
    release = tmp_path / "release"
    release.mkdir()
    (release / "app.py").write_text("print('hello world')\n", encoding="utf-8")
    (release / "README.md").write_text("# Release\n", encoding="utf-8")
    trust = tmp_path / "trust"
    trust.mkdir()
    private = tmp_path / "secret.pem"
    public = trust / "release.pem"
    create_keypair(private, public)
    reqs = tmp_path / "requirements.lock"
    reqs.write_text("cryptography==46.0.4\nfastapi==0.128.2\n", encoding="utf-8")
    sbom = generate_sbom(reqs, app_name="example", licenses={"cryptography": "Apache-2.0", "fastapi": "MIT"})
    policy = {
        "allowed_builders": ["local-demo"], "require_sbom": True,
        "require_component_licenses": True, "denied_licenses": ["GPL-3.0-only"],
        "required_paths": ["app.py", "README.md"], "forbidden_extensions": [".pem", ".env"],
    }
    envelope = attest_release(release, private, builder="local-demo", sbom=sbom)
    return {
        "tmp": tmp_path, "release": release, "trust": trust, "private": private,
        "public": public, "sbom": sbom, "policy": policy, "envelope": envelope,
    }
