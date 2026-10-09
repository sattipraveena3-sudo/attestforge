"""Adversarial and fail-closed regression cases."""

import copy
import os
from datetime import datetime

import pytest

from attestforge.crypto import create_keypair, load_private_key, load_trust_store, verify_envelope
from attestforge.engine import attest_release, validate_statement, verify_release
from attestforge.errors import AttestForgeError
from attestforge.manifest import build_manifest, validate_manifest
from attestforge.policy import validate_policy
from attestforge.sbom import generate_sbom, validate_sbom
from attestforge.util import canonical_json, decode_b64, read_json, strict_json_loads, write_json


def test_duplicate_json_key_rejected():
    with pytest.raises(AttestForgeError) as exc:
        strict_json_loads('{"a":1,"a":2}')
    assert exc.value.code == "DUPLICATE_JSON_KEY"


def test_json_nan_rejected():
    with pytest.raises(AttestForgeError) as exc:
        strict_json_loads('{"a":NaN}')
    assert exc.value.code == "INVALID_JSON"


def test_canonical_json_rejects_nan():
    with pytest.raises(AttestForgeError):
        canonical_json({"x": float("nan")})


def test_read_json_rejects_list(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[]")
    with pytest.raises(AttestForgeError):
        read_json(path)


def test_read_json_rejects_oversize(tmp_path):
    path = tmp_path / "huge.json"
    path.write_text('{"data":"' + "x" * 100 + '"}')
    with pytest.raises(AttestForgeError) as exc:
        read_json(path, max_bytes=20)
    assert exc.value.code == "INPUT_TOO_LARGE"


def test_write_json_refuses_overwrite(tmp_path):
    path = tmp_path / "out.json"
    write_json(path, {"x": 1})
    with pytest.raises(AttestForgeError) as exc:
        write_json(path, {"x": 2})
    assert exc.value.code == "OUTPUT_EXISTS"


def test_decode_b64_rejects_bad_padding():
    with pytest.raises(AttestForgeError):
        decode_b64("a", max_bytes=32)


def test_private_key_permissions_enforced(bundle):
    if os.name != "posix":
        pytest.skip("POSIX mode checks")
    bundle["private"].chmod(0o644)
    with pytest.raises(AttestForgeError) as exc:
        load_private_key(bundle["private"])
    assert exc.value.code == "INSECURE_PRIVATE_KEY"


def test_trust_store_rejects_symlink(bundle):
    (bundle["trust"] / "alias.pem").symlink_to(bundle["public"])
    with pytest.raises(AttestForgeError) as exc:
        load_trust_store(bundle["trust"])
    assert exc.value.code == "INVALID_TRUST_KEY"


def test_keygen_rejects_same_path(tmp_path):
    path = tmp_path / "same.pem"
    with pytest.raises(AttestForgeError):
        create_keypair(path, path)


def test_keygen_rejects_wrong_algorithm(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    path = tmp_path / "rsa.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    with pytest.raises(AttestForgeError) as exc:
        load_private_key(path)
    assert exc.value.code == "INVALID_PRIVATE_KEY"


def test_manifest_rejects_wrong_total(bundle):
    manifest = build_manifest(bundle["release"])
    manifest["totalBytes"] += 1
    with pytest.raises(AttestForgeError):
        validate_manifest(manifest)


def test_manifest_rejects_unsorted(bundle):
    manifest = build_manifest(bundle["release"])
    manifest["files"].reverse()
    with pytest.raises(AttestForgeError):
        validate_manifest(manifest)


def test_manifest_rejects_negative_size(bundle):
    manifest = build_manifest(bundle["release"])
    manifest["files"][0]["size"] = -1
    with pytest.raises(AttestForgeError):
        validate_manifest(manifest)


def test_envelope_rejects_extra_field(bundle):
    envelope = {**bundle["envelope"], "unsigned": True}
    with pytest.raises(AttestForgeError) as exc:
        verify_envelope(envelope, load_trust_store(bundle["trust"]))
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_rejects_missing_signatures(bundle):
    envelope = {**bundle["envelope"], "signatures": []}
    with pytest.raises(AttestForgeError):
        verify_envelope(envelope, load_trust_store(bundle["trust"]))


def test_envelope_rejects_bad_keyid(bundle):
    envelope = copy.deepcopy(bundle["envelope"])
    envelope["signatures"][0]["keyid"] = "fake"
    with pytest.raises(AttestForgeError):
        verify_envelope(envelope, load_trust_store(bundle["trust"]))


def test_signed_manifest_subject_mismatch(bundle):
    statement, _ = verify_envelope(bundle["envelope"], load_trust_store(bundle["trust"]))
    statement["subject"][0]["digest"]["sha256"] = "0" * 64
    with pytest.raises(AttestForgeError) as exc:
        validate_statement(statement)
    assert exc.value.code == "SUBJECT_MISMATCH"


def test_signed_statement_rejects_unexpected_predicate_fields(bundle):
    statement, _ = verify_envelope(bundle["envelope"], load_trust_store(bundle["trust"]))
    statement["predicate"]["surprise"] = "x"
    with pytest.raises(AttestForgeError):
        validate_statement(statement)


def test_attest_refuses_key_inside_artifact(bundle):
    private_copy = bundle["release"] / "secret.pem"
    private_copy.write_bytes(bundle["private"].read_bytes())
    private_copy.chmod(0o600)
    with pytest.raises(AttestForgeError) as exc:
        attest_release(bundle["release"], private_copy, builder="local-demo")
    assert exc.value.code == "KEY_INSIDE_ARTIFACT"


def test_attest_requires_timezone(bundle):
    with pytest.raises(AttestForgeError) as exc:
        attest_release(bundle["release"], bundle["private"], builder="local-demo", created_at=datetime(2026, 1, 1))
    assert exc.value.code == "INVALID_TIMESTAMP"


def test_policy_rejects_no_allowed_builders():
    with pytest.raises(AttestForgeError):
        validate_policy({"allowed_builders": []})


def test_policy_rejects_invalid_numeric_limits():
    with pytest.raises(AttestForgeError):
        validate_policy({"allowed_builders": ["x"], "max_age_hours": 10**9})


def test_policy_rejects_boolean_as_integer():
    with pytest.raises(AttestForgeError):
        validate_policy({"allowed_builders": ["x"], "max_files": True})


def test_sbom_rejects_invalid_licenses(bundle):
    sbom = copy.deepcopy(bundle["sbom"])
    sbom["components"][0]["licenses"] = {"license": "MIT"}
    with pytest.raises(AttestForgeError):
        validate_sbom(sbom)


def test_sbom_rejects_invalid_license_map(bundle):
    with pytest.raises(AttestForgeError):
        generate_sbom(bundle["tmp"] / "requirements.lock", licenses=[])


def test_sbom_rejects_invalid_license_id(bundle):
    with pytest.raises(AttestForgeError):
        generate_sbom(bundle["tmp"] / "requirements.lock", licenses={"fastapi": "not a license"})


def test_policy_rejects_large_artifact(bundle):
    policy = {**bundle["policy"], "max_total_bytes": 1}
    report = verify_release(bundle["envelope"], trust_dir=bundle["trust"], policy=policy, artifact_dir=bundle["release"], sbom=bundle["sbom"])
    assert "ARTIFACT_TOO_LARGE" in report.failures


def test_policy_rejects_many_files(bundle):
    policy = {**bundle["policy"], "max_files": 1}
    report = verify_release(bundle["envelope"], trust_dir=bundle["trust"], policy=policy, artifact_dir=bundle["release"], sbom=bundle["sbom"])
    assert "TOO_MANY_FILES" in report.failures


def test_attest_rejects_empty_builder(bundle):
    with pytest.raises(AttestForgeError) as exc:
        attest_release(bundle["release"], bundle["private"], builder="")
    assert exc.value.code == "INVALID_BUILDER"


def test_statement_rejects_bad_type(bundle):
    statement, _ = verify_envelope(bundle["envelope"], load_trust_store(bundle["trust"]))
    statement["_type"] = "unexpected"
    with pytest.raises(AttestForgeError):
        validate_statement(statement)


def test_statement_rejects_invalid_sbom_binding(bundle):
    statement, _ = verify_envelope(bundle["envelope"], load_trust_store(bundle["trust"]))
    statement["predicate"]["sbom"]["sha256"] = "not-a-hash"
    with pytest.raises(AttestForgeError):
        validate_statement(statement)


def test_statement_rejects_wrong_subject_shape(bundle):
    statement, _ = verify_envelope(bundle["envelope"], load_trust_store(bundle["trust"]))
    statement["subject"] = []
    with pytest.raises(AttestForgeError):
        validate_statement(statement)


def test_policy_rejects_invalid_bool():
    with pytest.raises(AttestForgeError):
        validate_policy({"allowed_builders": ["x"], "require_sbom": "true"})


def test_policy_rejects_invalid_list():
    with pytest.raises(AttestForgeError):
        validate_policy({"allowed_builders": "x"})


def test_sbom_rejects_invalid_component_name(bundle):
    sbom = copy.deepcopy(bundle["sbom"])
    sbom["components"][0]["name"] = ""
    with pytest.raises(AttestForgeError):
        validate_sbom(sbom)


def test_sbom_rejects_invalid_license_entry(bundle):
    sbom = copy.deepcopy(bundle["sbom"])
    sbom["components"][0]["licenses"] = ["MIT"]
    with pytest.raises(AttestForgeError):
        validate_sbom(sbom)


def test_sbom_rejects_invalid_component_ref(bundle):
    sbom = copy.deepcopy(bundle["sbom"])
    sbom["components"][0]["bom-ref"] = 100
    with pytest.raises(AttestForgeError):
        validate_sbom(sbom)


def test_sbom_rejects_invalid_app_name(bundle):
    with pytest.raises(AttestForgeError):
        generate_sbom(bundle["tmp"] / "requirements.lock", app_name="bad app")


def test_missing_policy_file_returns_503(bundle):
    from fastapi.testclient import TestClient
    from attestforge.api import create_app
    client = TestClient(create_app(trust_dir=bundle["trust"], policy_path=bundle["tmp"] / "missing.json"))
    assert client.post("/v1/verify-envelope", json={"envelope": bundle["envelope"]}).status_code == 503


def test_cli_missing_json_returns_error(bundle, capsys):
    from attestforge.cli import run
    rc = run(["verify", "--artifact", str(bundle["release"]), "--envelope", str(bundle["tmp"] / "absent.json"), "--trust-dir", str(bundle["trust"]), "--policy", str(bundle["tmp"] / "absent-policy.json")])
    assert rc == 2
    assert "INVALID_JSON" in capsys.readouterr().err
