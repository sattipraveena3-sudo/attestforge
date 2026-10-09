from datetime import datetime, timedelta, timezone

from attestforge.engine import attest_release, verify_release


def check(bundle, **kwargs):
    params = {
        "trust_dir": bundle["trust"], "policy": bundle["policy"],
        "artifact_dir": bundle["release"], "sbom": bundle["sbom"],
    }
    params.update(kwargs)
    return verify_release(bundle["envelope"], **params)


def test_release_passes(bundle):
    report = check(bundle)
    assert report.passed and report.release_verified
    assert report.artifact_integrity_checked
    assert "artifact_bytes_match_signed_manifest" in report.checks


def test_envelope_only_is_not_release_verification(bundle):
    report = check(bundle, artifact_dir=None)
    assert report.passed
    assert not report.release_verified
    assert not report.artifact_integrity_checked
    assert report.assurance_scope == "envelope-and-policy-only"


def test_tampered_artifact_fails(bundle):
    (bundle["release"] / "app.py").write_text("print('tampered')\n", encoding="utf-8")
    assert "ARTIFACT_MISMATCH" in check(bundle).failures


def test_added_artifact_fails(bundle):
    (bundle["release"] / "extra.txt").write_text("added", encoding="utf-8")
    assert "ARTIFACT_MISMATCH" in check(bundle).failures


def test_deleted_artifact_fails(bundle):
    (bundle["release"] / "README.md").unlink()
    report = check(bundle)
    assert "ARTIFACT_MISMATCH" in report.failures


def test_wrong_sbom_fails(bundle):
    sbom = {**bundle["sbom"], "components": []}
    report = check(bundle, sbom=sbom)
    assert "SBOM_DIGEST_MISMATCH" in report.failures


def test_missing_sbom_fails(bundle):
    report = check(bundle, sbom=None)
    assert "SBOM_MISSING" in report.failures
    assert "SBOM_REQUIRED" in report.failures


def test_unbound_sbom_fails(bundle):
    env = attest_release(bundle["release"], bundle["private"], builder="local-demo")
    report = verify_release(env, trust_dir=bundle["trust"], policy=bundle["policy"], artifact_dir=bundle["release"], sbom=bundle["sbom"])
    assert "UNBOUND_SBOM" in report.failures


def test_builder_policy_fails(bundle):
    policy = {**bundle["policy"], "allowed_builders": ["different-builder"]}
    assert "BUILDER_NOT_ALLOWED" in check(bundle, policy=policy).failures


def test_required_path_fails(bundle):
    policy = {**bundle["policy"], "required_paths": ["missing.txt"]}
    assert "REQUIRED_PATH_MISSING" in check(bundle, policy=policy).failures


def test_forbidden_extension_fails(bundle):
    policy = {**bundle["policy"], "forbidden_extensions": [".py"]}
    assert "FORBIDDEN_EXTENSION" in check(bundle, policy=policy).failures


def test_expired_attestation_fails(bundle):
    old = datetime.now(timezone.utc) - timedelta(days=40)
    env = attest_release(bundle["release"], bundle["private"], builder="local-demo", sbom=bundle["sbom"], created_at=old)
    report = verify_release(env, trust_dir=bundle["trust"], policy=bundle["policy"], artifact_dir=bundle["release"], sbom=bundle["sbom"])
    assert "EXPIRED_ATTESTATION" in report.failures


def test_future_attestation_fails(bundle):
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    env = attest_release(bundle["release"], bundle["private"], builder="local-demo", sbom=bundle["sbom"], created_at=future)
    report = verify_release(env, trust_dir=bundle["trust"], policy=bundle["policy"], artifact_dir=bundle["release"], sbom=bundle["sbom"])
    assert "FUTURE_ATTESTATION" in report.failures


def test_denied_license_fails(bundle):
    sbom = bundle["sbom"].copy()
    sbom["components"] = [dict(c) for c in bundle["sbom"]["components"]]
    sbom["components"][0]["licenses"] = [{"license": {"id": "GPL-3.0-only"}}]
    env = attest_release(bundle["release"], bundle["private"], builder="local-demo", sbom=sbom)
    report = verify_release(env, trust_dir=bundle["trust"], policy=bundle["policy"], artifact_dir=bundle["release"], sbom=sbom)
    assert "DENIED_LICENSE" in report.failures


def test_missing_license_fails(bundle):
    sbom = bundle["sbom"].copy()
    sbom["components"] = [dict(c) for c in bundle["sbom"]["components"]]
    sbom["components"][0].pop("licenses")
    env = attest_release(bundle["release"], bundle["private"], builder="local-demo", sbom=sbom)
    report = verify_release(env, trust_dir=bundle["trust"], policy=bundle["policy"], artifact_dir=bundle["release"], sbom=sbom)
    assert "UNKNOWN_LICENSE" in report.failures


def test_invalid_policy_fails_closed(bundle):
    policy = {**bundle["policy"], "accept_all": True}
    assert "INVALID_POLICY" in check(bundle, policy=policy).failures


def test_subject_digest_cannot_be_modified_without_signature(bundle):
    import base64
    import json
    import copy
    env = copy.deepcopy(bundle["envelope"])
    statement = json.loads(base64.b64decode(env["payload"]))
    statement["subject"][0]["digest"]["sha256"] = "0" * 64
    env["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    report = verify_release(env, trust_dir=bundle["trust"], policy=bundle["policy"], artifact_dir=bundle["release"], sbom=bundle["sbom"])
    assert "SIGNATURE_UNTRUSTED" in report.failures
