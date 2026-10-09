from fastapi.testclient import TestClient

from attestforge.api import create_app
from attestforge.util import write_json


def make_client(bundle):
    path = bundle["tmp"] / "policy.json"
    if not path.exists():
        write_json(path, bundle["policy"])
    return TestClient(create_app(trust_dir=bundle["trust"], policy_path=path))


def test_health_and_readiness(bundle):
    client = make_client(bundle)
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").json()["status"] == "ready"


def test_api_envelope_only_scope(bundle):
    client = make_client(bundle)
    result = client.post("/v1/verify-envelope", json={"envelope": bundle["envelope"], "sbom": bundle["sbom"]})
    assert result.status_code == 200
    data = result.json()
    assert data["passed"] is True
    assert data["release_verified"] is False
    assert data["artifact_integrity_checked"] is False


def test_api_denies_tampered_envelope(bundle):
    client = make_client(bundle)
    env = {**bundle["envelope"], "payload": "AAAA"}
    data = client.post("/v1/verify-envelope", json={"envelope": env, "sbom": bundle["sbom"]}).json()
    assert data["passed"] is False


def test_api_rejects_large_payload(bundle):
    client = make_client(bundle)
    result = client.post("/v1/verify-envelope", content=b"a" * (1024 * 1024 + 1), headers={"content-type": "application/json"})
    assert result.status_code == 413


def test_api_rejects_unexpected_fields(bundle):
    client = make_client(bundle)
    result = client.post("/v1/verify-envelope", json={"envelope": bundle["envelope"], "unexpected": True})
    assert result.status_code == 422


def test_api_fails_closed_without_trust(tmp_path):
    client = TestClient(create_app(trust_dir=tmp_path / "missing", policy_path=tmp_path / "missing.json"))
    assert client.get("/readyz").status_code == 503
