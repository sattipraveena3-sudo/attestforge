import json

from attestforge.cli import run


def test_cli_end_to_end(tmp_path, capsys):
    release = tmp_path / "release"
    release.mkdir()
    (release / "app.py").write_text("print(1)\n", encoding="utf-8")
    trust = tmp_path / "trust"
    trust.mkdir()
    private = tmp_path / "private.pem"
    public = trust / "public.pem"
    assert run(["keygen", "--private", str(private), "--public", str(public)]) == 0
    req = tmp_path / "requirements.lock"
    req.write_text("fastapi==0.128.2\n", encoding="utf-8")
    sbom = tmp_path / "sbom.json"
    assert run(["sbom", "--requirements", str(req), "--out", str(sbom)]) == 0
    env = tmp_path / "envelope.json"
    assert run(["attest", "--artifact", str(release), "--private", str(private), "--builder", "local-demo", "--sbom", str(sbom), "--out", str(env)]) == 0
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"allowed_builders": ["local-demo"], "require_sbom": True}))
    args = ["verify", "--artifact", str(release), "--envelope", str(env), "--trust-dir", str(trust), "--policy", str(policy), "--sbom", str(sbom)]
    assert run(args) == 0
    assert "release_verified" in capsys.readouterr().out
    (release / "app.py").write_text("tampered\n", encoding="utf-8")
    assert run(args) == 2


def test_cli_refuses_attestation_inside_artifact(bundle):
    assert run([
        "attest", "--artifact", str(bundle["release"]), "--private", str(bundle["private"]),
        "--builder", "local-demo", "--out", str(bundle["release"] / "envelope.json"),
    ]) == 2
