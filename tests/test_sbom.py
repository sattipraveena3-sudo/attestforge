
import pytest

from attestforge.errors import AttestForgeError
from attestforge.sbom import generate_sbom, sbom_digest, validate_sbom


def test_pinned_sbom_is_deterministic(bundle):
    requirements = bundle["tmp"] / "requirements.lock"
    a = generate_sbom(requirements)
    b = generate_sbom(requirements)
    assert a == b
    assert sbom_digest(a) == sbom_digest(b)
    assert a["bomFormat"] == "CycloneDX"
    assert a["specVersion"] == "1.6"


def test_unpinned_dependency_rejected(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi>=0.115\n", encoding="utf-8")
    with pytest.raises(AttestForgeError) as exc:
        generate_sbom(req)
    assert exc.value.code == "UNPINNED_DEPENDENCY"


def test_duplicate_dependency_rejected(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("Fast_API==1.0\nfast-api==1.0\n", encoding="utf-8")
    with pytest.raises(AttestForgeError) as exc:
        generate_sbom(req)
    assert exc.value.code == "DUPLICATE_COMPONENT"


def test_component_without_version_rejected():
    with pytest.raises(AttestForgeError):
        validate_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "x"}]})


def test_wrong_sbom_version_rejected(bundle):
    with pytest.raises(AttestForgeError):
        validate_sbom({**bundle["sbom"], "specVersion": "1.7"})


def test_duplicate_component_reference_rejected(bundle):
    c = bundle["sbom"]["components"][0]
    with pytest.raises(AttestForgeError):
        validate_sbom({**bundle["sbom"], "components": [c, c]})
