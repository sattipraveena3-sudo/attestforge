# Validation Report — 9 October 2026

## Verified locally

- **Automated tests:** **100 passed**, **0 failed**, using `PYTHONPATH=src pytest -q --cov=attestforge --cov-branch --cov-report=term`.
- **Branch-aware combined coverage:** **90.71%**, above the repository's configured 90% minimum.
- **CLI smoke:** Passed both a valid signed release and a negative control with a modified release file. The negative control returned a nonzero exit status and `ARTIFACT_MISMATCH`.
- **Package install:** Editable installation succeeded using `python -m pip install --no-build-isolation --no-deps -e .` against already available dependencies; the installed `attestforge` command responded to `--help`.
- **Compilation:** `python -m compileall -q src` succeeded.
- **Configuration parsing:** `pyproject.toml`, `compose.yaml`, and the CI workflow parsed successfully.
- **Runtime used for local tests:** Python 3.13.5, `cryptography` 46.0.4, FastAPI 0.128.2, pytest 9.0.2.
- **Test categories:** manifest determinism and limits; symlink/hardlink rejection; signed-envelope and signature tampering; trusted key enforcement; malformed JSON; SBOM binding; builder, timestamp, path, license and size policies; full versus envelope-only assurance scope; CLI end-to-end; API readiness, input validation and size limits.

### Coverage snapshot

| Module | Approx. coverage |
|---|---:|
| API | 93% |
| CLI | 93% |
| Cryptography | 85% |
| Verification engine | 94% |
| Manifest | 88% |
| Policy | 97% |
| SBOM | 89% |
| JSON utilities | 95% |
| **Total, including branches** | **90.71%** |

## Not verified in this delivery environment

- GitHub repository creation, hosted GitHub Actions execution, branch protections and release tag.
- Docker image build and container smoke, because the local runtime does not provide a Docker daemon.
- Ruff lint execution, because Ruff was not installed and the local environment could not download it. The workflow config includes Ruff and will run it on GitHub Actions.
- Official CycloneDX schema validation, independent DSSE interoperability testing, external penetration testing, package publication, end-user adoption or commercial integration.

## Evidence integrity

Do **not** describe the unexecuted checks as passed. The `README.md` CI badge is a future repository link; it is not evidence of a green workflow until the project is published and CI actually runs. This report is a local engineering validation record, **not an independent audit or a Global Talent endorsement decision**.

## Reproduction

```bash
python -m pip install -e '.[dev]'
pytest -q --cov=attestforge --cov-branch --cov-report=term-missing
bash scripts/smoke.sh
```
