#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/trust"
python -m attestforge keygen --private "$TMP/private.pem" --public "$TMP/trust/release.pem"
python -m attestforge sbom --requirements examples/requirements.lock --licenses examples/licenses.json --app-name demo --out "$TMP/sbom.json"
python -m attestforge attest --artifact examples/demo_release --private "$TMP/private.pem" --builder local-demo --sbom "$TMP/sbom.json" --out "$TMP/release.dsse.json"
python -m attestforge verify --artifact examples/demo_release --envelope "$TMP/release.dsse.json" --trust-dir "$TMP/trust" --policy examples/policy.json --sbom "$TMP/sbom.json" | python -c 'import json,sys; d=json.load(sys.stdin); assert d["release_verified"] and d["passed"]'
# Negative control: a modified copy must fail with a nonzero exit status.
cp -R examples/demo_release "$TMP/changed"
printf '\n# tampered\n' >> "$TMP/changed/hello.py"
if python -m attestforge verify --artifact "$TMP/changed" --envelope "$TMP/release.dsse.json" --trust-dir "$TMP/trust" --policy examples/policy.json --sbom "$TMP/sbom.json" > "$TMP/negative.json"; then
  echo 'ERROR: tampered artifact unexpectedly verified' >&2
  exit 1
fi
python -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "ARTIFACT_MISMATCH" in d["failures"]' "$TMP/negative.json"
echo 'CLI smoke: positive and tamper-negative controls passed.'
