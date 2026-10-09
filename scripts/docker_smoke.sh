#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
CID=""
cleanup() {
  if [[ -n "$CID" ]]; then docker rm -f "$CID" >/dev/null 2>&1 || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/trust"
cp -R examples/demo_release "$TMP/release"
cp examples/requirements.lock "$TMP/requirements.lock"
cp examples/licenses.json "$TMP/licenses.json"
cp examples/policy.json "$TMP/policy.json"
# The demo CLI runs in the same built image; it needs no host Python installation.
docker run --rm --user 0:0 -v "$TMP:/output" attestforge:ci attestforge keygen --private /output/private.pem --public /output/trust/release.pem >/dev/null
docker run --rm --user 0:0 -v "$TMP:/output" attestforge:ci attestforge sbom --requirements /output/requirements.lock --licenses /output/licenses.json --out /output/sbom.json >/dev/null
docker run --rm --user 0:0 -v "$TMP:/output" attestforge:ci attestforge attest --artifact /output/release --private /output/private.pem --builder local-demo --sbom /output/sbom.json --out /output/release.dsse.json >/dev/null
# The API process runs as UID 10001 and only needs read access to the trust and policy.
chmod 755 "$TMP" "$TMP/trust"
CID="$(docker run -d --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 -p 127.0.0.1:18080:8000 -v "$TMP/trust:/etc/attestforge/trust:ro" -v "$TMP/policy.json:/etc/attestforge/policy.json:ro" attestforge:ci)"
READY=0
for i in $(seq 1 30); do
  if python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18080/readyz',timeout=2)" >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
if [[ "$READY" -ne 1 ]]; then docker logs "$CID"; exit 1; fi
python - "$TMP" <<'PY'
import json,sys,urllib.request
from pathlib import Path
p=Path(sys.argv[1]); endpoint='http://127.0.0.1:18080/v1/verify-envelope'
with urllib.request.urlopen('http://127.0.0.1:18080/healthz',timeout=3) as r:
    assert json.load(r)['status']=='alive'
body={'envelope':json.loads((p/'release.dsse.json').read_text()),'sbom':json.loads((p/'sbom.json').read_text())}
def post(value):
    req=urllib.request.Request(endpoint,data=json.dumps(value).encode(),headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=5) as r: return json.load(r)
result=post(body)
assert result['passed'] and not result['release_verified'] and result['assurance_scope']=='envelope-and-policy-only'
body['envelope']['payload']='AAAA'
assert not post(body)['passed']
PY
echo 'Docker smoke: non-root read-only container, readiness, signed-envelope positive and tamper-negative checks passed.'
