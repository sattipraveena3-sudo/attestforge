"""Read-only verification API; server-owned trust roots and policy, no filesystem inputs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from .engine import verify_release
from .errors import AttestForgeError
from .policy import validate_policy
from .crypto import load_trust_store
from .util import read_json

MAX_REQUEST_BYTES = 1024 * 1024


class EnvelopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    envelope: dict[str, Any]
    sbom: dict[str, Any] | None = None


def create_app(*, trust_dir: Path | None = None, policy_path: Path | None = None) -> FastAPI:
    trust = trust_dir or Path(os.environ.get("ATTESTFORGE_TRUST_DIR", "/etc/attestforge/trust"))
    policy_file = policy_path or Path(os.environ.get("ATTESTFORGE_POLICY_PATH", "/etc/attestforge/policy.json"))
    app = FastAPI(title="AttestForge Verification API", version="0.1.0", docs_url="/docs")

    @app.middleware("http")
    async def bound_body(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH"}:
            length = request.headers.get("content-length")
            if length:
                try:
                    if int(length) > MAX_REQUEST_BYTES:
                        return JSONResponse({"detail": "Request too large"}, status_code=413)
                except ValueError:
                    return JSONResponse({"detail": "Invalid content length"}, status_code=400)
            # Streaming uploads without Content-Length must be bounded too.
            total = 0
            chunks = []
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_REQUEST_BYTES:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)  # Starlette replays cached body downstream
        return await call_next(request)

    @app.get("/healthz")
    def healthz():
        return {"status": "alive"}

    @app.get("/readyz")
    def readyz():
        try:
            load_trust_store(trust)
            validate_policy(read_json(policy_file))
        except AttestForgeError as exc:
            raise HTTPException(status_code=503, detail=exc.code) from exc
        return {"status": "ready", "assurance_scope": "envelope-and-policy-only"}

    @app.post("/v1/verify-envelope")
    def verify(payload: EnvelopeRequest):
        try:
            policy = read_json(policy_file)
            validate_policy(policy)
            load_trust_store(trust)
        except AttestForgeError as exc:
            raise HTTPException(status_code=503, detail=exc.code) from exc
        report = verify_release(payload.envelope, trust_dir=trust, policy=policy, sbom=payload.sbom)
        # HTTP 200 for machine-readable allow/deny decisions; the caller MUST inspect passed.
        return report.to_dict()

    return app


app = create_app()
