"""Command-line entry point; exit 2 means verification or validation failed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .crypto import create_keypair
from .engine import attest_release, verify_release
from .errors import AttestForgeError
from .sbom import generate_sbom
from .util import contained_within, read_json, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="attestforge", description="Offline release integrity attestations and policy gates")
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keygen", help="Generate Ed25519 signing and trust keys")
    keys.add_argument("--private", type=Path, required=True)
    keys.add_argument("--public", type=Path, required=True)

    sbom = sub.add_parser("sbom", help="Generate a deterministic CycloneDX 1.6 SBOM from pinned requirements")
    sbom.add_argument("--requirements", type=Path, required=True)
    sbom.add_argument("--licenses", type=Path)
    sbom.add_argument("--app-name", default="release")
    sbom.add_argument("--out", type=Path, required=True)

    attest = sub.add_parser("attest", help="Sign a release directory inventory")
    attest.add_argument("--artifact", type=Path, required=True)
    attest.add_argument("--private", type=Path, required=True)
    attest.add_argument("--builder", required=True)
    attest.add_argument("--sbom", type=Path)
    attest.add_argument("--out", type=Path, required=True)

    verify = sub.add_parser("verify", help="Verify signature, policy, SBOM and actual artifact bytes")
    verify.add_argument("--artifact", type=Path, required=True)
    verify.add_argument("--envelope", type=Path, required=True)
    verify.add_argument("--trust-dir", type=Path, required=True)
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--sbom", type=Path)
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "keygen":
            kid = create_keypair(args.private, args.public)
            result: dict[str, Any] = {"created": True, "keyid": kid, "private": str(args.private), "public": str(args.public)}
        elif args.command == "sbom":
            licenses = read_json(args.licenses) if args.licenses else None
            result = generate_sbom(args.requirements, app_name=args.app_name, licenses=licenses)
            write_json(args.out, result)
            result = {"created": True, "components": len(result["components"]), "path": str(args.out)}
        elif args.command == "attest":
            if contained_within(args.out, args.artifact):
                raise AttestForgeError("OUTPUT_INSIDE_ARTIFACT", "Attestation output must be outside artifact root")
            sbom = read_json(args.sbom) if args.sbom else None
            result = attest_release(args.artifact, args.private, builder=args.builder, sbom=sbom)
            write_json(args.out, result)
            result = {"created": True, "path": str(args.out), "keyid": result["signatures"][0]["keyid"]}
        else:
            envelope = read_json(args.envelope, max_bytes=2 * 1024 * 1024)
            policy = read_json(args.policy)
            sbom = read_json(args.sbom) if args.sbom else None
            report = verify_release(
                envelope, trust_dir=args.trust_dir, policy=policy,
                artifact_dir=args.artifact, sbom=sbom,
            )
            result = report.to_dict()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if report.release_verified else 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except AttestForgeError as exc:
        print(json.dumps({"passed": False, "error": exc.code, "detail": str(exc)}), file=sys.stderr)
        return 2
    except OSError as exc:
        print(json.dumps({"passed": False, "error": "IO_ERROR", "detail": str(exc)}), file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
