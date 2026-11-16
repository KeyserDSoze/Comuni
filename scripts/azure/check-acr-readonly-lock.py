#!/usr/bin/env python3
"""Read-only auditor for an already-approved ACR candidate tag and manifest.

Manual owner preflight after a test-image lock. It never PATCHes, unlocks,
pushes or alters registry/role state. Only requests OAuth2 scope
repository:comuni:pull; metadata and OAuth errors are not logged.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import sys

_spec = importlib.util.spec_from_file_location(
    "acr_registry_readonly_data_plane",
    Path(__file__).with_name("acr-registry-data-plane.py"))
_acr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_acr)
ACRClient = _acr.ACRClient
ACRRejected = _acr.ACRRejected

COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REGISTRY = re.compile(r"[a-z0-9]{5,50}\Z")


class AuditRejected(Exception):
    """Static, safe diagnostics only."""


def require(ok, message):
    if not ok:
        raise AuditRejected(message)


def audit(args):
    require(bool(COMMIT.fullmatch(args.source_commit_sha)),
            "invalid approved Git commit SHA")
    require(bool(DIGEST.fullmatch(args.candidate_image_digest)),
            "invalid approved OCI digest")
    require(bool(REGISTRY.fullmatch(args.registry_name))
            and args.registry_host == args.registry_name + ".azurecr.io",
            "invalid managed ACR registry host")
    require(args.image == args.registry_host + "/comuni@" + args.candidate_image_digest,
            "candidate URI does not match approved OCI digest")
    client = ACRClient(args.registry_name, args.registry_host, args.tenant_id,
                       read_only=True)
    client.authenticate()
    client.verify_locked(args.source_commit_sha, args.candidate_image_digest)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only verify immutable ACR tag and manifest by digest")
    parser.add_argument("--registry-name", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args(argv)
    try:
        audit(args)
    except Exception as error:
        reason = (str(error) if isinstance(error, (AuditRejected, ACRRejected))
                  else "unavailable or invalid read-only ACR metadata")
        print("ACR read-only audit rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
