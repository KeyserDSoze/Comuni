#!/usr/bin/env python3
"""Lock only the approved ACR tag and OCI manifest before ACA staging.

Azure Container Registry tracks tag and manifest changeable attributes
independently. Verify the approved digest before mutating either; lock
write/delete at both scopes; recheck tag digest and both read-back attribute
sets. Never unlock automatically, mutate a whole repository, or emit any
Azure CLI output on success or failure. No Key Vault values are accessed.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

_spec = importlib.util.spec_from_file_location(
    "acr_registry_data_plane", Path(__file__).with_name("acr-registry-data-plane.py"))
_acr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_acr)
ACRClient = _acr.ACRClient
ACRRejected = _acr.ACRRejected


SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
ACR_NAME = re.compile(r"[a-z0-9]{5,50}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_RESPONSE = 32768


class LockRejected(Exception):
    """Errors must contain static text, never CLI content."""


def require(ok, message):
    if not ok:
        raise LockRejected(message)


def lock(args):
    require(bool(SOURCE_SHA.fullmatch(args.source_commit_sha)),
            "invalid approved Git commit SHA")
    require(bool(ACR_NAME.fullmatch(args.registry_name)) and
            args.registry_host == args.registry_name + ".azurecr.io",
            "unapproved ACR registry host")
    require(bool(OCI_DIGEST.fullmatch(args.candidate_image_digest)),
            "invalid approved OCI manifest digest")
    require(args.image == args.registry_host + "/comuni@" + args.candidate_image_digest,
            "image does not identify the approved ACR manifest")

    # ACR OAuth2 data-plane scope restricted to repository:comuni:pull,push.
    # No ARM lookup or tag/manifest mutation beyond the two approved refs.
    client = ACRClient(args.registry_name, args.registry_host, args.tenant_id)
    client.authenticate()
    client.lock(args.source_commit_sha, args.candidate_image_digest)


def main():
    parser = argparse.ArgumentParser(
        description="Protect exact OCI candidate tag and manifest in Azure ACR")
    parser.add_argument("--registry-name", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    args = parser.parse_args()
    try:
        lock(args)
    except (LockRejected, ACRRejected, OSError, ValueError, TypeError,
            UnicodeError, subprocess.TimeoutExpired) as error:
        reason = (str(error) if isinstance(error, (LockRejected, ACRRejected))
                  else "invalid or unavailable ACR lock metadata")
        print("ACR candidate lock rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
