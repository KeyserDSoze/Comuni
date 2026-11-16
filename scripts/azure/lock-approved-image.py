#!/usr/bin/env python3
"""Lock only the approved ACR tag and OCI manifest before ACA staging.

Azure Container Registry tracks tag and manifest changeable attributes
independently. Verify the approved digest before mutating either; lock
write/delete at both scopes; recheck tag digest and both read-back attribute
sets. Never unlock automatically, mutate a whole repository, or emit any
Azure CLI output on success or failure. No Key Vault values are accessed.
"""
import argparse
import json
import re
import subprocess
import sys

SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
ACR_NAME = re.compile(r"[a-z0-9]{5,50}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_RESPONSE = 32768


class LockRejected(Exception):
    """Errors must contain static text, never CLI content."""


def require(ok, message):
    if not ok:
        raise LockRejected(message)


def az(*args):
    # Capture Azure CLI diagnostics even on failure, so no registry metadata,
    # signed token or credential can leak to the GitHub Actions job log.
    result = subprocess.run(
        ["az", *args], capture_output=True, text=True,
        check=False, timeout=30,
    )
    require(result.returncode == 0, "Azure ACR lock/read-back failed")
    require(len(result.stdout) <= MAX_RESPONSE, "oversized ACR metadata response")
    return result.stdout.strip()


def manifest_digest(registry, source_sha):
    response = az(
        "acr", "manifest", "show-metadata",
        "--registry", registry, "--name", "comuni:" + source_sha,
        "--query", "digest", "--output", "tsv", "--only-show-errors",
    )
    require(bool(OCI_DIGEST.fullmatch(response)),
            "ACR tag has no valid OCI digest")
    return response


def lock_image(registry, image_ref):
    # Never lock the whole repository: doing so would block the next release.
    az("acr", "repository", "update",
       "--name", registry, "--image", image_ref,
       "--write-enabled", "false", "--delete-enabled", "false",
       "--output", "none", "--only-show-errors")


def check_attributes(registry, image_ref):
    raw = az(
        "acr", "repository", "show",
        "--name", registry, "--image", image_ref,
        "--query", "changeableAttributes",
        "--output", "json", "--only-show-errors",
    )
    response = json.loads(raw)
    require(isinstance(response, dict) and
            response.get("writeEnabled") is False and
            response.get("deleteEnabled") is False and
            response.get("readEnabled") is True,
            "ACR tag/manifest not read-enabled and immutable")


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

    tag = "comuni:" + args.source_commit_sha
    manifest = "comuni@" + args.candidate_image_digest
    require(manifest_digest(args.registry_name, args.source_commit_sha) ==
            args.candidate_image_digest,
            "ACR tag changed before image lock")

    # ACR's attributes apply to tag and manifest separately; neither one
    # is sufficient on its own to protect both references.
    lock_image(args.registry_name, tag)
    lock_image(args.registry_name, manifest)

    # No auto-unlock on failure: manual owner review required.
    require(manifest_digest(args.registry_name, args.source_commit_sha) ==
            args.candidate_image_digest,
            "ACR tag changed during image lock")
    check_attributes(args.registry_name, tag)
    check_attributes(args.registry_name, manifest)


def main():
    parser = argparse.ArgumentParser(
        description="Protect exact OCI candidate tag and manifest in Azure ACR")
    parser.add_argument("--registry-name", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    args = parser.parse_args()
    try:
        lock(args)
    except (LockRejected, OSError, ValueError, TypeError,
            UnicodeError, subprocess.TimeoutExpired) as error:
        reason = (str(error) if isinstance(error, LockRejected)
                  else "invalid or unavailable ACR lock metadata")
        print("ACR candidate lock rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
