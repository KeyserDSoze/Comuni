#!/usr/bin/env python3
"""Resolve the *pushed* OCI manifest digest, fail closed before Terraform plan.

The Docker push receipt is the independent digest anchor. Azure Container
Registry metadata must confirm the same tag/digest at verification time.
Only non-secret GitHub environment entries are written on full success.
Never echo source files, CLI errors, manifest metadata or credentials.
"""
import argparse
import importlib.util
import os
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

SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REGISTRY_NAME = re.compile(r"[a-z0-9]{5,50}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_PUSH_RECEIPT = 65536


class ResolutionRejected(Exception):
    """Error whose message is constant and not derived from external input."""


def require(ok, reason):
    if not ok:
        raise ResolutionRejected(reason)


def pushed_digest(path, source_sha):
    with open(path, "rb") as receipt:
        raw = receipt.read(MAX_PUSH_RECEIPT + 1)
    require(len(raw) <= MAX_PUSH_RECEIPT,
            "Docker push receipt exceeds the maximum allowed size")
    log = raw.decode("utf-8")
    expected = re.compile(
        re.escape(source_sha) + r": digest: (sha256:[0-9a-f]{64}) size: [0-9]{1,10}\Z"
    )
    candidates = []
    for line in log.splitlines():
        if "digest:" not in line:
            continue
        match = expected.fullmatch(line)
        require(match is not None, "unrecognized or ambiguous Docker push digest line")
        candidates.append(match.group(1))
    require(len(candidates) == 1, "exactly one Docker push digest is required")
    return candidates[0]


def resolve(args):
    require(isinstance(args.source_commit_sha, str) and
            bool(SOURCE_COMMIT.fullmatch(args.source_commit_sha)),
            "invalid source commit SHA")
    require(isinstance(args.registry_name, str) and
            bool(REGISTRY_NAME.fullmatch(args.registry_name)),
            "invalid managed ACR name")
    require(args.registry_host == args.registry_name + ".azurecr.io",
            "ACR host must match the approved managed registry")
    push_digest = pushed_digest(args.push_output_file, args.source_commit_sha)
    client = ACRClient(args.registry_name, args.registry_host, args.tenant_id)
    client.authenticate()
    remote_digest = client.tag_digest(args.source_commit_sha, expected_digest=push_digest)
    require(push_digest == remote_digest,
            "ACR manifest digest differs from Docker's push receipt")

    # DO NOT set a tag URI: after this point the mutable tag is no longer
    # used to select what Azure Container Apps will execute.
    image = args.registry_host + "/comuni@" + push_digest
    require(os.path.isfile(args.github_env) and not os.path.islink(args.github_env),
            "missing or unsafe GitHub environment output")
    with open(args.github_env, "a", encoding="utf-8") as target:
        target.write("TF_VAR_image=" + image + "\n")
        target.write("CANDIDATE_IMAGE_DIGEST=" + push_digest + "\n")


def main():
    parser = argparse.ArgumentParser(description="Pin ACA release to Docker push and ACR digest")
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--registry-name", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--push-output-file", required=True)
    parser.add_argument("--github-env", required=True)
    args = parser.parse_args()
    try:
        resolve(args)
    except (ResolutionRejected, ACRRejected, OSError, UnicodeError, ValueError,
            subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, (ResolutionRejected, ACRRejected)) else "digest verification failed"
        print("Candidate image rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
