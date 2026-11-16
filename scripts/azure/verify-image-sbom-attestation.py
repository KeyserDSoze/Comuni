#!/usr/bin/env python3
"""Verify GitHub/Sigstore SPDX 2.3 attestation on the approved OCI manifest.

Does not parse unsigned bundles or trust the Terraform plan as a provenance
source. gh attestation verify checks the Sigstore signature, issuer and signing
workflow. Only verified subject and SPDX predicate metadata may authorize
the candidate. Never print CLI outputs or credential-bearing values.
"""
import argparse
import json
import os
import re
import subprocess
import sys

REPO = "KeyserDSoze/Comuni"
SIGNER = REPO + "/.github/workflows/deploy.yml"
SOURCE_REF = "refs/heads/main"
PREDICATE = "https://spdx.dev/Document/v2.3"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ACR_HOST = re.compile(r"[a-z0-9]{5,50}\.azurecr\.io\Z")
MAX_VERIFICATION_JSON = 131072


class SBOMRejected(Exception):
    """Only constant reasons can be exposed from a failure."""


def require(condition, reason):
    if not condition:
        raise SBOMRejected(reason)


def verified_sbom(args):
    require(args.repository == REPO and args.source_ref == SOURCE_REF,
            "unapproved repository or source ref")
    require(bool(SOURCE_SHA.fullmatch(args.source_commit_sha)),
            "invalid approved source commit")
    require(bool(DIGEST.fullmatch(args.candidate_image_digest)) and
            bool(ACR_HOST.fullmatch(args.registry_host)),
            "invalid approved OCI manifest identity")

    image_name = args.registry_host + "/comuni"
    require(args.image == image_name + "@" + args.candidate_image_digest,
            "candidate image differs from the approved manifest")
    require(bool(os.environ.get("GH_TOKEN")),
            "missing GitHub attestation verification credentials")

    result = subprocess.run(
        ["gh", "attestation", "verify", "oci://" + args.image,
         "--repo", REPO, "--signer-workflow", SIGNER,
         "--source-ref", SOURCE_REF, "--source-digest", args.source_commit_sha,
         "--predicate-type", PREDICATE, "--deny-self-hosted-runners",
         "--format", "json"],
        capture_output=True, text=True, check=False, timeout=45,
    )
    require(result.returncode == 0,
            "no valid signed SPDX SBOM for approved OCI manifest")
    require(len(result.stdout) <= MAX_VERIFICATION_JSON,
            "oversized verified SPDX metadata")
    rows = json.loads(result.stdout)
    require(isinstance(rows, list) and len(rows) > 0,
            "empty signed SPDX verification result")

    expected_sha256 = args.candidate_image_digest.split(":", 1)[1]

    def matching(row):
        if not isinstance(row, dict):
            return False
        vr = row.get("verificationResult")
        statement = vr.get("statement") if isinstance(vr, dict) else None
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE:
            return False
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            return False
        if not any(isinstance(s, dict) and s.get("name") == image_name and
                   isinstance(s.get("digest"), dict) and
                   s["digest"].get("sha256") == expected_sha256
                   for s in subjects):
            return False
        spdx = statement.get("predicate")
        return (isinstance(spdx, dict) and spdx.get("spdxVersion") == "SPDX-2.3"
                and isinstance(spdx.get("packages"), list)
                and len(spdx["packages"]) > 0)

    require(any(matching(row) for row in rows),
            "verified SBOM does not bind the approved image and SPDX packages")


def main():
    parser = argparse.ArgumentParser(
        description="Verify signed SPDX 2.3 SBOM of candidate OCI digest")
    parser.add_argument("--image", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    try:
        verified_sbom(args)
    except (SBOMRejected, OSError, UnicodeError, ValueError, TypeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        reason = str(error) if isinstance(error, SBOMRejected) else "invalid SPDX attestation metadata"
        print("Candidate SBOM rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
