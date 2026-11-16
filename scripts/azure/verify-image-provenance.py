#!/usr/bin/env python3
"""Fail-closed signed provenance gate for the OCI candidate before Terraform plan.

The trusted GitHub runner supplies source SHA, expected manifest digest and ACR
host independently of the Terraform plan. gh attestation verify performs
Sigstore verification, identity/certificate/ref/source checks against GitHub's
attestation API. This script enforces matching subject metadata and NEVER
echoes untrusted attestation bundles, CLI diagnostics, credentials or tokens.
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
PREDICATE = "https://slsa.dev/provenance/v1"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ACR_HOST = re.compile(r"[a-z0-9]{5,50}\.azurecr\.io\Z")
MAX_VERIFICATION_JSON = 131072


class ProvenanceRejected(Exception):
    """Messages must never embed external or sensitive values."""


def require(ok, reason):
    if not ok:
        raise ProvenanceRejected(reason)


def verify(args):
    require(args.repository == REPO and args.source_ref == SOURCE_REF,
            "unapproved repository or source ref")
    require(bool(SOURCE_SHA.fullmatch(args.source_commit_sha)),
            "invalid approved source commit")
    require(bool(DIGEST.fullmatch(args.candidate_image_digest)),
            "invalid approved OCI image digest")
    require(bool(ACR_HOST.fullmatch(args.registry_host)),
            "invalid managed ACR hostname")

    image_name = args.registry_host + "/comuni"
    require(args.image == image_name + "@" + args.candidate_image_digest,
            "candidate image differs from approved manifest digest")
    require(bool(os.environ.get("GH_TOKEN")),
            "missing GitHub attestation verification credentials")

    # CLI verifies Sigstore signature, GitHub OIDC issuer, repository,
    # signing workflow, source ref, source SHA and SLSA provenance predicate.
    # We deliberately DO NOT use --bundle or --bundle-from-oci: fetching
    # from GitHub's API avoids stale/name-reuse bundles.
    result = subprocess.run(
        ["gh", "attestation", "verify", "oci://" + args.image,
         "--repo", REPO,
         "--signer-workflow", SIGNER,
         "--source-ref", SOURCE_REF,
         "--source-digest", args.source_commit_sha,
         "--predicate-type", PREDICATE,
         "--deny-self-hosted-runners",
         "--format", "json"],
        text=True, capture_output=True, check=False, timeout=45,
    )
    require(result.returncode == 0,
            "no valid signed GitHub provenance for this OCI image")
    require(len(result.stdout) <= MAX_VERIFICATION_JSON,
            "oversized provenance verification metadata")
    payload = json.loads(result.stdout)
    require(isinstance(payload, list) and len(payload) > 0,
            "empty provenance verification results")
    expected_digest = args.candidate_image_digest.split(":", 1)[1]

    def subject_matches(entry):
        if not isinstance(entry, dict):
            return False
        verification = entry.get("verificationResult")
        statement = verification.get("statement") if isinstance(verification, dict) else None
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE:
            return False
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            return False
        return any(
            isinstance(subject, dict) and subject.get("name") == image_name
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == expected_digest
            for subject in subjects
        )

    require(any(subject_matches(entry) for entry in payload),
            "verified provenance does not bind the approved OCI manifest")


def main():
    parser = argparse.ArgumentParser(
        description="Verify signed OCI candidate provenance before Terraform plan")
    parser.add_argument("--image", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-ref", required=True)
    args = parser.parse_args()
    try:
        verify(args)
    except (ProvenanceRejected, OSError, ValueError, TypeError,
            UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        reason = (str(error) if isinstance(error, ProvenanceRejected)
                  else "invalid or unavailable provenance metadata")
        print("Candidate provenance rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
