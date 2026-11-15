#!/usr/bin/env python3
"""Read-only, fail-closed ACA staging verification after Terraform apply.

Azure CLI is used only for metadata GET commands. Never output raw Azure responses,
which might contain environment or infrastructure metadata. This is NOT an OIDC /
tenant RLS smoke test and never changes revision traffic or key validity.
"""
import argparse
import json
import re
import subprocess
import sys
import time

APP_NAME = re.compile(r"[a-z][a-z0-9-]{2,30}[a-z0-9]\Z")
RESOURCE_GROUP = re.compile(r"[a-zA-Z0-9._()-]{1,90}\Z")
SUFFIX = re.compile(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]\Z")
CANDIDATE = re.compile(r"r[0-9a-f]{12}\Z")
KEY_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
VERSION = re.compile(r"[0-9a-fA-F]{32}\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9.-]*(?:/[a-z0-9._-]+)+:[0-9a-f]{40}\Z")


class VerificationError(Exception):
    pass


def required(value, message):
    if not value:
        raise VerificationError(message)


def az_metadata(*args, output="json"):
    """Capture stdout and stderr without exposing Azure CLI responses in logs."""
    command = ["az", *args, "--output", output, "--only-show-errors"]
    try:
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise VerificationError("Azure metadata unavailable")
    try:
        return json.loads(result.stdout) if output == "json" else result.stdout.strip()
    except (json.JSONDecodeError, UnicodeError):
        raise VerificationError("Invalid Azure metadata")


def one_revision(revisions, name):
    required(isinstance(revisions, list), "Invalid revision collection")
    matches = [
        rev for rev in revisions
        if isinstance(rev, dict) and rev.get("name") == name
    ]
    required(len(matches) == 1, "Required revision missing or duplicated")
    return matches[0]


def ready(revision):
    props = revision.get("properties")
    required(isinstance(props, dict), "Invalid revision status")
    required(
        props.get("active") is True
        and props.get("healthState") == "Healthy"
        and props.get("provisioningState") == "Provisioned"
        and props.get("runningState") == "Running",
        "Revision is not active and healthy",
    )
    replicas = props.get("replicas")
    required(
        type(replicas) is int and replicas >= 1,
        "Revision has no running replicas",
    )


def candidate_metadata(revision, args):
    props = revision["properties"]
    template = props.get("template")
    required(isinstance(template, dict), "Invalid candidate template")
    containers = template.get("containers")
    required(
        isinstance(containers, list)
        and len(containers) == 1
        and isinstance(containers[0], dict),
        "Expected single API/SPA container",
    )
    container = containers[0]
    required(
        container.get("image") == args.expected_image,
        "Candidate image is not the approved immutable commit",
    )
    env = container.get("env")
    required(isinstance(env, list), "Candidate environment missing")

    def one_env(name):
        found = [
            setting for setting in env
            if isinstance(setting, dict) and setting.get("name") == name
        ]
        required(len(found) == 1, "Candidate environment missing or duplicated")
        return found[0]

    key_id = one_env("Security__TenantProofKeyId")
    secret = one_env("Security__TenantProofKey")
    required(
        key_id.get("value") == args.candidate_key_id and not key_id.get("secretRef"),
        "Candidate RLS key ID mismatch",
    )
    required(
        secret.get("secretRef")
        == "tenant-proof-key-v" + args.candidate_secret_version
        and not secret.get("value"),
        "Candidate RLS secret reference mismatch",
    )


def verify_traffic(traffic, stable_name, candidate_label):
    required(isinstance(traffic, list) and len(traffic) == 2,
             "Unexpected ingress traffic targets")
    stable = [
        item for item in traffic
        if isinstance(item, dict) and item.get("revisionName") == stable_name
    ]
    latest = [
        item for item in traffic
        if isinstance(item, dict) and item.get("latestRevision") is True
    ]
    required(len(stable) == 1 and len(latest) == 1 and stable[0] is not latest[0],
             "Stable/latest ingress rules are missing or ambiguous")
    required(
        stable[0].get("weight") == 100
        and stable[0].get("latestRevision") in (False, None)
        and latest[0].get("weight") == 0
        and latest[0].get("revisionName") in (None, "")
        and latest[0].get("label") == candidate_label
        and stable[0].get("label") != candidate_label,
        "Traffic drift: stable must remain at 100 percent and latest at zero, with candidate label",
    )


def check(args):
    mode = az_metadata(
        "containerapp", "show",
        "--name", args.app, "--resource-group", args.resource_group,
        "--query", "properties.configuration.activeRevisionsMode",
        output="tsv",
    )
    required(mode == "Multiple", "Azure app must be in Multiple revision mode")
    revisions = az_metadata(
        "containerapp", "revision", "list",
        "--name", args.app, "--resource-group", args.resource_group,
    )
    traffic = az_metadata(
        "containerapp", "ingress", "traffic", "show",
        "--name", args.app, "--resource-group", args.resource_group,
    )
    stable_name = args.app + "-" + args.stable_revision
    candidate_name = args.app + "-" + args.candidate_revision
    stable = one_revision(revisions, stable_name)
    candidate = one_revision(revisions, candidate_name)
    ready(stable)
    ready(candidate)
    candidate_metadata(candidate, args)
    verify_traffic(traffic, stable_name, args.candidate_revision)


def parse_args():
    parser = argparse.ArgumentParser(description="Verify staged ACA revisions without promotion")
    parser.add_argument("--app", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--stable-revision", required=True)
    parser.add_argument("--candidate-revision", required=True)
    parser.add_argument("--expected-image", required=True)
    parser.add_argument("--candidate-key-id", required=True)
    parser.add_argument("--candidate-secret-version", required=True)
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--interval-seconds", type=int, default=10)
    args = parser.parse_args()
    required(APP_NAME.fullmatch(args.app) and "--" not in args.app,
             "Invalid Container App name")
    required(RESOURCE_GROUP.fullmatch(args.resource_group),
             "Invalid Azure resource group")
    required(SUFFIX.fullmatch(args.stable_revision) and
             "--" not in args.stable_revision,
             "Invalid stable revision suffix")
    required(CANDIDATE.fullmatch(args.candidate_revision) and
             args.stable_revision != args.candidate_revision,
             "Invalid candidate revision suffix")
    required(IMAGE.fullmatch(args.expected_image),
             "Expected a commit-SHA-tagged image")
    required(KEY_ID.fullmatch(args.candidate_key_id),
             "Invalid candidate key ID")
    required(VERSION.fullmatch(args.candidate_secret_version),
             "Invalid pinned Key Vault secret version")
    required(1 <= args.attempts <= 30 and 0 <= args.interval_seconds <= 30,
             "Invalid bounded Azure verification retry policy")
    return args


def main():
    try:
        args = parse_args()
        for attempt in range(args.attempts):
            try:
                check(args)
                print("Azure stage verified: stable 100%, healthy candidate 0%; no traffic changes.")
                return 0
            except VerificationError:
                if attempt + 1 < args.attempts:
                    time.sleep(args.interval_seconds)
        print("Azure stage verification failed: metadata, health or traffic did not match.",
              file=sys.stderr)
    except VerificationError:
        print("Azure stage verification failed: invalid approved deployment inputs.",
              file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
