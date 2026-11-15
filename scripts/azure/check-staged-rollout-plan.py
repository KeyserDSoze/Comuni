#!/usr/bin/env python3
"""Fail-closed review of an Azure Container App Terraform staging plan.

Consumes Terraform show JSON from stdin. The JSON may contain sensitive
values: never echo any part of the plan or its resource data.
"""
import argparse
import json
import re
import sys
from urllib.parse import urlparse

APP_ADDRESS = "azurerm_container_app.main"
STABLE_SECRET = "tenant-proof-key"
VERSION = re.compile(r"[0-9a-fA-F]{32}\Z")
KEY_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
SUFFIX = re.compile(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]\Z")


class PlanRejected(Exception):
    """Only generic reasons, never strings copied from the sensitive plan."""


def require(ok, reason):
    if not ok:
        raise PlanRejected(reason)


def one_block(obj, key):
    blocks = obj.get(key, []) if isinstance(obj, dict) else []
    require(isinstance(blocks, list) and len(blocks) == 1 and isinstance(blocks[0], dict),
            "missing or ambiguous container-app configuration")
    return blocks[0]


def named(items, name):
    require(isinstance(items, list), "invalid resource collection")
    entries = [i for i in items if isinstance(i, dict) and i.get("name") == name]
    require(len(entries) == 1, "required or duplicated release resource")
    return entries[0]


def secret_version_uri(value, version):
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(re.fullmatch(r"[a-z0-9-]+\.vault\.azure\.net", parsed.netloc or ""))
        and (parsed.path or "").lower()
            == ("/secrets/tenant-proof-key/" + version).lower()
        and not parsed.query and not parsed.fragment and not parsed.username
    )


def validate(plan, args):
    for version in (args.stable_secret_version, args.candidate_secret_version):
        require(bool(VERSION.fullmatch(version)), "invalid pinned secret version")
    require(bool(KEY_ID.fullmatch(args.candidate_key_id)), "invalid candidate key ID")
    for suffix in (args.stable_revision, args.candidate_revision):
        require(bool(SUFFIX.fullmatch(suffix)) and "--" not in suffix,
                "invalid or missing revision suffix")
    require(args.stable_revision != args.candidate_revision,
            "candidate cannot equal stable revision")

    changes = plan.get("resource_changes", []) if isinstance(plan, dict) else []
    require(isinstance(changes, list), "missing Terraform changes")
    app_changes = [item for item in changes
                   if isinstance(item, dict) and item.get("address") == APP_ADDRESS]
    require(len(app_changes) == 1, "a single existing container-app change is required")
    change = app_changes[0].get("change", {})
    require(isinstance(change, dict) and change.get("actions") == ["update"],
            "refusing container-app creation, deletion, replacement or no-op")
    before, after = change.get("before"), change.get("after")
    require(isinstance(before, dict) and isinstance(after, dict),
            "existing stable revision is required before staging")
    require(after.get("revision_mode") == "Multiple",
            "candidate requires multiple-revision mode")

    before_secrets = before.get("secret", [])
    after_secrets = after.get("secret", [])
    stable_before = named(before_secrets, STABLE_SECRET)
    stable_after = named(after_secrets, STABLE_SECRET)
    require(secret_version_uri(stable_before.get("key_vault_secret_id"),
                               args.stable_secret_version),
            "stable secret must be pinned to the approved previous version")
    require(stable_before.get("key_vault_secret_id") ==
            stable_after.get("key_vault_secret_id"),
            "the stable revision's existing secret must never change")

    # Application-scoped secret changes affect active revisions. Preserve *all*
    # existing names and Key Vault version references during staging.
    require(isinstance(before_secrets, list), "invalid existing secret collection")
    for existing in before_secrets:
        require(isinstance(existing, dict) and isinstance(existing.get("name"), str),
                "invalid existing secret")
        current = named(after_secrets, existing["name"])
        require(existing.get("key_vault_secret_id") == current.get("key_vault_secret_id"),
                "staging may not change or remove an existing app-scoped secret")

    candidate_name = "tenant-proof-key-v" + args.candidate_secret_version
    candidate_secret = named(after_secrets, candidate_name)
    require(secret_version_uri(candidate_secret.get("key_vault_secret_id"),
                               args.candidate_secret_version),
            "candidate secret must reference its own approved pinned version")
    require(candidate_name != STABLE_SECRET,
            "candidate must use a separate app-scoped secret name")

    template = one_block(after, "template")
    require(template.get("revision_suffix") == args.candidate_revision,
            "unexpected candidate revision suffix")
    require(isinstance(template.get("min_replicas"), int) and
            template["min_replicas"] >= 1,
            "candidate must remain running for zero-traffic smoke testing")
    containers = template.get("container", [])
    require(isinstance(containers, list) and len(containers) == 1 and
            isinstance(containers[0], dict),
            "expected single API + SPA container")
    proof = named(containers[0].get("env", []), "Security__TenantProofKey")
    proof_id = named(containers[0].get("env", []), "Security__TenantProofKeyId")
    require(proof.get("secret_name") == candidate_name and not proof.get("value"),
            "candidate API must use only its own versioned secret reference")
    require(proof_id.get("value") == args.candidate_key_id and
            not proof_id.get("secret_name"),
            "candidate key ID must match approved PostgreSQL verifier ID")

    ingress = one_block(after, "ingress")
    weights = ingress.get("traffic_weight", [])
    require(isinstance(weights, list) and len(weights) == 2,
            "expected only two explicit traffic weights")
    stable = [w for w in weights if isinstance(w, dict) and
              w.get("latest_revision") is False]
    candidate = [w for w in weights if isinstance(w, dict) and
                 w.get("latest_revision") is True]
    require(len(stable) == 1 and len(candidate) == 1,
            "unexpected latest revision promotion or traffic targets")
    require(stable[0].get("revision_suffix") == args.stable_revision and
            stable[0].get("percentage") == 100,
            "stable revision must retain 100 percent traffic")
    require(candidate[0].get("percentage") == 0 and
            not candidate[0].get("revision_suffix"),
            "candidate must retain zero percent public traffic")


def main():
    parser = argparse.ArgumentParser(
        description="Validate staged ACA Terraform plan without emitting state or secrets"
    )
    parser.add_argument("--stable-revision", required=True)
    parser.add_argument("--candidate-revision", required=True)
    parser.add_argument("--stable-secret-version", required=True)
    parser.add_argument("--candidate-secret-version", required=True)
    parser.add_argument("--candidate-key-id", required=True)
    args = parser.parse_args()
    try:
        plan = json.load(sys.stdin)
        validate(plan, args)
    except (PlanRejected, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        reason = str(error) if isinstance(error, PlanRejected) else "invalid Terraform plan"
        print("Staged release rejected: " + reason, file=sys.stderr)
        return 1
    print("Verified stage: stable=100%, candidate=0%, existing secrets unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
