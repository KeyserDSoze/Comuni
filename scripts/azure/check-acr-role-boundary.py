#!/usr/bin/env python3
"""Read-only Azure ACR RBAC boundary preflight before Docker push.

The managed ACA identity must remain pull-only under legacy registry RBAC;
the GitHub OIDC release principal must be a separate service principal with
an explicit AcrPush assignment. Reject mode drift, admin login, inherited
privilege or ambiguous role assignments before any image build or push.

Azure stdout/stderr (potentially sensitive) never enter workflow logs.
This is role-assignment inspection, not proof of effective data-plane access.
"""
import argparse
import json
import re
import subprocess
import sys

PREFIX = re.compile(r"[a-z][a-z0-9-]{3,17}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)
MAX_RESPONSE = 65536


class RoleBoundaryRejected(Exception):
    """Safe, static messages only."""


def require(ok, reason):
    if not ok:
        raise RoleBoundaryRejected(reason)


def az(*args):
    result = subprocess.run(
        ["az", *args], capture_output=True, text=True, check=False, timeout=30)
    require(result.returncode == 0, "Azure identity/ACR inspection unavailable")
    require(len(result.stdout) <= MAX_RESPONSE, "oversized Azure RBAC response")
    return result.stdout.strip()


def az_json(*args):
    return json.loads(az(*args))


def uuid(value):
    return isinstance(value, str) and bool(UUID.fullmatch(value))


def roles_for(principal, acr_id):
    rows = az_json(
        "role", "assignment", "list",
        "--assignee-object-id", principal, "--scope", acr_id,
        "--all", "--include-inherited",
        "--fill-principal-name", "false",
        "--output", "json", "--only-show-errors")
    require(isinstance(rows, list), "invalid ACR role assignments")
    return rows


def validate_roles(rows, principal, acr_id, allowed_role):
    found = 0
    for row in rows:
        require(isinstance(row, dict) and
                uuid(row.get("principalId")) and
                row["principalId"].casefold() == principal.casefold() and
                isinstance(row.get("scope"), str) and
                isinstance(row.get("roleDefinitionName"), str) and
                row.get("condition") in (None, ""),
                "unexpected or conditional ACR role assignment")
        scope = row["scope"].casefold()
        name = row["roleDefinitionName"]
        # Only a read-only inherited Reader role is tolerated; inherited
        # Contributor/Owner or unknown roles would bypass the intended boundary.
        if scope == acr_id.casefold() and name == allowed_role:
            found += 1
        else:
            require(name == "Reader" and
                    acr_id.casefold().startswith(scope.rstrip("/") + "/"),
                    "unexpected privileged or mismatched ACR role")
    require(found == 1, "missing or ambiguous expected direct ACR role")


def preflight(args):
    require(bool(PREFIX.fullmatch(args.prefix)), "invalid Azure resource prefix")
    expected_registry = (args.prefix.replace("-", "") + "acr")[:50]
    require(args.registry_name == expected_registry and
            args.registry_host == expected_registry + ".azurecr.io",
            "registry does not match the Terraform-managed identity")
    require(uuid(args.deployer_client_id) and uuid(args.infra_client_id)
            and args.deployer_client_id.casefold() != args.infra_client_id.casefold(),
            "registry build and infrastructure OIDC clients must be distinct")

    group = args.prefix + "-rg"
    registry = az_json(
        "acr", "show",
        "--name", expected_registry, "--resource-group", group,
        "--query",
        "{id:id,name:name,loginServer:loginServer,roleAssignmentMode:roleAssignmentMode,adminUserEnabled:adminUserEnabled}",
        "--output", "json", "--only-show-errors")
    require(isinstance(registry, dict) and
            registry.get("name") == expected_registry and
            registry.get("loginServer") == args.registry_host and
            registry.get("roleAssignmentMode") == "rbac" and
            registry.get("adminUserEnabled") is False,
            "managed ACR mode/admin/login server drifted from approved RBAC")
    acr_id = registry.get("id")
    pattern = (r"/subscriptions/[0-9a-f-]{36}/resourceGroups/" +
               re.escape(group) +
               r"/providers/Microsoft\.ContainerRegistry/registries/" +
               re.escape(expected_registry) + r"\Z")
    require(isinstance(acr_id, str) and
            bool(re.fullmatch(pattern, acr_id, re.IGNORECASE)),
            "unexpected managed ACR resource ID")

    app = az_json(
        "identity", "show", "--name", args.prefix + "-app-identity",
        "--resource-group", group,
        "--query", "{principalId:principalId,clientId:clientId}",
        "--output", "json", "--only-show-errors")
    require(isinstance(app, dict) and uuid(app.get("principalId"))
            and uuid(app.get("clientId"))
            and app["clientId"].casefold() != args.deployer_client_id.casefold(),
            "missing or ambiguous pull-only managed identity")
    app_object_id = app["principalId"]
    deployer_object_id = az(
        "ad", "sp", "show", "--id", args.deployer_client_id,
        "--query", "id", "--output", "tsv", "--only-show-errors")
    require(uuid(deployer_object_id) and
            app_object_id.casefold() != deployer_object_id.casefold(),
            "deployment identity must be separate from ACA pull identity")

    validate_roles(roles_for(app_object_id, acr_id),
                   app_object_id, acr_id, "AcrPull")
    validate_roles(roles_for(deployer_object_id, acr_id),
                   deployer_object_id, acr_id, "AcrPush")


def main():
    parser = argparse.ArgumentParser(
        description="Read-only ACR RBAC preflight; no role changes")
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--registry-name", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--deployer-client-id", required=True)
    parser.add_argument("--infra-client-id", required=True)
    args = parser.parse_args()
    try:
        preflight(args)
    except (RoleBoundaryRejected, OSError, ValueError, TypeError,
            UnicodeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        reason = (str(exc) if isinstance(exc, RoleBoundaryRejected)
                  else "invalid or unavailable ACR RBAC metadata")
        print("ACR role preflight rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
