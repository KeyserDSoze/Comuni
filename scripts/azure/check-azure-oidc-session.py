#!/usr/bin/env python3
"""Fail-closed active Azure OIDC service-principal guard for stage boundaries.

After each azure/login OIDC action this verifies the Azure CLI session is
exactly the approved Entra app, tenant and subscription, and that the other
release-phase app has a DIFFERENT client ID. It never logs CLI output,
credentials, account IDs or token-related metadata. It does not prove an
isolated runner or actual effective RBAC permissions.
"""
import argparse
import json
import re
import subprocess
import sys

UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)
MAX_RESPONSE = 32768


class SessionRejected(Exception):
    """Only static, safe errors may be exposed."""


def require(ok, reason):
    if not ok:
        raise SessionRejected(reason)


def uuid(value):
    return isinstance(value, str) and bool(UUID.fullmatch(value))


def check(args):
    require(all(uuid(value) for value in (
        args.expected_client_id, args.other_client_id,
        args.expected_tenant_id, args.expected_subscription_id,
    )), "missing or invalid Azure OIDC identity metadata")
    require(args.expected_client_id.casefold() != args.other_client_id.casefold(),
            "build and infrastructure OIDC clients must be distinct")

    result = subprocess.run(
        ["az", "account", "show",
         "--query", "{id:id,tenantId:tenantId,user:user}",
         "--output", "json", "--only-show-errors"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    require(result.returncode == 0, "active Azure CLI service principal unavailable")
    require(len(result.stdout) <= MAX_RESPONSE, "oversized Azure CLI account metadata")
    account = json.loads(result.stdout)
    require(isinstance(account, dict), "ambiguous Azure CLI session")
    user = account.get("user")
    require(isinstance(user, dict)
            and user.get("type") == "servicePrincipal"
            and uuid(user.get("name"))
            and user["name"].casefold() == args.expected_client_id.casefold(),
            "active Azure CLI principal does not match this release phase")
    require(uuid(account.get("tenantId"))
            and account["tenantId"].casefold() == args.expected_tenant_id.casefold()
            and uuid(account.get("id"))
            and account["id"].casefold() == args.expected_subscription_id.casefold(),
            "active Azure CLI tenant/subscription differs from approved environment")


def main():
    parser = argparse.ArgumentParser(
        description="Verify Azure OIDC phase identity before any privileged actions")
    parser.add_argument("--expected-client-id", required=True)
    parser.add_argument("--other-client-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-subscription-id", required=True)
    args = parser.parse_args()
    try:
        check(args)
    except (SessionRejected, OSError, UnicodeError, TypeError,
            ValueError, subprocess.TimeoutExpired) as error:
        message = (str(error) if isinstance(error, SessionRejected)
                   else "unavailable or invalid Azure CLI account metadata")
        print("Azure OIDC phase rejected: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
