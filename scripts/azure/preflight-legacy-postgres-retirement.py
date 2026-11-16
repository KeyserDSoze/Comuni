#!/usr/bin/env python3
"""Read-only, fail-closed inventory before any LEGACY PostgreSQL secret retirement.

All stored Container Apps revisions are inspected, including inactive ones.
This is an operator-facing PRECHECK, not a secret deletion or state migration.
No secret values, revision payloads, resource names, or Azure errors are logged.
"""
import argparse
import json
import re
import subprocess
import sys

APP_NAME = re.compile(r"[a-z][a-z0-9-]{2,30}[a-z0-9]\Z")
RESOURCE_GROUP = re.compile(r"[a-z][a-z0-9-]{2,60}[a-z0-9]\Z")
REVISION_SUFFIX = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
PINNED_RUNTIME_SECRET = re.compile(r"pg-[0-9a-f]{16}\Z")
LEGACY_SECRET = "postgres-connection"
MAX_REVISIONS = 200


class PreflightRejected(Exception):
    """Never include any user, Azure, or secret data in the exception."""


def require(valid):
    if not valid:
        raise PreflightRejected()


def az_metadata(*args):
    # Explicit CLI arguments, no shell=True, and no raw Azure response in logs.
    try:
        result = subprocess.run(
            ["az", *args, "--output", "json", "--only-show-errors"],
            capture_output=True, text=True, timeout=30, check=True,
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, UnicodeError):
        raise PreflightRejected() from None


def check_revision(revision, expected_name):
    require(isinstance(revision, dict) and revision.get("name") == expected_name)
    properties = revision.get("properties")
    require(isinstance(properties, dict) and type(properties.get("active")) is bool)
    template = properties.get("template")
    require(isinstance(template, dict))
    containers = template.get("containers")
    # The single API/PWA contains one container. Missing templates/containers
    # cannot be interpreted as proof of no legacy secret references.
    require(isinstance(containers, list) and len(containers) == 1
            and isinstance(containers[0], dict))
    env = containers[0].get("env")
    require(isinstance(env, list))
    db_connection_count = 0
    for entry in env:
        require(isinstance(entry, dict) and isinstance(entry.get("name"), str))
        reference = entry.get("secretRef")
        require(reference is None or isinstance(reference, str))
        # An alternative env var can still consume the old app-scoped secret.
        require(not isinstance(reference, str)
                or reference.lower() != LEGACY_SECRET)
        if entry["name"] == "ConnectionStrings__Default":
            db_connection_count += 1
            require(isinstance(reference, str)
                    and PINNED_RUNTIME_SECRET.fullmatch(reference)
                    and not entry.get("value"))
    require(db_connection_count == 1)
    return properties["active"]


def check(app, resource_group):
    require(bool(APP_NAME.fullmatch(app)) and app.endswith("-app")
            and "--" not in app)
    require(bool(RESOURCE_GROUP.fullmatch(resource_group))
            and resource_group == app[:-4] + "-rg"
            and "--" not in resource_group)

    # By default CLI omits inactive revisions, which may be reactivated.
    # Explicit --all is mandatory before any decision to retire a secret.
    entries = az_metadata(
        "containerapp", "revision", "list",
        "--name", app, "--resource-group", resource_group, "--all",
    )
    require(isinstance(entries, list)
            and 1 <= len(entries) <= MAX_REVISIONS)
    names = set()
    active_count = 0
    for entry in entries:
        require(isinstance(entry, dict))
        name = entry.get("name")
        require(isinstance(name, str) and name.startswith(app + "-"))
        suffix = name[len(app) + 1:]
        require(bool(REVISION_SUFFIX.fullmatch(suffix))
                and "--" not in suffix and name not in names)
        listed_properties = entry.get("properties")
        require(isinstance(listed_properties, dict)
                and type(listed_properties.get("active")) is bool)
        names.add(name)
        # revision list may present a summary; revision show is authoritative
        # for the full immutable container env and its secretRefs.
        full = az_metadata(
            "containerapp", "revision", "show",
            "--name", app, "--resource-group", resource_group,
            "--revision", name,
        )
        active = check_revision(full, name)
        require(active == listed_properties["active"])
        if active:
            active_count += 1
    require(active_count > 0)


def main():
    parser = argparse.ArgumentParser(
        description="Read-only inventory of every stored ACA revision before "
                    "approved legacy PostgreSQL secret retirement"
    )
    parser.add_argument("--app", required=True)
    parser.add_argument("--resource-group", required=True)
    args = parser.parse_args()
    try:
        check(args.app, args.resource_group)
    except PreflightRejected:
        print("Legacy PostgreSQL preflight blocked: revision metadata or "
              "secret references cannot be verified.", file=sys.stderr)
        return 1
    print("Legacy PostgreSQL revision inventory passed (read-only). "
          "No secret or state was changed; owner approval is still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
