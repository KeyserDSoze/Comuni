#!/usr/bin/env python3
"""Review only: validate a future owner-approved Terraform state handoff plan.

Reads JSON via stdin. NEVER executes Terraform/Azure or accesses live state.
No plan details, resource IDs, URIs, hostnames or secret values are logged.
An accepted plan is NOT approval to apply or proof that revisions have migrated.
"""
import json
import re
import sys

LEGACY = "azurerm_key_vault_secret.postgres_connection"
APP = "azurerm_container_app.main"
LEGACY_APP_SECRET = "postgres-connection"
LEGACY_URI = re.compile(
    r"https://([a-z][a-z0-9-]{2,23}\.vault\.azure\.net)/secrets/postgres-connection\Z",
    re.IGNORECASE,
)
NEW_URI = re.compile(
    r"https://([a-z][a-z0-9-]{2,23}\.vault\.azure\.net)/secrets/postgres-runtime-connection/([0-9a-f]{32})\Z",
    re.IGNORECASE,
)
NEW_APP_SECRET = re.compile(r"pg-[0-9a-f]{16}\Z")


class HandoffRejected(Exception):
    pass


def require(condition):
    if not condition:
        raise HandoffRejected()


def only_entry(entries, name):
    require(isinstance(entries, list))
    matches = [e for e in entries
               if isinstance(e, dict) and e.get("name") == name]
    require(len(matches) == 1)
    return matches[0]


def validate_app(app_before, legacy_uri):
    # A state-only handoff must NOT update the application-scoped secret or
    # any revision. The legacy Key Vault secret must stay in Azure.
    require(isinstance(app_before, dict))
    secret = only_entry(app_before.get("secret"), LEGACY_APP_SECRET)
    require(secret.get("key_vault_secret_id") == legacy_uri)
    require("value" not in secret)

    template = app_before.get("template")
    require(isinstance(template, list) and len(template) == 1
            and isinstance(template[0], dict))
    containers = template[0].get("container")
    require(isinstance(containers, list) and len(containers) == 1
            and isinstance(containers[0], dict))
    default = only_entry(containers[0].get("env"), "ConnectionStrings__Default")
    runtime_name = default.get("secret_name")
    require(isinstance(runtime_name, str)
            and NEW_APP_SECRET.fullmatch(runtime_name)
            and not default.get("value"))
    runtime_secret = only_entry(app_before.get("secret"), runtime_name)
    new_uri = runtime_secret.get("key_vault_secret_id")
    require(isinstance(new_uri, str))
    matching = NEW_URI.fullmatch(new_uri)
    require(matching is not None)
    legacy_vault = LEGACY_URI.fullmatch(legacy_uri).group(1).lower()
    require(matching.group(1).lower() == legacy_vault
            and runtime_name == "pg-" + matching.group(2)[:16].lower())


def validate(plan):
    require(isinstance(plan, dict)
            and plan.get("format_version") == "1.2")
    changes = plan.get("resource_changes")
    require(isinstance(changes, list) and 2 <= len(changes) <= 500)
    require(plan.get("resource_drift", []) == [])
    outputs = plan.get("output_changes", {})
    require(isinstance(outputs, dict))
    for change in outputs.values():
        require(isinstance(change, dict)
                and change.get("actions") == ["no-op"]
                and change.get("before") == change.get("after"))

    found = {}
    for item in changes:
        require(isinstance(item, dict))
        address = item.get("address")
        require(isinstance(address, str) and address
                and address not in found)
        change = item.get("change")
        require(isinstance(change, dict))
        actions = change.get("actions")
        require(isinstance(actions, list))
        require(isinstance(item.get("type"), str) and item.get("type"))
        require(not change.get("importing"))
        if address == LEGACY:
            # "forget" means removal from STATE only; "delete" destroys the
            # actual Azure secret. A missing/null AFTER is mandatory.
            require(item["type"] == "azurerm_key_vault_secret"
                    and actions == ["forget"]
                    and change.get("after") is None
                    and not change.get("after_unknown"))
            before = change.get("before")
            require(isinstance(before, dict)
                    and before.get("name") == LEGACY_APP_SECRET
                    and isinstance(before.get("id"), str) and before["id"])
            uri = before.get("versionless_id")
            require(isinstance(uri, str) and LEGACY_URI.fullmatch(uri))
        else:
            require(actions == ["no-op"]
                    and change.get("before") is not None
                    and change.get("after") == change.get("before")
                    and not change.get("after_unknown"))
            if address == APP:
                require(item["type"] == "azurerm_container_app")
        found[address] = item

    require(LEGACY in found and APP in found)
    app_before = found[APP]["change"]["before"]
    legacy_uri = found[LEGACY]["change"]["before"]["versionless_id"]
    validate_app(app_before, legacy_uri)


def main():
    try:
        # No printing of any source JSON or exception contents: a plan can
        # include the cleartext PostgreSQL admin/runtime passwords in state.
        plan = json.load(sys.stdin)
        validate(plan)
    except (HandoffRejected, KeyError, TypeError, ValueError,
            json.JSONDecodeError):
        print("Legacy PostgreSQL handoff plan rejected: independent owner "
              "review and verified immutable resources are required.",
              file=sys.stderr)
        return 1
    print("Legacy PostgreSQL handoff plan shape verified (read-only). "
          "No state or Azure resource changed; owner approval still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
