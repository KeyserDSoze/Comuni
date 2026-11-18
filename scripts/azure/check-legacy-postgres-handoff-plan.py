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
POSTGRES_ADDRESS = "azurerm_postgresql_flexible_server.main"
AZURE_POSTGRES_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.postgres\.database\.azure\.com\Z"
)


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


def validate_existing_staged_traffic(app, template):
    # This is a READ-ONLY state handoff, not a deployment. Even a Terraform
    # app no-op is unsafe as approval evidence if ACA is ALREADY promoting the
    # candidate or the active revision cannot be identified unambiguously.
    require(app.get("revision_mode") == "Multiple")
    ingress = app.get("ingress")
    require(isinstance(ingress, list) and len(ingress) == 1
            and isinstance(ingress[0], dict))
    weights = ingress[0].get("traffic_weight")
    require(isinstance(weights, list) and len(weights) == 2
            and all(isinstance(w, dict) for w in weights))
    stable = [w for w in weights if w.get("latest_revision") is False]
    candidate = [w for w in weights if w.get("latest_revision") is True]
    require(len(stable) == 1 and len(candidate) == 1)
    stable_weight, candidate_weight = stable[0], candidate[0]

    # Check exact types: bool is an int subclass in Python (True == 1).
    require(type(stable_weight.get("percentage")) is int
            and stable_weight["percentage"] == 100)
    require(type(candidate_weight.get("percentage")) is int
            and candidate_weight["percentage"] == 0)

    stable_suffix = stable_weight.get("revision_suffix")
    candidate_suffix = template.get("revision_suffix")
    require(isinstance(stable_suffix, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]",
                             stable_suffix) is not None)
    require(isinstance(candidate_suffix, str)
            and re.fullmatch(r"r[a-z0-9]{12}", candidate_suffix) is not None
            and candidate_suffix != stable_suffix)
    require(not candidate_weight.get("revision_suffix")
            and candidate_weight.get("label") == candidate_suffix
            and stable_weight.get("label") != candidate_suffix)


def managed_postgres_fqdn(plan):
    # Bind candidate TLS identity to an independently managed Terraform
    # resource, never to a supplied argument, secret or ACA env value.
    planned = plan.get("planned_values")
    require(isinstance(planned, dict))
    root = planned.get("root_module")
    require(isinstance(root, dict))
    resources = root.get("resources")
    require(isinstance(resources, list))
    matching = [resource for resource in resources
                if isinstance(resource, dict)
                and resource.get("address") == POSTGRES_ADDRESS]
    require(len(matching) == 1
            and matching[0].get("type") == "azurerm_postgresql_flexible_server")
    values = matching[0].get("values")
    require(isinstance(values, dict))
    fqdn, name = values.get("fqdn"), values.get("name")
    require(isinstance(fqdn, str)
            and AZURE_POSTGRES_HOST.fullmatch(fqdn) is not None
            and isinstance(name, str)
            and fqdn == name + ".postgres.database.azure.com")
    return fqdn


def validate_app(app_before, legacy_uri, expected_postgres_host):
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
    validate_existing_staged_traffic(app_before, template[0])
    # Even a valid TLS certificate for ANOTHER Azure server is not enough.
    # The bound hostname must be the real managed Flexible Server in this plan.
    expected = only_entry(containers[0].get("env"), "RuntimePostgres__ExpectedHost")
    require(expected.get("value") == expected_postgres_host
            and not expected.get("secret_name"))
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
    validate_app(app_before, legacy_uri, managed_postgres_fqdn(plan))


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
