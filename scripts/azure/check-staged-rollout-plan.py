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
POSTGRES_ADDRESS = "azurerm_postgresql_flexible_server.main"
REGISTRY_ADDRESS = "azurerm_container_registry.main"
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REGISTRY_NAME = re.compile(r"[a-z0-9]{5,50}\Z")
AZURE_POSTGRES_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.postgres\.database\.azure\.com\Z"
)
STABLE_SECRET = "tenant-proof-key"
PLATFORM_INVENTORY_SECRET = "platform-inventory-connection"
RUNTIME_POSTGRES_SECRET = "postgres-runtime-connection"
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


def platform_inventory_version_uri(value, version, trusted_vault_host):
    """Pinned Key Vault URI, same vault as the tenant-proof-key candidate."""
    if not isinstance(value, str) or not isinstance(trusted_vault_host, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and parsed.netloc == trusted_vault_host
        and (parsed.path or "").lower()
            == ("/secrets/" + PLATFORM_INVENTORY_SECRET + "/" + version).lower()
        and not parsed.query and not parsed.fragment and not parsed.username
        and not parsed.password
    )


def runtime_postgres_version_uri(value, version, trusted_vault_host):
    """The candidate SQL URI must be pinned to the SAME approved Key Vault."""
    if not isinstance(value, str) or not isinstance(trusted_vault_host, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and parsed.netloc == trusted_vault_host
        and (parsed.path or "").lower()
            == ("/secrets/" + RUNTIME_POSTGRES_SECRET + "/" + version).lower()
        and not parsed.query and not parsed.fragment and not parsed.username
        and not parsed.password
    )


def validate_hosted_oidc_environment(env):
    """Reject ambiguous ACA env keys before .NET configuration is assembled.

    Azure Container Apps can take the last duplicate; ASP.NET Core configuration
    keys ignore case and normalize "__" to ":". Treat every conflicting key as
    an invalid release, even when the original exact-name key looks safe.
    """
    require(isinstance(env, list) and len(env) > 0,
            "invalid candidate environment variables")
    indexed = {}
    for entry in env:
        require(isinstance(entry, dict) and isinstance(entry.get("name"), str),
                "malformed candidate environment variable")
        name = entry["name"]
        require(bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)),
                "invalid or noncanonical environment variable name")
        normalized = name.replace("__", ":").casefold()
        require(normalized not in indexed,
                "duplicate ASP.NET Core configuration key in candidate")
        indexed[normalized] = entry

    # DOTNET_ENVIRONMENT may override ASPNETCORE_ENVIRONMENT in WebApplication.
    # This candidate must not provide a second source of environment selection.
    require("dotnet_environment" not in indexed,
            "candidate cannot override hosted environment selection")

    def plain_value(key):
        entry = indexed.get(key.replace("__", ":").casefold())
        require(isinstance(entry, dict) and isinstance(entry.get("value"), str)
                and not entry.get("secret_name"),
                "missing or non-plain required hosted OIDC setting")
        return entry["value"]

    require(plain_value("ASPNETCORE_ENVIRONMENT") == "Production",
            "candidate must run with Production environment")
    require(plain_value("Authentication__Mode") == "Oidc",
            "candidate must enforce OIDC token validation")

    authority = plain_value("Authentication__Authority")
    parsed = urlparse(authority)
    require(bool(authority) and authority == authority.strip()
            and not any(char.isspace() for char in authority)
            and parsed.scheme == "https" and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment,
            "candidate OIDC authority must be an HTTPS issuer without credentials")

    audience = plain_value("Authentication__Audience")
    require(bool(audience) and not any(char.isspace() for char in audience),
            "candidate OIDC audience must be explicit and nonempty")


def managed_postgres_fqdn(plan):
    """Trust only the managed Flexible Server in Terraform planned_values.

    Neither an operator variable nor the Key Vault secret can supply this
    expected host. Never echo Terraform state or its sensitive values.
    """
    planned = plan.get("planned_values") if isinstance(plan, dict) else None
    root = planned.get("root_module") if isinstance(planned, dict) else None
    resources = root.get("resources") if isinstance(root, dict) else None
    require(isinstance(resources, list), "missing managed PostgreSQL plan metadata")
    matching = [resource for resource in resources if isinstance(resource, dict)
                and resource.get("address") == POSTGRES_ADDRESS]
    require(len(matching) == 1 and matching[0].get("type") ==
            "azurerm_postgresql_flexible_server",
            "missing or ambiguous authorized PostgreSQL resource")
    values = matching[0].get("values")
    require(isinstance(values, dict), "missing PostgreSQL planned values")
    fqdn, name = values.get("fqdn"), values.get("name")
    require(isinstance(fqdn, str) and bool(AZURE_POSTGRES_HOST.fullmatch(fqdn))
            and isinstance(name, str)
            and fqdn == name + ".postgres.database.azure.com",
            "invalid approved PostgreSQL server FQDN")
    return fqdn


def managed_acr_login_server(plan):
    """Only the managed ACR in Terraform planned_values is a trusted image source.

    Never trust a registry host copied from template.container.image, runtime
    app registry alone, or an operator-controlled Terraform variable.
    """
    planned = plan.get("planned_values") if isinstance(plan, dict) else None
    root = planned.get("root_module") if isinstance(planned, dict) else None
    resources = root.get("resources") if isinstance(root, dict) else None
    require(isinstance(resources, list), "missing managed ACR plan metadata")
    matching = [resource for resource in resources if isinstance(resource, dict)
                and resource.get("address") == REGISTRY_ADDRESS]
    require(len(matching) == 1 and matching[0].get("type") ==
            "azurerm_container_registry",
            "missing or ambiguous authorized container registry")
    values = matching[0].get("values")
    require(isinstance(values, dict), "invalid managed container registry metadata")
    name, host = values.get("name"), values.get("login_server")
    require(isinstance(name, str) and bool(REGISTRY_NAME.fullmatch(name))
            and isinstance(host, str) and host == name + ".azurecr.io",
            "invalid managed container registry identity")
    return host


def validate(plan, args):
    require(bool(VERSION.fullmatch(args.runtime_secret_version)),
            "candidate runtime PostgreSQL requires explicit pinned Key Vault version")
    require(args.inventory_enabled in ("true", "false"),
            "invalid inventory activation flag")
    enable_inventory = args.inventory_enabled == "true"
    require(not enable_inventory or bool(VERSION.fullmatch(args.inventory_secret_version)),
            "inventory stage requires explicit pinned Key Vault version")
    require(args.inventory_secret_version == "" or
            bool(VERSION.fullmatch(args.inventory_secret_version)),
            "invalid inventory version metadata")

    for version in (args.stable_secret_version, args.candidate_secret_version):
        require(bool(VERSION.fullmatch(version)), "invalid pinned secret version")
    require(bool(KEY_ID.fullmatch(args.candidate_key_id)), "invalid candidate key ID")
    for suffix in (args.stable_revision, args.candidate_revision):
        require(bool(SUFFIX.fullmatch(suffix)) and "--" not in suffix,
                "invalid or missing revision suffix")
    require(args.stable_revision != args.candidate_revision,
            "candidate cannot equal stable revision")
    require(bool(SOURCE_COMMIT.fullmatch(args.source_commit_sha)),
            "source commit must be an exact lowercase 40-hex Git SHA")
    require(args.candidate_revision == "r" + args.source_commit_sha[:12],
            "candidate revision must derive from the approved source commit")
    require(bool(OCI_DIGEST.fullmatch(args.candidate_image_digest)),
            "candidate requires an externally verified OCI manifest digest")

    expected_postgres_host = managed_postgres_fqdn(plan)
    managed_registry_host = managed_acr_login_server(plan)
    changes = plan.get("resource_changes", []) if isinstance(plan, dict) else []
    require(isinstance(changes, list), "missing Terraform changes")
    # The approved 0%-traffic stage is NOT a general infrastructure release.
    # Terraform apply follows this gate without a second review: only the ONE
    # Container App is allowed to change. Passwords, database, network, Key
    # Vault, RBAC, identities, ACR and state-removal actions must remain NO-OP.
    # Even external state drift requires a separate audited change procedure.
    drift = plan.get("resource_drift", []) if isinstance(plan, dict) else []
    require(isinstance(drift, list) and not drift,
            "infrastructure drift requires separate review before candidate staging")
    output_changes = plan.get("output_changes", {}) if isinstance(plan, dict) else {}
    require(isinstance(output_changes, dict),
            "invalid Terraform output changes")
    for output in output_changes.values():
        require(isinstance(output, dict) and output.get("actions") == ["no-op"],
                "Terraform output changes require separate review")

    addresses = set()
    for item in changes:
        require(isinstance(item, dict) and isinstance(item.get("change"), dict),
                "unrecognized planned resource change")
        address = item.get("address")
        require(isinstance(address, str) and bool(address) and address not in addresses,
                "missing or duplicated Terraform resource address")
        addresses.add(address)
        actions = item["change"].get("actions")
        require(isinstance(actions, list), "invalid Terraform action list")
        if address == APP_ADDRESS:
            require(item.get("type") == "azurerm_container_app" and actions == ["update"],
                    "only an existing Container App update may stage a candidate")
        else:
            require(isinstance(item.get("type"), str) and bool(item["type"])
                    and actions == ["no-op"],
                    "non-Container App resources must be unchanged during staging")
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

    # A Container App has revision-scoped templates but app-scoped identities,
    # registry credentials, ingress and secrets. Do not mutate these under a
    # zero-traffic stage: they may affect the currently serving stable revision.
    assigned = one_block(before, "identity")
    assigned_ids = assigned.get("identity_ids")
    require(assigned.get("type") == "UserAssigned"
            and isinstance(assigned_ids, list) and len(assigned_ids) == 1
            and isinstance(assigned_ids[0], str) and bool(assigned_ids[0]),
            "existing ACA must use one approved user-assigned identity")
    managed_identity = assigned_ids[0]
    require(after.get("identity") == before.get("identity"),
            "staging cannot change the app-scoped managed identity")

    existing_registry = before.get("registry")
    require(isinstance(existing_registry, list) and len(existing_registry) == 1
            and isinstance(existing_registry[0], dict)
            and existing_registry[0].get("identity") == managed_identity
            and isinstance(existing_registry[0].get("server"), str)
            and bool(existing_registry[0]["server"]),
            "existing ACA registry must use the approved managed identity")
    require(after.get("registry") == existing_registry,
            "staging cannot modify app-scoped registry credentials or source")
    require(existing_registry[0]["server"] == managed_registry_host,
            "existing ACA image registry must match the managed ACR")

    environment_id = before.get("container_app_environment_id")
    require(isinstance(environment_id, str) and bool(environment_id)
            and after.get("container_app_environment_id") == environment_id,
            "staging cannot change the Container Apps environment")

    before_ingress = one_block(before, "ingress")
    after_ingress = one_block(after, "ingress")
    require({k: v for k, v in before_ingress.items() if k != "traffic_weight"}
            == {k: v for k, v in after_ingress.items() if k != "traffic_weight"},
            "staging cannot modify shared ingress settings outside traffic weights")

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
        require(existing == current,
                "staging may not change or remove an existing app-scoped secret")

    candidate_name = "tp-" + args.candidate_secret_version[:16]
    candidate_secret = named(after_secrets, candidate_name)
    require(secret_version_uri(candidate_secret.get("key_vault_secret_id"),
                               args.candidate_secret_version),
            "candidate secret must reference its own approved pinned version")
    require(candidate_name != STABLE_SECRET,
            "candidate must use a separate app-scoped secret name")

    runtime_secret_name = "pg-" + args.runtime_secret_version[:16]
    runtime_secret = named(after_secrets, runtime_secret_name)
    trusted_vault = urlparse(candidate_secret["key_vault_secret_id"]).netloc
    require(runtime_postgres_version_uri(
        runtime_secret.get("key_vault_secret_id"),
        args.runtime_secret_version, trusted_vault),
        "candidate PostgreSQL runtime must use its own pinned version in the same vault")
    require(runtime_secret_name not in (STABLE_SECRET, "postgres-connection", candidate_name),
            "candidate PostgreSQL runtime must use an independent app-scoped secret name")

    inventory_secret_name = "pi-" + args.inventory_secret_version[:16]
    if enable_inventory:
        inventory_secret = named(after_secrets, inventory_secret_name)
        trusted_vault = urlparse(candidate_secret["key_vault_secret_id"]).netloc
        require(platform_inventory_version_uri(inventory_secret.get("key_vault_secret_id"),
                                                args.inventory_secret_version,
                                                trusted_vault),
                "platform inventory must use approved pinned version in the same vault")

    # Reject new app-scoped secrets unrelated to this release, even if they
    # appear benign. Existing secret names/URIs remain immutable in either mode.
    existing_names = {item["name"] for item in before_secrets}
    allowed_new = {candidate_name, runtime_secret_name}
    if enable_inventory:
        allowed_new.add(inventory_secret_name)
    for item in after_secrets:
        require(isinstance(item, dict) and isinstance(item.get("name"), str),
                "invalid candidate secret definition")
        require(item["name"] in existing_names or item["name"] in allowed_new,
                "unexpected new application secret in stage")
        if item["name"] not in existing_names:
            require(item.get("identity") == managed_identity,
                    "new ACA secret must use the approved managed identity")

    template = one_block(after, "template")
    # A malicious init container can run even when the sole primary image
    # matches the approved SHA; never allow a second workload image in stage.
    init_containers = template.get("init_container", [])
    require(init_containers is None or
            (isinstance(init_containers, list) and len(init_containers) == 0),
            "candidate cannot add init-container images during staging")
    require(template.get("revision_suffix") == args.candidate_revision,
            "unexpected candidate revision suffix")
    require(isinstance(template.get("min_replicas"), int) and
            template["min_replicas"] >= 1,
            "candidate must remain running for zero-traffic smoke testing")
    containers = template.get("container", [])
    require(isinstance(containers, list) and len(containers) == 1 and
            isinstance(containers[0], dict),
            "expected single API + SPA container")
    validate_hosted_oidc_environment(containers[0].get("env"))
    # Digest is received separately from the Docker push + authenticated ACR
    # match in the workflow. A mutable tag is never deployable, even if it
    # bears the same source commit SHA.
    require(containers[0].get("image") ==
            managed_registry_host + "/comuni@" + args.candidate_image_digest,
            "candidate image must match the approved OCI digest in managed ACR")
    proof = named(containers[0].get("env", []), "Security__TenantProofKey")
    proof_id = named(containers[0].get("env", []), "Security__TenantProofKeyId")
    require(proof.get("secret_name") == candidate_name and not proof.get("value"),
            "candidate API must use only its own versioned secret reference")
    require(proof_id.get("value") == args.candidate_key_id and
            not proof_id.get("secret_name"),
            "candidate key ID must match approved PostgreSQL verifier ID")

    # Exact authorized Flexible Server FQDN must be wired as ordinary
    # non-secret Terraform resource metadata, with no alternate secret ref.
    expected_host = named(containers[0].get("env", []), "RuntimePostgres__ExpectedHost")
    require(expected_host.get("value") == expected_postgres_host and
            not expected_host.get("secret_name"),
            "candidate expected PostgreSQL host must match managed resource")

    # The municipal runtime MUST NOT receive an inline connection string,
    # a versionless stable secret, or the privileged platform reader credential.
    db_connection = named(containers[0].get("env", []), "ConnectionStrings__Default")
    require(db_connection.get("secret_name") == runtime_secret_name and
            not db_connection.get("value"),
            "candidate runtime must use only its approved pinned PostgreSQL secret")

    # No JWT claim or tenant context may activate this setting; only the
    # explicitly approved workflow option selects a platform-read secret.
    env = containers[0].get("env", [])
    require(isinstance(env, list), "invalid container environment")
    inventory_flags = [e for e in env if isinstance(e, dict)
                       and e.get("name") == "PlatformInventory__Enabled"]
    require(len(inventory_flags) <= 1, "ambiguous inventory activation flag")
    if enable_inventory:
        flag = named(env, "PlatformInventory__Enabled")
        require(flag.get("value") == "true" and not flag.get("secret_name"),
                "approved inventory enablement missing from candidate")
        connection = named(env, "ConnectionStrings__PlatformRead")
        require(connection.get("secret_name") == inventory_secret_name and
                not connection.get("value"),
                "platform inventory connection must use approved ACA Key Vault secret")
    else:
        # Missing flag is fail-closed for legacy revision plans; new templates
        # explicitly set the flag to false. A connection env is never allowed.
        if inventory_flags:
            require(inventory_flags[0].get("value") == "false" and
                    not inventory_flags[0].get("secret_name"),
                    "inventory must remain disabled by default")
        require(not any(isinstance(e, dict) and
                        e.get("name") == "ConnectionStrings__PlatformRead"
                        for e in env),
                "disabled candidate must not receive platform DB credentials")

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
    # The direct canary label must route to the current latest (0%-weight)
    # only, never to stable or a different revision.
    require(candidate[0].get("label") == args.candidate_revision,
            "candidate label must be pinned to the approved immutable suffix")
    require(stable[0].get("label") != args.candidate_revision,
            "candidate label must not select the stable revision")


def main():
    parser = argparse.ArgumentParser(
        description="Validate staged ACA Terraform plan without emitting state or secrets"
    )
    parser.add_argument("--stable-revision", required=True)
    parser.add_argument("--candidate-revision", required=True)
    parser.add_argument("--source-commit-sha", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--stable-secret-version", required=True)
    parser.add_argument("--candidate-secret-version", required=True)
    parser.add_argument("--candidate-key-id", required=True)
    parser.add_argument("--runtime-secret-version", required=True)
    parser.add_argument("--inventory-enabled", default="false")
    parser.add_argument("--inventory-secret-version", default="")
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
