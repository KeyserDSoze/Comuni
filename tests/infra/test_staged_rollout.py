"""Contract and adversarial Terraform-plan tests for zero-traffic ACA staging.

These run without Azure credentials and never access signing keys or actual state.
"""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = (ROOT / "infra/main.tf").read_text()
VARIABLES = (ROOT / "infra/variables.tf").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
PLAN_GATE = ROOT / "scripts/azure/check-staged-rollout-plan.py"
STABLE_VERSION = "a" * 32
CANDIDATE_VERSION = "b" * 32
STABLE_REVISION = "stable001"
CANDIDATE_REVISION = "r123456789abc"
CANDIDATE_KEY_ID = "rotate2026"
RUNTIME_POSTGRES_VERSION = "d" * 32
VAULT_URI = "https://comuni-itn-001-kv.vault.azure.net/"


def fixture_plan():
    identity_id = "/subscriptions/synthetic/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/comuni-app"
    old_secret = {
        "identity": identity_id,
        "name": "tenant-proof-key",
        "key_vault_secret_id": VAULT_URI + "secrets/tenant-proof-key/" + STABLE_VERSION,
    }
    candidate_secret = {
        "identity": identity_id,
        "name": "tp-" + CANDIDATE_VERSION[:16],
        "key_vault_secret_id": VAULT_URI + "secrets/tenant-proof-key/" + CANDIDATE_VERSION,
    }
    runtime_connection = {
        "identity": identity_id,
        "name": "pg-" + RUNTIME_POSTGRES_VERSION[:16],
        "key_vault_secret_id": VAULT_URI + "secrets/postgres-runtime-connection/" + RUNTIME_POSTGRES_VERSION,
    }
    shared = {
        "identity": [{"type": "UserAssigned", "identity_ids": [identity_id]}],
        "registry": [{"server": "synthetic.azurecr.io", "identity": identity_id}],
        "container_app_environment_id": "/subscriptions/synthetic/containerAppEnvironment",
    }
    ingress_settings = {"external_enabled": True, "target_port": 8080, "transport": "auto"}
    before = {
        **copy.deepcopy(shared),
        "revision_mode": "Single",
        "secret": [copy.deepcopy(old_secret)],
        "ingress": [{**ingress_settings, "traffic_weight": [{"latest_revision": True, "percentage": 100}]}],
    }
    after = {
        **copy.deepcopy(shared),
        "revision_mode": "Multiple",
        "secret": [copy.deepcopy(old_secret), copy.deepcopy(candidate_secret), copy.deepcopy(runtime_connection)],
        "template": [{
            "revision_suffix": CANDIDATE_REVISION,
            "min_replicas": 1,
            "container": [{
                "env": [
                    {"name": "Security__TenantProofKey", "secret_name": candidate_secret["name"]},
                    {"name": "Security__TenantProofKeyId", "value": CANDIDATE_KEY_ID},
                    {"name": "ConnectionStrings__Default", "secret_name": runtime_connection["name"]},
                ],
            }],
        }],
        "ingress": [{
            **ingress_settings,
            "traffic_weight": [
                {"latest_revision": False, "revision_suffix": STABLE_REVISION, "percentage": 100},
                {"latest_revision": True, "revision_suffix": None, "percentage": 0, "label": CANDIDATE_REVISION},
            ],
        }],
    }
    # The exact host trust anchor comes from Terraform's MANAGED PostgreSQL
    # Flexible Server planned values, not the external Key Vault secret.
    after["template"][0]["container"][0]["env"].append(
        {"name": "RuntimePostgres__ExpectedHost",
         "value": "comuni-itn-001-pg.postgres.database.azure.com"}
    )
    return {
        "planned_values": {"root_module": {"resources": [{
            "address": "azurerm_postgresql_flexible_server.main",
            "type": "azurerm_postgresql_flexible_server",
            "values": {
                "name": "comuni-itn-001-pg",
                "fqdn": "comuni-itn-001-pg.postgres.database.azure.com",
            },
        }]}},
        "format_version": "1.2",
        "resource_changes": [{
            "address": "azurerm_container_app.main",
            "type": "azurerm_container_app",
            "change": {"actions": ["update"], "before": before, "after": after},
        }],
    }


class StagedRolloutTests(unittest.TestCase):
    def test_terraform_stages_candidate_without_moving_production_traffic(self):
        self.assertRegex(TERRAFORM, r'revision_mode\s*=\s*"Multiple"')
        self.assertIn("revision_suffix = var.candidate_revision_suffix", TERRAFORM)
        self.assertRegex(TERRAFORM, r'min_replicas\s*=\s*1')
        self.assertIn("revision_suffix = var.stable_revision_suffix", TERRAFORM)
        self.assertIn("label           = var.candidate_revision_suffix", TERRAFORM)
        self.assertRegex(TERRAFORM, r'percentage\s*=\s*0\s+latest_revision\s*=\s*true')
        self.assertNotRegex(TERRAFORM, r'percentage\s*=\s*100\s+latest_revision\s*=\s*true')
        for name in ("stable_revision_suffix", "candidate_revision_suffix", "stable_tenant_proof_secret_version"):
            self.assertRegex(VARIABLES, r'variable\s+"' + name + r'"\s*\{')

    def test_stable_secret_retained_and_candidate_uses_distinct_versioned_name(self):
        self.assertIn("var.stable_tenant_proof_secret_version", TERRAFORM)
        self.assertIn('name                = "tenant-proof-key"', TERRAFORM)
        self.assertIn("tp-${substr(var.tenant_proof_secret_version, 0, 16)}", TERRAFORM)
        self.assertIn("var.tenant_proof_secret_version", TERRAFORM)
        self.assertRegex(TERRAFORM, r'secret_name\s*=\s*"tp-')
        self.assertNotRegex(TERRAFORM, r'name\s*=\s*"Security__TenantProofKey"\s+secret_name\s*=\s*"tenant-proof-key"')

    def test_deployment_requires_explicit_stable_revision_and_stable_key_version(self):
        self.assertIn("TF_VAR_stable_revision_suffix:", DEPLOY)
        self.assertIn("TF_VAR_stable_tenant_proof_secret_version:", DEPLOY)
        self.assertIn("TF_VAR_candidate_revision_suffix=", DEPLOY)
        self.assertIn("scripts/azure/check-staged-rollout-plan.py", DEPLOY)
        self.assertIn("terraform -chdir=infra show -json deploy.tfplan", DEPLOY)
        self.assertLess(DEPLOY.index("check-staged-rollout-plan.py"), DEPLOY.index("terraform -chdir=infra apply"))
        self.assertIn('scripts/azure/check-tenant-proof-secret.sh', DEPLOY)

    def gate(self, plan, stable=STABLE_REVISION, candidate=CANDIDATE_REVISION):
        if not PLAN_GATE.is_file():
            return subprocess.CompletedProcess([], 127, "", "plan gate missing")
        return subprocess.run(
            [sys.executable, str(PLAN_GATE),
             "--stable-revision", stable, "--candidate-revision", candidate,
             "--stable-secret-version", STABLE_VERSION,
             "--candidate-secret-version", CANDIDATE_VERSION,
             "--candidate-key-id", CANDIDATE_KEY_ID,
             "--runtime-secret-version", RUNTIME_POSTGRES_VERSION],
            input=json.dumps(plan), capture_output=True, text=True, check=False,
        )

    def test_aca_candidate_secret_name_max_twenty_and_full_pinned_uri(self):
        fixture = fixture_plan()
        secret = fixture["resource_changes"][0]["change"]["after"]["secret"][1]
        self.assertLessEqual(len(secret["name"]), 20)
        self.assertEqual("tp-" + CANDIDATE_VERSION[:16], secret["name"])
        self.assertIn("secrets/tenant-proof-key/" + CANDIDATE_VERSION,
                      secret["key_vault_secret_id"])
        self.assertIn("substr(var.tenant_proof_secret_version, 0, 16)", TERRAFORM)

    def test_aca_candidate_prefix_collision_cannot_replace_stable_secret(self):
        plan = fixture_plan()
        change = plan["resource_changes"][0]["change"]
        old_version = CANDIDATE_VERSION[:16] + "d" * 16
        change["before"]["secret"].append({
            "name": "tp-" + CANDIDATE_VERSION[:16],
            "key_vault_secret_id": VAULT_URI + "secrets/tenant-proof-key/" + old_version,
        })
        self.assertNotEqual(0, self.gate(plan).returncode)

    def test_valid_update_to_0_percent_candidate_is_accepted(self):
        response = self.gate(fixture_plan())
        self.assertEqual(0, response.returncode, response.stderr)
        self.assertNotIn("signing_key", response.stdout)
        self.assertNotIn("tp-" + CANDIDATE_VERSION[:16], response.stdout)

    def test_missing_previous_revision_or_replacing_container_app_is_rejected(self):
        for plan in [
            {},
            {"resource_changes": []},
            fixture_plan(),
            fixture_plan(),
        ]:
            if "resource_changes" in plan and plan["resource_changes"]:
                change = plan["resource_changes"][0]["change"]
                if change["before"] is not None and change["actions"] == ["update"]:
                    change["before"] = None
                else:
                    change["actions"] = ["delete", "create"]
            self.assertNotEqual(0, self.gate(plan).returncode)
        plan = fixture_plan()
        plan["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        self.assertNotEqual(0, self.gate(plan).returncode)

    def test_destruction_of_any_other_infrastructure_resource_is_rejected(self):
        plan = fixture_plan()
        plan["resource_changes"].append({
            "address": "azurerm_postgresql_flexible_server.main",
            "type": "azurerm_postgresql_flexible_server",
            "change": {"actions": ["delete"], "before": {"id": "pg-id"}, "after": None},
        })
        self.assertNotEqual(0, self.gate(plan).returncode)
        plan["resource_changes"][-1]["change"]["actions"] = ["delete", "create"]
        self.assertNotEqual(0, self.gate(plan).returncode)

    def test_secret_mutation_missing_or_wrong_candidate_version_is_rejected(self):
        cases = []
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["secret"][0]["key_vault_secret_id"] = (
            VAULT_URI + "secrets/tenant-proof-key/" + CANDIDATE_VERSION)
        cases.append(p)
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["secret"].pop(0)
        cases.append(p)
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["secret"][1]["key_vault_secret_id"] = (
            VAULT_URI + "secrets/tenant-proof-key/" + "c" * 32)
        cases.append(p)
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][0]["secret_name"] = (
            "tenant-proof-key")
        cases.append(p)
        for plan in cases:
            self.assertNotEqual(0, self.gate(plan).returncode)

    def test_plan_rejects_candidate_label_missing_or_pointing_elsewhere(self):
        plan = fixture_plan()
        plan["resource_changes"][0]["change"]["after"]["ingress"][0]["traffic_weight"][1].pop("label")
        self.assertNotEqual(0, self.gate(plan).returncode)
        plan = fixture_plan()
        plan["resource_changes"][0]["change"]["after"]["ingress"][0]["traffic_weight"][1]["label"] = "stable"
        self.assertNotEqual(0, self.gate(plan).returncode)
        plan = fixture_plan()
        plan["resource_changes"][0]["change"]["after"]["ingress"][0]["traffic_weight"][0]["label"] = CANDIDATE_REVISION
        self.assertNotEqual(0, self.gate(plan).returncode)

    def test_auto_promotion_wrong_suffix_and_missing_key_id_are_rejected(self):
        cases = []
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["ingress"][0]["traffic_weight"][1]["percentage"] = 100
        cases.append(p)
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["ingress"][0]["traffic_weight"][0]["revision_suffix"] = "wrong"
        cases.append(p)
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][1]["value"] = "forged"
        cases.append(p)
        p = fixture_plan()
        p["resource_changes"][0]["change"]["after"]["revision_mode"] = "Single"
        cases.append(p)
        for plan in cases:
            self.assertNotEqual(0, self.gate(plan).returncode)

    def test_gate_does_not_echo_plan_json_or_secrets(self):
        script = PLAN_GATE.read_text() if PLAN_GATE.exists() else ""
        self.assertNotIn("print(json.dumps(plan", script)
        self.assertNotIn("print(plan)", script)
        self.assertNotIn("set -x", DEPLOY)


if __name__ == "__main__":
    unittest.main()
