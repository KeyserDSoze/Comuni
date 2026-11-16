"""RED-first: ACA 0%-traffic staging must mutate ONLY the single Container App.

All examples are synthetic; never load Azure state, Key Vault, or passwords.
"""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from test_staged_rollout import (
    fixture_plan, STABLE_REVISION, CANDIDATE_REVISION,
    STABLE_VERSION, CANDIDATE_VERSION, CANDIDATE_KEY_ID,
    RUNTIME_POSTGRES_VERSION, SOURCE_COMMIT_SHA, SOURCE_IMAGE_DIGEST,
)

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/azure/check-staged-rollout-plan.py"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
SENTINEL = "synthetic-credential-that-must-never-reach-stdout"
APP = "azurerm_container_app.main"

NON_APP_RESOURCES = [
    ("azurerm_key_vault_secret.postgres_connection", "azurerm_key_vault_secret"),
    ("azurerm_key_vault.main", "azurerm_key_vault"),
    ("azurerm_role_assignment.runtime", "azurerm_role_assignment"),
    ("azurerm_postgresql_flexible_server.main", "azurerm_postgresql_flexible_server"),
    ("azurerm_postgresql_flexible_server_configuration.extensions", "azurerm_postgresql_flexible_server_configuration"),
    ("azurerm_postgresql_flexible_server_database.main", "azurerm_postgresql_flexible_server_database"),
    ("azurerm_virtual_network.main", "azurerm_virtual_network"),
    ("azurerm_subnet.postgres", "azurerm_subnet"),
    ("azurerm_container_registry.main", "azurerm_container_registry"),
    ("azurerm_resource_group.main", "azurerm_resource_group"),
    ("azurerm_container_app.other", "azurerm_container_app"),
]


def check(plan, source_sha=SOURCE_COMMIT_SHA):
    return subprocess.run(
        [
            sys.executable, str(GATE),
            "--stable-revision", STABLE_REVISION,
            "--candidate-revision", CANDIDATE_REVISION,
            "--source-commit-sha", source_sha,
            "--candidate-image-digest", SOURCE_IMAGE_DIGEST,
            "--stable-secret-version", STABLE_VERSION,
            "--candidate-secret-version", CANDIDATE_VERSION,
            "--candidate-key-id", CANDIDATE_KEY_ID,
            "--runtime-secret-version", RUNTIME_POSTGRES_VERSION,
        ],
        input=json.dumps(plan),
        capture_output=True, text=True, check=False,
    )


def resource(address, type_name, actions):
    return {
        "address": address, "type": type_name,
        "change": {
            "actions": actions,
            "before": {"id": "synthetic-existing", "value": SENTINEL},
            "after": {"id": "synthetic-updated", "value": SENTINEL},
        },
    }


class OnlyContainerAppStageTests(unittest.TestCase):
    def test_valid_candidate_with_unrelated_no_ops_remains_allowed(self):
        plan = fixture_plan()
        for address, type_name in NON_APP_RESOURCES:
            plan["resource_changes"].append(resource(address, type_name, ["no-op"]))
        result = check(plan)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_cannot_mutate_other_infrastructure_during_aca_stage(self):
        for address, type_name in NON_APP_RESOURCES:
            for actions in (["create"], ["update"], ["delete"], ["delete", "create"],
                            ["create", "delete"], ["read"]):
                with self.subTest(address=address, actions=actions):
                    plan = fixture_plan()
                    plan["resource_changes"].append(resource(address, type_name, actions))
                    result = check(plan)
                    self.assertNotEqual(0, result.returncode)
                    self.assertNotIn(SENTINEL, result.stdout + result.stderr)
                    self.assertNotIn(address, result.stdout + result.stderr)

    def test_duplicate_non_app_address_rejected_even_if_no_op(self):
        plan = fixture_plan()
        resource_def = resource("azurerm_key_vault.main", "azurerm_key_vault", ["no-op"])
        plan["resource_changes"].extend((resource_def, copy.deepcopy(resource_def)))
        self.assertNotEqual(0, check(plan).returncode)

    def test_rejects_unexpected_action_schemas_and_missing_address(self):
        for actions in ([], ["no-op", "update"], ["no-op", "no-op"], ["unknown"], "no-op"):
            with self.subTest(actions=actions):
                plan = fixture_plan()
                plan["resource_changes"].append(resource(
                    "azurerm_key_vault.main", "azurerm_key_vault", actions))
                self.assertNotEqual(0, check(plan).returncode)
        plan = fixture_plan()
        plan["resource_changes"].append(resource(
            "", "azurerm_key_vault", ["no-op"]))
        self.assertNotEqual(0, check(plan).returncode)

    def test_rejects_state_drift_even_if_stage_app_plan_is_clean(self):
        for drift in (
            [resource("azurerm_key_vault.main", "azurerm_key_vault", ["update"])],
            [resource("azurerm_key_vault_secret.postgres_connection",
                      "azurerm_key_vault_secret", ["update"])],
            [{"address": "azurerm_postgresql_flexible_server.main",
              "change": {"actions": ["delete", "create"]}}],
        ):
            with self.subTest(drift=drift[0]["address"]):
                plan = fixture_plan()
                plan["resource_drift"] = drift
                result = check(plan)
                self.assertNotEqual(0, result.returncode)
                self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_rejects_output_changes_in_same_app_stage(self):
        for change in (["create"], ["update"], ["delete"]):
            plan = fixture_plan()
            plan["output_changes"] = {"runtime_password": {
                "actions": change, "before": SENTINEL,
                "after": SENTINEL, "after_sensitive": True}}
            result = check(plan)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_workflow_applies_only_the_plan_binary_reviewed_by_gate(self):
        self.assertIn("terraform -chdir=infra plan -input=false -out=deploy.tfplan", DEPLOY)
        self.assertIn("terraform -chdir=infra show -json deploy.tfplan | python3 scripts/azure/check-staged-rollout-plan.py", DEPLOY)
        self.assertIn("terraform -chdir=infra apply -input=false -auto-approve deploy.tfplan", DEPLOY)
        self.assertEqual(1, DEPLOY.count("terraform -chdir=infra apply"))
        self.assertLess(DEPLOY.index("check-staged-rollout-plan.py"), DEPLOY.index("terraform -chdir=infra apply"))
        self.assertNotIn("az containerapp ingress traffic set", DEPLOY)


if __name__ == "__main__":
    unittest.main()
