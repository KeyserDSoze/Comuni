"""TDD contracts for opt-in Key Vault backed platform inventory staging.

The tests never contact Azure, access Key Vault values or read Terraform state.
They exercise the same staged-release gate with hostile synthetic plan JSON.
"""
import copy
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

from test_staged_rollout import fixture_plan, STABLE_REVISION, CANDIDATE_REVISION, STABLE_VERSION, CANDIDATE_VERSION, CANDIDATE_KEY_ID, VAULT_URI, RUNTIME_POSTGRES_VERSION, SOURCE_COMMIT_SHA

ROOT = Path(__file__).resolve().parents[2]
TF = (ROOT / "infra/main.tf").read_text()
VARS = (ROOT / "infra/variables.tf").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
GATE = ROOT / "scripts/azure/check-staged-rollout-plan.py"
PREFLIGHT = ROOT / "scripts/azure/check-platform-inventory-secret.sh"
VERSION = "c" * 32
SECRET = "pi-" + VERSION[:16]
URI = VAULT_URI + "secrets/platform-inventory-connection/" + VERSION


def valid_plan(enabled=True):
    plan = fixture_plan()
    app = plan["resource_changes"][0]["change"]["after"]
    env = app["template"][0]["container"][0]["env"]
    env.append({"name": "PlatformInventory__Enabled", "value": str(enabled).lower()})
    if enabled:
        app["secret"].append({"name": SECRET, "key_vault_secret_id": URI,
                              "identity": app["identity"][0]["identity_ids"][0]})
        env.append({"name": "ConnectionStrings__PlatformRead", "secret_name": SECRET})
    return plan


def check(plan, enabled=False, version=""):
    args = [
        sys.executable, str(GATE),
        "--stable-revision", STABLE_REVISION,
        "--candidate-revision", CANDIDATE_REVISION,
        "--source-commit-sha", SOURCE_COMMIT_SHA,
        "--stable-secret-version", STABLE_VERSION,
        "--candidate-secret-version", CANDIDATE_VERSION,
        "--candidate-key-id", CANDIDATE_KEY_ID,
        "--runtime-secret-version", RUNTIME_POSTGRES_VERSION,
        "--inventory-enabled", str(enabled).lower(),
        "--inventory-secret-version", version,
    ]
    return subprocess.run(args, input=json.dumps(plan), text=True, capture_output=True, check=False)


class PlatformInventoryReleaseTests(unittest.TestCase):
    def test_terraform_wires_opt_in_only_from_external_pinned_kv_uri(self):
        # ACA secret keys are limited to 20 characters; keep the *full*
        # immutable version only in the Key Vault URI.
        self.assertLessEqual(len(SECRET), 20)
        self.assertIn('substr(secret.value, 0, 16)', TF)
        self.assertIn('substr(env.value, 0, 16)', TF)
        self.assertIn('variable "platform_inventory_enabled"', VARS)
        self.assertRegex(VARS, r'variable "platform_inventory_enabled"\s*\{[^}]*default\s*=\s*false')
        self.assertIn('variable "platform_inventory_secret_version"', VARS)
        self.assertIn('var.platform_inventory_enabled', TF)
        self.assertIn('secrets/platform-inventory-connection/', TF)
        self.assertIn('name  = "PlatformInventory__Enabled"', TF)
        self.assertIn('name        = "ConnectionStrings__PlatformRead"', TF)
        self.assertNotIn('azurerm_key_vault_secret" "platform_inventory', TF)
        self.assertNotIn('var.platform_inventory_connection', TF)
        self.assertNotIn('var.platform_inventory_password', TF)
        self.assertNotIn("data \"azurerm_key_vault_secret\"", TF)
        self.assertIn("TF_VAR_platform_inventory_enabled:", DEPLOY)
        self.assertIn("TF_VAR_platform_inventory_secret_version:", DEPLOY)
        self.assertIn("check-platform-inventory-secret.sh", DEPLOY)
        self.assertLess(DEPLOY.index("check-platform-inventory-secret.sh"),
                        DEPLOY.index("terraform -chdir=infra plan"))
        self.assertIn("--inventory-enabled", DEPLOY)
        self.assertIn("--inventory-secret-version", DEPLOY)
        self.assertNotIn("PLATFORM_READ_DB_PASSWORD:", DEPLOY)
        self.assertNotIn("ConnectionStrings__PlatformRead:", DEPLOY)

    def test_disabled_inventory_requires_no_platform_secret_or_connection(self):
        self.assertEqual(0, check(valid_plan(False)).returncode,
                         check(valid_plan(False)).stderr)
        p = valid_plan(True)
        self.assertNotEqual(0, check(p, enabled=False, version=VERSION).returncode)

    def test_approved_pinned_inventory_secret_and_candidate_only_are_accepted(self):
        p = valid_plan(True)
        result = check(p, enabled=True, version=VERSION)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(URI, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_plan_deny_wrong_version_versionless_disabled_missing_duplicate_and_injected_values(self):
        cases = []
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["secret"][-1]["key_vault_secret_id"] = (
            VAULT_URI + "secrets/platform-inventory-connection")
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["secret"][-1]["key_vault_secret_id"] = (
            VAULT_URI + "secrets/platform-inventory-connection/" + "d" * 32)
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["secret"][-1]["key_vault_secret_id"] = (
            "https://evil.example.test/secrets/platform-inventory-connection/" + VERSION)
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["secret"].pop()
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1]["secret_name"] = (
            "postgres-connection")
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1] = (
            {"name": "ConnectionStrings__PlatformRead", "value": "password=inline-secret"})
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-2]["value"] = "false"
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["secret"].append(
            {"name": SECRET, "key_vault_secret_id": URI})
        cases.append(p)
        p = valid_plan(True)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"].append(
            {"name": "ConnectionStrings__PlatformRead", "secret_name": SECRET})
        cases.append(p)
        for p in cases:
            with self.subTest(p=p):
                self.assertNotEqual(0, check(p, enabled=True, version=VERSION).returncode)
        self.assertNotEqual(0, check(valid_plan(True), enabled=True, version="bad").returncode)
        self.assertNotEqual(0, check(valid_plan(True), enabled=False, version=VERSION).returncode)

    def test_existing_stable_inventory_secret_must_remain_unchanged(self):
        before_uri = VAULT_URI + "secrets/platform-inventory-connection/" + "a" * 32
        p = valid_plan(True)
        change = p["resource_changes"][0]["change"]
        change["before"]["secret"].append({
            "name": "pi-" + "a" * 16,
            "key_vault_secret_id": before_uri,
            "identity": change["before"]["identity"][0]["identity_ids"][0],
        })
        change["after"]["secret"].append(copy.deepcopy(change["before"]["secret"][-1]))
        self.assertEqual(0, check(p, enabled=True, version=VERSION).returncode)
        change["after"]["secret"][-1]["key_vault_secret_id"] = URI
        self.assertNotEqual(0, check(p, enabled=True, version=VERSION).returncode)

    def test_compact_key_prefix_collision_fails_closed_without_overwriting_old_version(self):
        # Different approved 32-hex versions can share the first 16 chars.
        # A pre-existing ACA key with a different full URI must remain pinned;
        # neither the old secret nor the current revision can be overwritten.
        p = valid_plan(True)
        different_full_version = VERSION[:16] + "d" * 16
        before = p["resource_changes"][0]["change"]["before"]
        before["secret"].append({
            "name": SECRET, "key_vault_secret_id":
                VAULT_URI + "secrets/platform-inventory-connection/" + different_full_version,
        })
        result = check(p, enabled=True, version=VERSION)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(URI, result.stdout + result.stderr)

    def test_preflight_requires_exact_enabled_version_without_reading_secret_value(self):
        self.assertTrue(PREFLIGHT.is_file(), "platform inventory metadata preflight missing")
        text = PREFLIGHT.read_text()
        self.assertIn("az keyvault secret list-versions", text)
        self.assertNotIn("az keyvault secret show", text)
        self.assertNotIn("set -x", text)
        with tempfile.TemporaryDirectory() as tmp:
            az = Path(tmp) / "az"
            az.write_text(textwrap.dedent("""\
                #!/usr/bin/env python3
                import os, sys
                with open(os.environ["FAKE_AZ_LOG"], "a") as f:
                    f.write(" ".join(sys.argv[1:]) + "\\n")
                if sys.argv[1:4] != ["keyvault", "secret", "list-versions"]:
                    sys.exit(3)
                if "--name" not in sys.argv or sys.argv[sys.argv.index("--name") + 1] != "platform-inventory-connection":
                    sys.exit(4)
                print(os.environ.get("FAKE_AZ_ENABLED", "true"))
            """))
            az.chmod(0o700)
            env = os.environ.copy()
            env.update(PATH=tmp + os.pathsep + env.get("PATH", ""),
                       FAKE_AZ_LOG=str(Path(tmp) / "calls"),
                       FAKE_AZ_ENABLED="true")
            for version, enabled, expect_ok in [
                (VERSION, "true", True),
                (VERSION, "false", False),
                (VERSION, "", False),
                ("wrong", "true", False),
            ]:
                env["FAKE_AZ_ENABLED"] = enabled
                result = subprocess.run(
                    ["bash", str(PREFLIGHT), "comuni-itn-001-kv", version],
                    env=env, capture_output=True, text=True)
                self.assertEqual(expect_ok, result.returncode == 0)
                self.assertNotIn(URI, result.stdout + result.stderr)
                self.assertNotIn("password", (result.stdout + result.stderr).lower())
            calls = (Path(tmp) / "calls").read_text()
            self.assertIn("list-versions", calls)
            self.assertNotIn("secret show", calls)

if __name__ == "__main__":
    unittest.main()
