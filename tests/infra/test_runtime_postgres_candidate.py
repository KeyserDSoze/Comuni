"""TDD: one pinned external Key Vault PostgreSQL connection per ACA candidate.

All runtime credentials and Azure metadata are synthetic. No live account.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_staged_rollout import (
    fixture_plan, STABLE_REVISION, CANDIDATE_REVISION,
    STABLE_VERSION, CANDIDATE_VERSION, CANDIDATE_KEY_ID, VAULT_URI
)

ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = (ROOT / "infra/main.tf").read_text()
VARS = (ROOT / "infra/variables.tf").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
PLAN_GATE = ROOT / "scripts/azure/check-staged-rollout-plan.py"
PREFLIGHT = ROOT / "scripts/azure/check-runtime-postgres-secret.sh"
VERSION = "d" * 32
SECRET_NAME = "pg-" + VERSION[:16]
SECRET_URI = VAULT_URI + "secrets/postgres-runtime-connection/" + VERSION


def runtime_plan():
    return fixture_plan()


def gate(plan, version=VERSION, *, include_version=True):
    command = [
        sys.executable, str(PLAN_GATE),
        "--stable-revision", STABLE_REVISION,
        "--candidate-revision", CANDIDATE_REVISION,
        "--stable-secret-version", STABLE_VERSION,
        "--candidate-secret-version", CANDIDATE_VERSION,
        "--candidate-key-id", CANDIDATE_KEY_ID,
    ]
    if include_version:
        command += ["--runtime-secret-version", version]
    return subprocess.run(command, input=json.dumps(plan), text=True,
                          capture_output=True, check=False)


class RuntimePostgresCandidateSecretTests(unittest.TestCase):
    def test_metadata_only_terraform_pins_new_candidate_secret_without_mutating_stable(self):
        self.assertLessEqual(len(SECRET_NAME), 20)
        self.assertIn('variable "runtime_postgres_connection_secret_version"', VARS)
        self.assertIn('secrets/postgres-runtime-connection/', TERRAFORM)
        self.assertIn('pg-${substr(var.runtime_postgres_connection_secret_version, 0, 16)}', TERRAFORM)
        self.assertIn('name        = "ConnectionStrings__Default"', TERRAFORM)
        self.assertIn('secret_name = "pg-${substr(var.runtime_postgres_connection_secret_version, 0, 16)}"', TERRAFORM)
        self.assertIn('name                = "postgres-connection"', TERRAFORM)
        self.assertNotIn('azurerm_key_vault_secret" "postgres_runtime_connection', TERRAFORM)
        self.assertNotIn("var.runtime_postgres_connection_password", TERRAFORM)
        self.assertIn("TF_VAR_runtime_postgres_connection_secret_version:", DEPLOY)
        self.assertIn("vars.RUNTIME_POSTGRES_CONNECTION_SECRET_VERSION", DEPLOY)
        self.assertNotIn("TF_VAR_runtime_postgres_connection:", DEPLOY)
        self.assertNotIn("TF_VAR_runtime_postgres_connection_password:", DEPLOY)
        self.assertIn("check-runtime-postgres-secret.sh", DEPLOY)
        self.assertLess(DEPLOY.index("check-runtime-postgres-secret.sh"),
                        DEPLOY.index("terraform -chdir=infra plan"))
        self.assertIn("--runtime-secret-version", DEPLOY)

    def test_pinned_secret_in_same_vault_is_accepted_without_values_in_output(self):
        result = gate(runtime_plan())
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(SECRET_URI, result.stdout + result.stderr)
        self.assertNotIn(SECRET_NAME, result.stdout + result.stderr)

    def test_missing_version_and_nonpinned_or_untrusted_credentials_fail_closed(self):
        self.assertNotEqual(0, gate(runtime_plan(), include_version=False).returncode)
        self.assertNotEqual(0, gate(runtime_plan(), version="").returncode)
        self.assertNotEqual(0, gate(runtime_plan(), version="wrong").returncode)
        cases = []
        plan = runtime_plan()
        plan["resource_changes"][0]["change"]["after"]["secret"].pop()
        cases.append(plan)
        for changed in [
            VAULT_URI + "secrets/postgres-runtime-connection",
            VAULT_URI + "secrets/postgres-runtime-connection/" + "e" * 32,
            "https://other-vault.vault.azure.net/secrets/postgres-runtime-connection/" + VERSION,
            "https://evil.example.test/secrets/postgres-runtime-connection/" + VERSION,
        ]:
            plan = runtime_plan()
            plan["resource_changes"][0]["change"]["after"]["secret"][-1]["key_vault_secret_id"] = changed
            cases.append(plan)
        plan = runtime_plan()
        plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1] = {
            "name": "ConnectionStrings__Default", "secret_name": "postgres-connection"}
        cases.append(plan)
        plan = runtime_plan()
        plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1] = {
            "name": "ConnectionStrings__Default", "value": "Password=example-dont-print"}
        cases.append(plan)
        plan = runtime_plan()
        plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"].pop()
        cases.append(plan)
        plan = runtime_plan()
        plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"].append(
            {"name": "ConnectionStrings__Default", "secret_name": SECRET_NAME})
        cases.append(plan)
        plan = runtime_plan()
        plan["resource_changes"][0]["change"]["after"]["secret"].append(
            {"name": SECRET_NAME, "key_vault_secret_id": SECRET_URI})
        cases.append(plan)
        for plan in cases:
            with self.subTest(index=len(cases)):
                result = gate(plan)
                self.assertNotEqual(0, result.returncode, result.stdout)
                self.assertNotIn("example-dont-print", result.stdout + result.stderr)
                self.assertNotIn(SECRET_URI, result.stdout + result.stderr)

    def test_existing_app_secrets_cannot_be_mutated_or_removed_by_candidate(self):
        plan = runtime_plan()
        before = plan["resource_changes"][0]["change"]["before"]
        after = plan["resource_changes"][0]["change"]["after"]
        before["secret"].append({"name": "postgres-connection",
                                 "key_vault_secret_id": VAULT_URI + "secrets/postgres-connection"})
        after["secret"].append(copy.deepcopy(before["secret"][-1]))
        self.assertEqual(0, gate(plan).returncode, gate(plan).stderr)
        after["secret"][-1]["key_vault_secret_id"] += "/" + VERSION
        self.assertNotEqual(0, gate(plan).returncode)
        after["secret"].pop()
        self.assertNotEqual(0, gate(plan).returncode)

    def test_collision_of_prefix_with_an_existing_version_is_not_rewritten(self):
        plan = runtime_plan()
        old = VERSION[:16] + "e" * 16
        plan["resource_changes"][0]["change"]["before"]["secret"].append({
            "name": SECRET_NAME,
            "key_vault_secret_id": VAULT_URI + "secrets/postgres-runtime-connection/" + old
        })
        result = gate(plan)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(SECRET_URI, result.stdout + result.stderr)

    def test_metadata_only_azure_preflight_has_no_value_read_or_leak(self):
        self.assertTrue(PREFLIGHT.is_file(), "RED: missing Key Vault runtime metadata preflight")
        body = PREFLIGHT.read_text()
        self.assertIn("az keyvault secret list-versions", body)
        self.assertNotIn("az keyvault secret show", body)
        self.assertNotIn("set -x", body)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "az"
            path.write_text(
                "#!/bin/sh\n"
                'case " $* " in *" list-versions "*) ;; *) exit 3;; esac\n'
                'case " $* " in *" --name postgres-runtime-connection "*) ;; *) exit 4;; esac\n'
                'case " $* " in *" --vault-name comuni-itn-001-kv "*) ;; *) exit 5;; esac\n'
                'case " $* " in *"attributes.enabled"*) ;; *) exit 6;; esac\n'
                'printf "%s\\n" "${TEST_ENABLED:-true}"\n'
            )
            path.chmod(0o700)
            env = {**os.environ, "PATH": folder + os.pathsep + os.environ.get("PATH", "")}
            for version, enabled, success in [
                (VERSION, "true", True), (VERSION, "false", False),
                (VERSION, "", False), ("bad", "true", False)
            ]:
                result = subprocess.run(
                    ["bash", str(PREFLIGHT), "comuni-itn-001-kv", version],
                    env={**env, "TEST_ENABLED": enabled},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(success, result.returncode == 0)
                self.assertNotIn(SECRET_URI, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
