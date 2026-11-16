"""RED-first exact PostgreSQL FQDN trust source contracts, no live Azure."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_staged_rollout import fixture_plan, STABLE_REVISION, CANDIDATE_REVISION
from test_staged_rollout import STABLE_VERSION, CANDIDATE_VERSION, CANDIDATE_KEY_ID, RUNTIME_POSTGRES_VERSION, SOURCE_COMMIT_SHA
from test_live_revision_verification import (
    APP, RG, STABLE, CANDIDATE, IMAGE, KEY_ID, VERSION,
    valid_revisions, valid_traffic, MOCK_AZ
)

ROOT = Path(__file__).resolve().parents[2]
TF = (ROOT / "infra/main.tf").read_text()
GATE = ROOT / "scripts/azure/check-staged-rollout-plan.py"
VERIFY = ROOT / "scripts/azure/verify-staged-revisions.py"
PROGRAM = (ROOT / "src/backend/Applications/Api/Program.cs").read_text()
SETTINGS = (ROOT / "src/backend/Applications/Api/Security/RuntimePostgresConnectionSettings.cs").read_text()
HOST = "comuni-itn-001-pg.postgres.database.azure.com"
OTHER = "other-pg.postgres.database.azure.com"


def plan_with_approved_db_host():
    p = fixture_plan()
    return p


def plan_gate(plan):
    return subprocess.run([
        sys.executable, str(GATE),
        "--stable-revision", STABLE_REVISION,
        "--candidate-revision", CANDIDATE_REVISION,
        "--source-commit-sha", SOURCE_COMMIT_SHA,
        "--stable-secret-version", STABLE_VERSION,
        "--candidate-secret-version", CANDIDATE_VERSION,
        "--candidate-key-id", CANDIDATE_KEY_ID,
        "--runtime-secret-version", RUNTIME_POSTGRES_VERSION,
    ], input=json.dumps(plan), text=True, capture_output=True)


class ExpectedHostPlanTests(unittest.TestCase):
    def test_terraform_uses_managed_db_fqdn_not_secret_or_workflow_variable(self):
        self.assertIn('name  = "RuntimePostgres__ExpectedHost"', TF)
        self.assertIn("value = azurerm_postgresql_flexible_server.main.fqdn", TF)
        self.assertNotIn("var.runtime_postgres_expected_host", TF)
        self.assertIn('configuration["RuntimePostgres:ExpectedHost"]', SETTINGS)
        self.assertIn("RuntimePostgresConnectionSettings.Read(", PROGRAM)

    def test_plan_rejects_missing_spoofed_or_inline_secret_host_metadata(self):
        good = plan_with_approved_db_host()
        self.assertEqual(0, plan_gate(good).returncode, plan_gate(good).stderr)
        wrong = []
        p = copy.deepcopy(good)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1]["value"] = OTHER
        wrong.append(p)
        p = copy.deepcopy(good)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1]["value"] = ""
        wrong.append(p)
        p = copy.deepcopy(good)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"].pop()
        wrong.append(p)
        p = copy.deepcopy(good)
        p["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"][-1] = {
            "name": "RuntimePostgres__ExpectedHost", "secret_name": "postgres-connection"}
        wrong.append(p)
        p = copy.deepcopy(good)
        p["planned_values"]["root_module"]["resources"][0]["values"]["fqdn"] = OTHER
        wrong.append(p)
        p = copy.deepcopy(good)
        p["resource_changes"].append({
            "address": "azurerm_postgresql_flexible_server.main",
            "type": "azurerm_postgresql_flexible_server",
            "change": {"actions": ["update"], "before": {"fqdn": HOST},
                       "after": {"fqdn": OTHER}}
        })
        wrong.append(p)
        p = copy.deepcopy(good)
        del p["planned_values"]
        wrong.append(p)
        p = copy.deepcopy(good)
        p["planned_values"]["root_module"]["resources"].append(
            copy.deepcopy(p["planned_values"]["root_module"]["resources"][0]))
        wrong.append(p)
        for plan in wrong:
            result = plan_gate(plan)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn(HOST, result.stdout + result.stderr)
            self.assertNotIn(OTHER, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
