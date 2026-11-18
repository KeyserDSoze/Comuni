"""TDD RED: separated, read-only Terraform plan gate for state-only legacy handoff.

All fixtures and passwords are synthetic. No Azure, Terraform backend, or secret
value is accessed. The actual state handoff requires a future owner-approved change.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/azure/check-legacy-postgres-handoff-plan.py"
TF = (ROOT / "infra/main.tf").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()

SECRET_ADDRESS = "azurerm_key_vault_secret.postgres_connection"
APP_ADDRESS = "azurerm_container_app.main"
URI = "https://comuni-itn-001-kv.vault.azure.net/secrets/postgres-connection"
SENTINEL = "synthetic-postgres-password-private-not-for-logs"
SENTINEL_HOST = "synthetic-secret-host-private-not-for-logs"
POSTGRES_ADDRESS = "azurerm_postgresql_flexible_server.main"
EXPECTED_HOST = "comuni-itn-001-pg.postgres.database.azure.com"


def resource(address, type_name, actions, before=None, after=None):
    return {
        "address": address, "type": type_name,
        "change": {"actions": actions, "before": before, "after": after},
    }


def plan():
    legacy_before = {
        "name": "postgres-connection", "versionless_id": URI,
        "value": SENTINEL, "id": "synthetic-id-not-to-log",
    }
    app = {
        "revision_mode": "Multiple",
        "ingress": [{
            "external_enabled": True,
            "target_port": 8080,
            "traffic_weight": [
                {"latest_revision": False, "revision_suffix": "r111111111111",
                 "percentage": 100},
                {"latest_revision": True, "label": "r222222222222",
                 "percentage": 0},
            ],
        }],
        "secret": [
            {"name": "postgres-connection", "key_vault_secret_id": URI},
            {"name": "pg-dddddddddddddddd",
             "key_vault_secret_id": "https://comuni-itn-001-kv.vault.azure.net/secrets/postgres-runtime-connection/" + "d" * 32},
        ],
        "template": [{
            "revision_suffix": "r222222222222",
            "container": [{
                "env": [
                    {"name": "ConnectionStrings__Default",
                     "secret_name": "pg-dddddddddddddddd"},
                    {"name": "RuntimePostgres__ExpectedHost",
                     "value": EXPECTED_HOST}
                ]
            }]
        }],
    }
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": [{
            "address": POSTGRES_ADDRESS,
            "type": "azurerm_postgresql_flexible_server",
            "values": {
                "name": "comuni-itn-001-pg",
                "fqdn": EXPECTED_HOST,
            },
        }]}},
        "resource_changes": [
            resource(SECRET_ADDRESS, "azurerm_key_vault_secret",
                     ["forget"], legacy_before, None),
            resource(APP_ADDRESS, "azurerm_container_app", ["no-op"],
                     app, copy.deepcopy(app)),
            resource("azurerm_key_vault.main", "azurerm_key_vault", ["no-op"],
                     {"name": "comuni-itn-001-kv"}, {"name": "comuni-itn-001-kv"}),
        ],
        "resource_drift": [],
        "output_changes": {},
    }


def run_gate(data):
    if not GATE.is_file():
        return subprocess.CompletedProcess([], 127, "", "missing read-only state handoff gate")
    return subprocess.run(
        [sys.executable, str(GATE)],
        input=json.dumps(data) if not isinstance(data, str) else data,
        text=True, capture_output=True, check=False, timeout=10,
    )


class LegacyPostgresHandoffPlanTests(unittest.TestCase):
    def deny(self, data):
        result = run_gate(data)
        self.assertNotEqual(0, result.returncode, result.stdout)
        for value in (SENTINEL, SENTINEL_HOST, URI, SECRET_ADDRESS,
                      "synthetic-id-not-to-log"):
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_only_single_non_destructive_forget_with_unchanged_app_is_accepted(self):
        result = run_gate(plan())
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn(URI, result.stdout + result.stderr)

    def test_target_cannot_be_destroyed_recreated_or_updated(self):
        for actions in (["delete"], ["create"], ["update"], ["delete", "create"],
                        ["create", "forget"], ["no-op"], ["forget", "create"],
                        ["forget", "delete"], [], "forget"):
            with self.subTest(actions=actions):
                p = plan()
                p["resource_changes"][0]["change"]["actions"] = actions
                self.deny(p)

    def test_forget_requires_exact_target_before_and_null_after(self):
        for key, value in [
            ("before", None),
            ("before", {"name": "another-secret", "versionless_id": URI}),
            ("before", {"name": "postgres-connection", "versionless_id": URI}),
            ("after", {"value": SENTINEL}),
            ("after", {}),
        ]:
            with self.subTest(key=key, value=value):
                p = plan()
                p["resource_changes"][0]["change"][key] = value
                self.deny(p)

    def test_must_leave_stable_aca_app_secret_and_runtime_reference_unchanged(self):
        cases = []
        for change in ("update", "delete", "forget", "create"):
            p = plan()
            p["resource_changes"][1]["change"]["actions"] = [change]
            cases.append(p)
        p = plan()
        p["resource_changes"][1]["change"]["after"]["secret"][0]["key_vault_secret_id"] += "/" + "e" * 32
        cases.append(p)
        p = plan()
        p["resource_changes"][1]["change"]["after"]["secret"].pop(0)
        cases.append(p)
        p = plan()
        p["resource_changes"][1]["change"]["before"]["secret"].pop(0)
        p["resource_changes"][1]["change"]["after"]["secret"].pop(0)
        cases.append(p)
        p = plan()
        p["resource_changes"][1]["change"]["before"]["secret"].append(
            {"name": "postgres-connection", "key_vault_secret_id": URI})
        cases.append(p)
        p = plan()
        p["resource_changes"][1]["change"]["before"]["template"][0]["container"][0]["env"][0] = {
            "name": "ConnectionStrings__Default", "value": SENTINEL_HOST}
        cases.append(p)
        p = plan()
        p["resource_changes"].pop(1)
        cases.append(p)
        for case in cases:
            self.deny(case)

    def test_authorized_postgres_server_must_come_from_managed_planned_values(self):
        def resource_for(p):
            return p["planned_values"]["root_module"]["resources"][0]

        for change in (
            lambda p: p.pop("planned_values"),
            lambda p: p.update(planned_values={}),
            lambda p: p["planned_values"].pop("root_module"),
            lambda p: p["planned_values"]["root_module"].pop("resources"),
            lambda p: p["planned_values"]["root_module"].update(resources=[]),
            lambda p: p["planned_values"]["root_module"].update(resources="untrusted"),
            lambda p: p["planned_values"]["root_module"]["resources"].append(
                copy.deepcopy(resource_for(p))),
            lambda p: resource_for(p).update(address="azurerm_postgresql_flexible_server.other"),
            lambda p: resource_for(p).update(type="azurerm_key_vault_secret"),
            lambda p: resource_for(p).pop("values"),
            lambda p: resource_for(p)["values"].update(name="other-pg"),
            lambda p: resource_for(p)["values"].update(fqdn="other-pg.postgres.database.azure.com"),
            lambda p: resource_for(p)["values"].update(fqdn="10.90.2.8"),
            lambda p: resource_for(p)["values"].update(fqdn="other-pg.postgres.database.azure.com.evil.test"),
            lambda p: resource_for(p)["values"].update(fqdn="other-pg.private.postgres.database.azure.com"),
            lambda p: resource_for(p)["values"].update(fqdn=SENTINEL_HOST),
            lambda p: resource_for(p)["values"].update(fqdn=EXPECTED_HOST + "."),
            lambda p: resource_for(p)["values"].update(fqdn=""),
        ):
            with self.subTest(change=change):
                p = plan()
                change(p)
                self.deny(p)

    def test_candidate_expected_host_is_exact_authorized_managed_server_metadata(self):
        def environment(app):
            return app["template"][0]["container"][0]["env"]

        for change in (
            lambda app: environment(app).pop(1),
            lambda app: environment(app).append(
                {"name": "RuntimePostgres__ExpectedHost", "value": EXPECTED_HOST}),
            lambda app: environment(app)[1].update(value="other-pg.postgres.database.azure.com"),
            lambda app: environment(app)[1].update(value="10.90.2.8"),
            lambda app: environment(app)[1].update(value=SENTINEL_HOST),
            lambda app: environment(app)[1].update(value=""),
            lambda app: environment(app)[1].update(value=None),
            lambda app: environment(app)[1].update(secret_name="pg-dddddddddddddddd"),
            lambda app: environment(app)[1].pop("value"),
            lambda app: environment(app)[1].update(name="RuntimePostgres__OtherHost"),
        ):
            with self.subTest(change=change):
                self.deny(self.risky_aca(change))

    def test_host_identity_check_is_not_trusted_from_cli_or_candidate_secret(self):
        case = plan()
        # A signed-looking value in ACA cannot override the managed FQDN.
        case["resource_changes"][1]["change"]["before"]["template"][0][
            "container"][0]["env"][1]["value"] = SENTINEL_HOST
        case["resource_changes"][1]["change"]["after"]["template"][0][
            "container"][0]["env"][1]["value"] = SENTINEL_HOST
        self.deny(case)

    @staticmethod
    def risky_aca(mutate):
        case = plan()
        app_change = case["resource_changes"][1]["change"]
        # Both snapshots mutate identically. A plain no-op comparison MUST
        # NOT turn a dangerous pre-existing routing state into an approval.
        mutate(app_change["before"])
        mutate(app_change["after"])
        return case

    def test_legacy_handoff_requires_multiple_revision_mode_and_staged_traffic(self):
        for mutate in (
            lambda app: app.update(revision_mode="Single"),
            lambda app: app.pop("revision_mode"),
            lambda app: app.update(revision_mode="multiple"),
            lambda app: app.pop("ingress"),
            lambda app: app.update(ingress=[]),
            lambda app: app.update(ingress={}),
            lambda app: app["ingress"][0].pop("traffic_weight"),
            lambda app: app["ingress"][0].update(traffic_weight=[]),
            lambda app: app["ingress"][0]["traffic_weight"].pop(),
            lambda app: app["ingress"][0]["traffic_weight"].append({
                "latest_revision": False, "revision_suffix": "other", "percentage": 0,
            }),
            lambda app: app["ingress"][0]["traffic_weight"][0].update(percentage=90),
            lambda app: app["ingress"][0]["traffic_weight"][1].update(percentage=10),
            lambda app: app["ingress"][0]["traffic_weight"][0].update(percentage=True),
            lambda app: app["ingress"][0]["traffic_weight"][1].update(percentage=False),
            lambda app: app["ingress"][0]["traffic_weight"][0].update(latest_revision=True),
            lambda app: app["ingress"][0]["traffic_weight"][1].update(latest_revision=False),
            lambda app: app["ingress"][0]["traffic_weight"][0].update(revision_suffix=""),
            lambda app: app["ingress"][0]["traffic_weight"][0].pop("revision_suffix"),
            lambda app: app["ingress"][0]["traffic_weight"][1].update(revision_suffix="r222222222222"),
            lambda app: app["ingress"][0]["traffic_weight"][1].update(label="other"),
            lambda app: app["ingress"][0]["traffic_weight"][1].pop("label"),
            lambda app: app["ingress"][0]["traffic_weight"][0].update(revision_suffix="r222222222222"),
            lambda app: app["template"][0].update(revision_suffix="other"),
            lambda app: app["template"][0].pop("revision_suffix"),
            lambda app: app["template"][0].update(revision_suffix=""),
            lambda app: app["ingress"][0]["traffic_weight"][1].update(label="r111111111111"),
        ):
            with self.subTest(mutate=mutate):
                self.deny(self.risky_aca(mutate))

    def test_legacy_handoff_rejects_state_or_ingress_changes_even_if_safe_after(self):
        case = plan()
        case["resource_changes"][1]["change"]["before"]["ingress"][0][
            "traffic_weight"][0]["percentage"] = 90
        self.deny(case)
        case = plan()
        case["resource_changes"][1]["change"]["after"]["ingress"][0][
            "traffic_weight"][1]["percentage"] = 1
        self.deny(case)

    def test_unrelated_terraform_mutations_and_duplicate_resources_are_denied(self):
        for addr, t in [
            ("azurerm_key_vault.main", "azurerm_key_vault"),
            ("azurerm_postgresql_flexible_server.main", "azurerm_postgresql_flexible_server"),
            ("azurerm_role_assignment.secrets", "azurerm_role_assignment"),
            ("azurerm_container_app.other", "azurerm_container_app"),
        ]:
            for action in (["forget"], ["update"], ["delete"], ["create"],
                           ["read"], ["delete", "create"]):
                p = plan()
                p["resource_changes"].append(resource(
                    addr, t, action, {"value": SENTINEL}, None))
                self.deny(p)
        p = plan()
        p["resource_changes"].append(copy.deepcopy(p["resource_changes"][0]))
        self.deny(p)
        p = plan()
        p["resource_changes"].append(copy.deepcopy(p["resource_changes"][1]))
        self.deny(p)

    def test_bad_secret_uri_and_inconsistent_legacy_id_are_denied(self):
        for uri in (
            "https://evil.example.test/secrets/postgres-connection",
            "http://comuni-itn-001-kv.vault.azure.net/secrets/postgres-connection",
            URI + "/" + "a" * 32,
            URI + "?alt=1",
            URI + ".evil.test",
        ):
            p = plan()
            p["resource_changes"][0]["change"]["before"]["versionless_id"] = uri
            self.deny(p)
        p = plan()
        p["resource_changes"][0]["change"]["before"]["versionless_id"] = URI + "/" + "b" * 32
        p["resource_changes"][1]["change"]["before"]["secret"][0]["key_vault_secret_id"] = URI + "/" + "b" * 32
        p["resource_changes"][1]["change"]["after"]["secret"][0]["key_vault_secret_id"] = URI + "/" + "b" * 32
        self.deny(p)

    def test_reject_drift_output_changes_empty_plan_and_untrusted_json(self):
        for mutation in (
            lambda p: p.update(resource_drift=[resource(SECRET_ADDRESS,
                "azurerm_key_vault_secret", ["update"], {"value": SENTINEL}, None)]),
            lambda p: p.update(output_changes={"secret": {
                "actions": ["update"], "before": SENTINEL, "after": SENTINEL}}),
            lambda p: p.update(resource_changes=[]),
            lambda p: p.update(resource_changes=[p["resource_changes"][0]]),
        ):
            p = plan()
            mutation(p)
            self.deny(p)
        self.deny("{ invalid json with " + SENTINEL)
        self.deny({"resource_changes": []})

    def test_gate_is_read_only_and_production_staging_remains_separate(self):
        self.assertTrue(GATE.is_file(), "RED: missing independent state-handoff plan gate")
        source = GATE.read_text()
        for prohibited in ("terraform apply", "terraform state rm", "az keyvault",
                           "az containerapp", "shell=True", "print(plan)", "print(json.dumps(plan"):
            self.assertNotIn(prohibited, source)
        self.assertIn("json.load(sys.stdin)", source)
        self.assertIn("['forget']", source.replace('"', "'"))
        self.assertIn('resource "azurerm_key_vault_secret" "postgres_connection"', TF)
        self.assertIn("azurerm_key_vault_secret.postgres_connection.versionless_id", TF)
        self.assertNotIn("from = azurerm_key_vault_secret.postgres_connection", TF)
        self.assertNotIn("check-legacy-postgres-handoff-plan.py", DEPLOY)
        self.assertIn("check-staged-rollout-plan.py", DEPLOY)


if __name__ == "__main__":
    unittest.main()
