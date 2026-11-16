"""TDD RED: read-only ACR RBAC boundary before Docker push (#69).

Tests replace Azure CLI with a strict fake, never contact an Azure tenant.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/azure/check-acr-role-boundary.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
TERRAFORM = (ROOT / "infra/main.tf").read_text()
PREFIX, ACR = "comuni-itn-001", "comuniitn001acr"
HOST = ACR + ".azurecr.io"
SUB = "11111111-2222-3333-4444-555555555555"
ACR_ID = f"/subscriptions/{SUB}/resourceGroups/{PREFIX}-rg/providers/Microsoft.ContainerRegistry/registries/{ACR}"
APP_ID = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
APP_CLIENT = "bbbbbbbb-1111-2222-3333-cccccccccccc"
DEPLOY_CLIENT = "cccccccc-1111-2222-3333-dddddddddddd"
INFRA_CLIENT = "eeeeeeee-1111-2222-3333-ffffffffffff"
DEPLOY_ID = "dddddddd-1111-2222-3333-eeeeeeeeeeee"
SENTINEL = "azure-private-token-never-print"


def role(name, principal, scope=ACR_ID, condition=None):
    return {"principalId": principal, "roleDefinitionName": name,
            "scope": scope, "condition": condition}


def registry():
    return {"id": ACR_ID, "name": ACR, "loginServer": HOST,
            "roleAssignmentMode": "rbac", "adminUserEnabled": False}


FAKE_AZ = '''#!/usr/bin/env python3
import json
import os
import sys
r, rg = os.environ["ACR"], os.environ["RG"]
scope, app, deploy = os.environ["SCOPE"], os.environ["APP"], os.environ["DEPLOY"]
commands = [
    ["acr", "show", "--name", r, "--resource-group", rg,
     "--query", "{id:id,name:name,loginServer:loginServer,roleAssignmentMode:roleAssignmentMode,adminUserEnabled:adminUserEnabled}",
     "--output", "json", "--only-show-errors"],
    ["identity", "show", "--name", os.environ["PREFIX"] + "-app-identity",
     "--resource-group", rg, "--query", "{principalId:principalId,clientId:clientId}",
     "--output", "json", "--only-show-errors"],
    ["ad", "sp", "show", "--id", os.environ["CLIENT"],
     "--query", "id", "--output", "tsv", "--only-show-errors"],
    ["role", "assignment", "list", "--assignee-object-id", app,
     "--scope", scope, "--all", "--include-inherited",
     "--fill-principal-name", "false", "--output", "json", "--only-show-errors"],
    ["role", "assignment", "list", "--assignee-object-id", deploy,
     "--scope", scope, "--all", "--include-inherited",
     "--fill-principal-name", "false", "--output", "json", "--only-show-errors"],
]
with open(os.environ["CALL_LOG"], "a", encoding="utf8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
index = sum(1 for _ in open(os.environ["CALL_LOG"], encoding="utf8")) - 1
if index >= len(commands) or sys.argv[1:] != commands[index]:
    sys.stderr.write(os.environ["SECRET"])
    sys.exit(83)
if os.environ["FAIL_AT"] == str(index):
    sys.stderr.write(os.environ["SECRET"])
    sys.exit(84)
print(os.environ["RESPONSE_" + str(index)])
'''


def check(*, acr=None, app=None, deploy=DEPLOY_ID, pull=None, push=None,
          prefix=PREFIX, registry_name=ACR, host=HOST,
          client=DEPLOY_CLIENT, infra_client=INFRA_CLIENT, fail_at=-1):
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        fake = directory / "az"
        fake.write_text(FAKE_AZ, encoding="utf8")
        fake.chmod(0o700)
        log = directory / "calls.jsonl"
        def encoded(value):
            return value if isinstance(value, str) else json.dumps(value)
        env = {**os.environ, "PATH": str(directory) + os.pathsep + os.environ.get("PATH", ""),
               "ACR": ACR, "RG": PREFIX + "-rg", "SCOPE": ACR_ID,
               "APP": APP_ID, "DEPLOY": DEPLOY_ID, "PREFIX": PREFIX,
               "CLIENT": DEPLOY_CLIENT, "CALL_LOG": str(log),
               "SECRET": SENTINEL, "FAIL_AT": str(fail_at),
               "RESPONSE_0": encoded(registry() if acr is None else acr),
               "RESPONSE_1": encoded({"principalId": APP_ID, "clientId": APP_CLIENT}
                                     if app is None else app),
               "RESPONSE_2": deploy,
               "RESPONSE_3": encoded([role("AcrPull", APP_ID)] if pull is None else pull),
               "RESPONSE_4": encoded([role("AcrPush", DEPLOY_ID)] if push is None else push)}
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--prefix", prefix,
             "--registry-name", registry_name, "--registry-host", host,
             "--deployer-client-id", client, "--infra-client-id", infra_client],
            env=env, capture_output=True, text=True, check=False, timeout=12)
        calls = ([json.loads(line) for line in log.read_text().splitlines()]
                 if log.exists() else [])
        return result, calls


class ACRRbacPreflightTests(unittest.TestCase):
    def rejected(self, **kwargs):
        result, calls = check(**kwargs)
        self.assertNotEqual(result.returncode, 0, "unsafe ACR roles allowed")
        for secret in (SENTINEL, APP_ID, DEPLOY_ID, DEPLOY_CLIENT):
            self.assertNotIn(secret, result.stdout + result.stderr)
        for command in calls:
            for verb in ("create", "delete", "update", "assign"):
                self.assertNotIn(verb, command, "preflight must be read-only")
        return calls

    def test_managed_identity_acrpull_and_distinct_deployer_acrpush(self):
        result, calls = check()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(5, len(calls))
        self.assertEqual(APP_ID, calls[3][calls[3].index("--assignee-object-id") + 1])
        self.assertEqual(DEPLOY_ID, calls[4][calls[4].index("--assignee-object-id") + 1])

    def test_abac_admin_user_drift_unknown_registry_fail_closed(self):
        for delta in (
            {"roleAssignmentMode": "rbac-abac"}, {"roleAssignmentMode": None},
            {"roleAssignmentMode": "unknown"}, {"adminUserEnabled": True},
            {"adminUserEnabled": "false"}, {"adminUserEnabled": None},
            {"loginServer": "evil.azurecr.io"},
            {"id": ACR_ID.replace(ACR, "attackeracr")},
            {"name": "attackeracr"},
        ):
            with self.subTest(delta=delta):
                self.rejected(acr={**registry(), **delta})

    def test_rejects_untrusted_principals_or_inputs(self):
        for mutation in (
            {"prefix": "BAD-prefix"}, {"prefix": "evilprefix"},
            {"registry_name": "evilacr"}, {"host": "evil.azurecr.io"},
            {"client": SENTINEL}, {"client": APP_CLIENT},
            {"infra_client": SENTINEL}, {"infra_client": DEPLOY_CLIENT},
            {"deploy": APP_ID}, {"deploy": ""}, {"deploy": SENTINEL},
            {"app": {"principalId": DEPLOY_ID, "clientId": APP_CLIENT}},
            {"app": {"principalId": APP_ID, "clientId": "invalid"}},
            {"app": {}}, {"app": []}, {"app": "invalid-json"},
        ):
            with self.subTest(mutation=list(mutation.keys())):
                self.rejected(**mutation)

    def test_build_and_infra_client_ids_must_be_distinct_before_any_azure_query(self):
        for bad in (DEPLOY_CLIENT, "", "not-a-guid", SENTINEL):
            with self.subTest(input_kind=bad[:4]):
                calls = self.rejected(infra_client=bad)
                self.assertEqual(0, len(calls))

    def test_app_pull_identity_must_have_no_registry_write_or_inherited_privilege(self):
        for roles in (
            [], [role("AcrPush", APP_ID)], [role("Owner", APP_ID)],
            [role("Contributor", APP_ID)], [role("AcrDelete", APP_ID)],
            [role("Container Registry Repository Writer", APP_ID)],
            [role("AcrPull", APP_ID, scope="/subscriptions/" + SUB)],
            [role("AcrPull", APP_ID, condition="condition")],
            [role("AcrPull", DEPLOY_ID)],
            [role("AcrPull", APP_ID), role("AcrPush", APP_ID)],
            [role("AcrPull", APP_ID),
             role("Contributor", APP_ID, scope="/subscriptions/" + SUB)],
            [{"roleDefinitionName": "AcrPull", "scope": ACR_ID}],
            "broken-json", {},
        ):
            with self.subTest(roles=str(roles)[:60]):
                self.rejected(pull=roles)

    def test_deployment_principal_needs_explicit_acrpush_and_no_acr_owner(self):
        for roles in (
            [], [role("AcrPull", DEPLOY_ID)], [role("Owner", DEPLOY_ID)],
            [role("Contributor", DEPLOY_ID)],
            [role("AcrPush", DEPLOY_ID, scope="/subscriptions/" + SUB)],
            [role("AcrPush", DEPLOY_ID, condition="condition")],
            [role("AcrPush", APP_ID)],
            [role("AcrPush", DEPLOY_ID), role("Owner", DEPLOY_ID)],
            [role("AcrPush", DEPLOY_ID), role("AcrDelete", DEPLOY_ID)],
            "broken-json", {},
        ):
            with self.subTest(roles=str(roles)[:60]):
                self.rejected(push=roles)

    def test_azure_cli_error_at_every_step_stops_without_leak(self):
        for step in range(5):
            with self.subTest(step=step):
                calls = self.rejected(fail_at=step)
                self.assertEqual(step + 1, len(calls))
        self.rejected(acr="invalid-json")
        self.rejected(pull=SENTINEL)
        self.rejected(push=SENTINEL)

    def test_workflow_preflight_before_acr_login_build_and_push(self):
        self.assertIn("scripts/azure/check-acr-role-boundary.py", WORKFLOW)
        self.assertLess(WORKFLOW.index("check-acr-role-boundary.py"),
                        WORKFLOW.index("login-acr-oauth.py"))
        self.assertLess(WORKFLOW.index("check-acr-role-boundary.py"),
                        WORKFLOW.index("docker push"))
        self.assertIn('--deployer-client-id "$ACR_PUSH_CLIENT_ID"', WORKFLOW)
        self.assertIn('--infra-client-id "$ARM_CLIENT_ID"', WORKFLOW)
        self.assertIn('--prefix "$AZURE_PREFIX"', WORKFLOW)
        self.assertIn('--registry-host "$REGISTRY_HOST"', WORKFLOW)
        self.assertIn('role_definition_name = "AcrPull"', TERRAFORM)
        self.assertNotIn('role_definition_name = "AcrPush"', TERRAFORM)
        self.assertNotIn("az acr update --role-assignment-mode", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
