"""RED-first contract for separate GitHub OIDC ACR build and Terraform apply identities.

Azure calls use a strict local fake; production validation is delegated to
Azure Login OIDC and an authenticated, read-only az account show.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/azure/check-azure-oidc-session.py"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
UUID_INFRA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
UUID_BUILD = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
UUID_SUB = "11111111-2222-3333-4444-555555555555"
UUID_TENANT = "22222222-3333-4444-5555-666666666666"
SENTINEL = "private-entra-authentication-token-never-expose"

FAKE_AZ = '''#!/usr/bin/env python3
import os
import sys
if sys.argv[1:] != ["account", "show",
                    "--query", "{id:id,tenantId:tenantId,user:user}",
                    "--output", "json", "--only-show-errors"]:
    sys.stderr.write(os.environ["SENTINEL"])
    sys.exit(61)
if os.environ.get("FAIL_AZ") == "1":
    sys.stderr.write(os.environ["SENTINEL"])
    sys.exit(62)
if os.environ["ACCOUNT_OUTPUT"] == "__OVERSIZED__":
    print(" " * 200000)
else:
    print(os.environ["ACCOUNT_OUTPUT"])
'''


def account(client=UUID_BUILD):
    return {"id": UUID_SUB, "tenantId": UUID_TENANT,
            "user": {"type": "servicePrincipal", "name": client}}


def verify(*, data=None, client=UUID_BUILD, other=UUID_INFRA,
           tenant=UUID_TENANT, subscription=UUID_SUB, fail_cli=False):
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        (folder / "az").write_text(FAKE_AZ, encoding="utf-8")
        (folder / "az").chmod(0o700)
        env = {**os.environ, "PATH": str(folder) + os.pathsep + os.environ.get("PATH", ""),
               "ACCOUNT_OUTPUT": json.dumps(account()) if data is None
               else (data if isinstance(data, str) else json.dumps(data)),
               "FAIL_AZ": "1" if fail_cli else "0", "SENTINEL": SENTINEL}
        run = subprocess.run(
            [sys.executable, str(GATE),
             "--expected-client-id", client, "--other-client-id", other,
             "--expected-tenant-id", tenant, "--expected-subscription-id", subscription],
            capture_output=True, text=True, env=env, check=False, timeout=12)
        return run


class OidcIdentityHandoffTests(unittest.TestCase):
    def deny(self, **kwargs):
        result = verify(**kwargs)
        self.assertNotEqual(0, result.returncode,
                            "wrong or ambiguous OIDC principal accepted")
        for sensitive in (SENTINEL, UUID_BUILD, UUID_INFRA,
                          UUID_SUB, UUID_TENANT):
            self.assertNotIn(sensitive, result.stdout + result.stderr)

    def test_active_azure_cli_service_principal_matches_expected_build_or_infra(self):
        build = verify()
        self.assertEqual(0, build.returncode, build.stderr)
        self.assertEqual("", build.stdout)
        infra = verify(client=UUID_INFRA, other=UUID_BUILD,
                       data=account(UUID_INFRA))
        self.assertEqual(0, infra.returncode, infra.stderr)

    def test_rejects_identity_overlap_and_mismatched_active_account(self):
        self.deny(client=UUID_INFRA, other=UUID_INFRA, data=account(UUID_INFRA))
        self.deny(other=UUID_BUILD)
        self.deny(client=UUID_INFRA, other=UUID_BUILD)
        self.deny(client="bad")
        self.deny(other="bad")
        self.deny(subscription="bad")
        self.deny(tenant="bad")
        self.deny(client=SENTINEL)

    def test_rejects_user_login_cross_tenant_wrong_subscription_and_no_auth(self):
        mismatches = (
            {"user": {"type": "user", "name": UUID_BUILD}},
            {"user": {"type": "servicePrincipal", "name": UUID_INFRA}},
            {"user": {"type": "servicePrincipal", "name": SENTINEL}},
            {"tenantId": UUID_SUB}, {"id": UUID_TENANT},
            {"user": None}, {"user": []}, {"user": {}},
            {"tenantId": ""}, {"id": ""}, {"tenantId": None},
            {"user": {"type": "managedIdentity", "name": UUID_BUILD}},
        )
        for delta in mismatches:
            with self.subTest(key=next(iter(delta))):
                self.deny(data={**account(), **delta})

    def test_rejects_cli_error_null_ambiguous_or_invalid_account_response(self):
        self.deny(fail_cli=True)
        for data in ("", "null", "[]", "{}", "{bad-json", SENTINEL,
                     "__OVERSIZED__", [{**account()}, {**account()}],
                     {**account(), "user": {"type": True, "name": UUID_BUILD}}):
            with self.subTest(kind=type(data).__name__, length=len(str(data))):
                self.deny(data=data)

    def test_only_main_workflow_dispatch_can_login_to_either_azure_principal(self):
        guard = "name: Reject unapproved GitHub release source before OIDC"
        login = "name: Login Azure infrastructure identity for RBAC preflight"
        self.assertIn(guard, DEPLOY)
        self.assertLess(DEPLOY.index(guard), DEPLOY.index(login))
        content = DEPLOY[DEPLOY.index(guard):DEPLOY.index(login)]
        self.assertIn('"$GITHUB_REPOSITORY" == "KeyserDSoze/Comuni"', content)
        self.assertIn('"$GITHUB_REF" == "refs/heads/main"', content)
        self.assertIn('"$GITHUB_EVENT_NAME" == "workflow_dispatch"', content)

    def test_postgres_passwords_exist_only_in_infra_terraform_stage_not_build_env(self):
        job_environment = DEPLOY[:DEPLOY.index("    steps:\n")]
        build_phase = DEPLOY[DEPLOY.index("name: Login Azure ACR build/push identity"):
                             DEPLOY.index("name: Login Azure infrastructure identity for Terraform stage")]
        plan_phase = DEPLOY[DEPLOY.index("name: Plan and stage candidate at zero traffic"):]
        for variable, secret in (
            ("TF_VAR_postgres_admin_password", "POSTGRES_ADMIN_PASSWORD"),
            ("TF_VAR_postgres_runtime_password", "POSTGRES_RUNTIME_PASSWORD"),
        ):
            self.assertNotIn(variable + ":", job_environment)
            self.assertNotIn(variable + ":", build_phase)
            self.assertIn(variable + ": ${{ secrets." + secret + " }}", plan_phase)
        self.assertIn('docker logout "$REGISTRY_HOST" >/dev/null 2>&1', build_phase)
        self.assertNotIn('docker logout "$REGISTRY_HOST" >/dev/null 2>&1 || true',
                         build_phase)

    def test_workflow_uses_three_separate_login_boundaries_and_no_secret_fallback(self):
        self.assertEqual(3, DEPLOY.count("uses: azure/login@a641126d1b8aa4d1fa005f4f92df94a3a4c4c906"))
        self.assertEqual(3, DEPLOY.count("scripts/azure/check-azure-oidc-session.py"))
        self.assertIn("ACR_PUSH_CLIENT_ID: ${{ secrets.AZURE_ACR_PUSH_CLIENT_ID }}", DEPLOY)
        self.assertIn("client-id: ${{ secrets.AZURE_ACR_PUSH_CLIENT_ID }}", DEPLOY)
        self.assertEqual(2, DEPLOY.count("client-id: ${{ secrets.AZURE_CLIENT_ID }}"))
        self.assertIn('--deployer-client-id "$ACR_PUSH_CLIENT_ID"', DEPLOY)
        self.assertIn('--infra-client-id "$ARM_CLIENT_ID"', DEPLOY)

        steps = [
            "name: Login Azure infrastructure identity for RBAC preflight",
            "name: Verify infra CLI OIDC before RBAC preflight",
            "scripts/azure/check-acr-role-boundary.py",
            "name: Clear infra Azure session before registry build",
            "name: Login Azure ACR build/push identity",
            "name: Verify ACR build CLI OIDC session",
            "docker push",
            "scripts/azure/lock-approved-image.py",
            "name: Clear build Azure session before Terraform",
            "name: Login Azure infrastructure identity for Terraform stage",
            "name: Verify infra CLI OIDC before Terraform",
            "terraform -chdir=infra init",
            "terraform -chdir=infra plan",
        ]
        for left, right in zip(steps, steps[1:]):
            self.assertLess(DEPLOY.index(left), DEPLOY.index(right),
                            "identity phase order violated between " + left + " and " + right)
        for marker in ("name: Clear infra Azure session before registry build",
                       "name: Clear build Azure session before Terraform"):
            block = DEPLOY[DEPLOY.index(marker):]
            block = block[:block.index("      - name: ") if "      - name: " in block else len(block)]
            self.assertIn("az logout", block)
            self.assertIn("az account clear", block)
        self.assertNotIn("client-id: ${{ inputs.", DEPLOY)
        self.assertNotIn("az acr update --role-assignment-mode", DEPLOY)


if __name__ == "__main__":
    unittest.main()
