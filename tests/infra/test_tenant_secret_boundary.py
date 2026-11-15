"""Contract regression for Key Vault secret boundary (no Azure account needed)."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = (ROOT / "infra/main.tf").read_text()
VARIABLES = (ROOT / "infra/variables.tf").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
PREFLIGHT = ROOT / "scripts/azure/check-tenant-proof-secret.sh"


class TenantProofSecretBoundaryTests(unittest.TestCase):
    def test_terraform_references_existing_versionless_key_vault_secret_not_its_value(self):
        self.assertNotRegex(VARIABLES, r'variable\s+"tenant_proof_key"\s+\{')
        self.assertNotRegex(TERRAFORM, r'resource\s+"azurerm_key_vault_secret"\s+"tenant_proof_key"')
        self.assertIn("secrets/tenant-proof-key", TERRAFORM)
        self.assertIn("key_vault_secret_id", TERRAFORM)
        self.assertNotIn("var.tenant_proof_key\n", TERRAFORM)
        # Non-destructive transition for any state that already tracks this secret.
        self.assertRegex(TERRAFORM, r'removed\s*\{[\s\S]*?azurerm_key_vault_secret\.tenant_proof_key[\s\S]*?destroy\s*=\s*false')
        self.assertNotIn("TF_VAR_tenant_proof_key:", DEPLOY)
        self.assertIn("TF_VAR_tenant_proof_key_id:", DEPLOY)

    def test_workflow_preflights_only_secret_metadata_before_terraform_plan(self):
        self.assertTrue(PREFLIGHT.is_file())
        self.assertIn("scripts/azure/check-tenant-proof-secret.sh", DEPLOY)
        self.assertLess(DEPLOY.index("scripts/azure/check-tenant-proof-secret.sh"),
                        DEPLOY.index("terraform -chdir=infra plan"))
        self.assertNotIn("az keyvault secret show --query value", DEPLOY)

    def check_preflight(self, enabled="true", exit_status="0", vault="comuni-itn-001-kv", version="a" * 32):
        with tempfile.TemporaryDirectory() as temp:
            fake_az = Path(temp) / "az"
            fake_az.write_text(
                "#!/bin/sh\n"
                'case " $* " in *" --query attributes.enabled "*) ;; *) exit 9;; esac\n'
                'case " $* " in *" --id https://comuni-itn-001-kv.vault.azure.net/secrets/tenant-proof-key/' + 'a' * 32 + ' "*) ;; *) exit 8;; esac\n'
                f"printf '%s\\n' '{enabled}'\n"
                f"exit {exit_status}\n"
            )
            fake_az.chmod(0o700)
            return subprocess.run(
                ["bash", str(PREFLIGHT), vault, version],
                env={**os.environ, "PATH": temp + os.pathsep + os.environ.get("PATH", "")},
                text=True, capture_output=True, check=False
            )

    def test_preflight_accepts_enabled_existing_secret(self):
        result = self.check_preflight()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("secret value", result.stdout.lower())

    def test_preflight_rejects_disabled_missing_and_invalid_vault(self):
        self.assertNotEqual(0, self.check_preflight(enabled="false").returncode)
        self.assertNotEqual(0, self.check_preflight(enabled="", exit_status="1").returncode)
        self.assertNotEqual(0, self.check_preflight(vault="bad; echo insecure").returncode)

    def test_preflight_never_prints_secret_value(self):
        # Metadata-only query must not ask Azure CLI for the actual HMAC secret.
        text = PREFLIGHT.read_text()
        self.assertNotIn("--query value", text)
        self.assertNotIn("--query '{value", text)
        self.assertNotIn("--query \"value\"", text)


if __name__ == "__main__":
    unittest.main()
