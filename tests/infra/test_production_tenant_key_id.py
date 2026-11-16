"""Production signer must never silently fall back to legacy tenant proofs.

Offline contract for Terraform and the entrypoint; no Azure account required.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
VARIABLES = (ROOT / "infra/variables.tf").read_text()
PROGRAM = (ROOT / "src/backend/Applications/Api/Program.cs").read_text()
SETTINGS = ROOT / "src/backend/Applications/Api/Security/TenantProofSigningSettings.cs"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()


class ProductionTenantKeyIdTests(unittest.TestCase):
    def test_terraform_requires_an_explicit_versioned_nonlegacy_key_id(self):
        match = re.search(r'^variable "tenant_proof_key_id"\s*\{(.*?)^\}',
                          VARIABLES, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        block = match.group(1)
        self.assertNotRegex(block, r'\bdefault\s*=')
        self.assertRegex(block, r'\bnullable\s*=\s*false')
        self.assertIn('var.tenant_proof_key_id != "legacy"', block)
        self.assertIn('can(regex(', block)

    def test_backend_entrypoint_validates_environment_before_registration(self):
        self.assertIn("TenantProofSigningSettings.Read(", PROGRAM)
        self.assertLess(PROGRAM.index("TenantProofSigningSettings.Read("),
                        PROGRAM.index("builder.Services.AddSingleton(tenantProofSigner)"))
        self.assertTrue(SETTINGS.exists())
        settings = SETTINGS.read_text()
        self.assertIn('Security:TenantProofKeyId', settings)
        self.assertIn('Production', settings)
        self.assertIn('"Development"', settings)
        self.assertIn('"Testing"', settings)

    def test_deploy_does_not_provide_a_legacy_fallback(self):
        self.assertIn("TF_VAR_tenant_proof_key_id:", DEPLOY)
        self.assertIn("vars.TENANT_PROOF_KEY_ID", DEPLOY)
        self.assertNotIn('TF_VAR_tenant_proof_key_id: ""', DEPLOY)
        self.assertNotIn("TF_VAR_tenant_proof_key_id: legacy", DEPLOY)


if __name__ == "__main__":
    unittest.main()
