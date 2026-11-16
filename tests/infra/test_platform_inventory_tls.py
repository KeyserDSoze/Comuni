"""Offline regression for global inventory SQL TLS server identity, no Azure."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = (ROOT / "src/backend/Applications/Api/Security/PlatformInventorySettings.cs").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()

class PlatformInventoryTlsContractTests(unittest.TestCase):
    def test_hosted_platform_reader_requires_hostname_and_ca_validation(self):
        self.assertIn("SslMode.VerifyFull", SETTINGS)
        self.assertIn("TrustServerCertificate", SETTINGS)
        self.assertNotIn("SslMode.Require or SslMode.VerifyCA", SETTINGS)
        self.assertIn('environmentName is not ("Development" or "Testing")', SETTINGS)

    def test_feature_remains_opt_in_without_plaintext_secret_in_terraform(self):
        self.assertIn("enable_platform_inventory", DEPLOY)
        self.assertNotIn("TF_VAR_platform_inventory_password:", DEPLOY)
        self.assertNotIn("TF_VAR_platform_inventory_connection:", DEPLOY)

if __name__ == "__main__":
    unittest.main()
