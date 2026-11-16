"""Enforce a fail-closed API runtime PostgreSQL startup boundary for hosted Azure.

Offline source contract only; it does not inspect Key Vault secret values or
simulate a genuine Azure certificate authority.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROGRAM = (ROOT / "src/backend/Applications/Api/Program.cs").read_text()
SETTINGS = ROOT / "src/backend/Applications/Api/Security/RuntimePostgresConnectionSettings.cs"
TF = (ROOT / "infra/main.tf").read_text()


class RuntimePostgresStartupContractTests(unittest.TestCase):
    def test_single_api_validates_runtime_connection_before_platform_and_ef(self):
        self.assertIn("RuntimePostgresConnectionSettings.Read(", PROGRAM)
        self.assertNotIn('builder.Configuration.GetConnectionString("Default")', PROGRAM)
        self.assertLess(PROGRAM.index("RuntimePostgresConnectionSettings.Read("),
                        PROGRAM.index("PlatformInventorySettings.Read("))
        self.assertLess(PROGRAM.index("RuntimePostgresConnectionSettings.Read("),
                        PROGRAM.index("builder.Services.AddDbContext<ComuniDbContext>"))
        self.assertTrue(SETTINGS.is_file())
        source = SETTINGS.read_text()
        self.assertIn("NpgsqlConnectionStringBuilder", source)
        self.assertIn("SslMode.VerifyFull", source)
        self.assertIn("TrustServerCertificate", source)
        self.assertIn("comuni_app_runtime", source)
        self.assertIn("postgres.database.azure.com", source)
        self.assertIn('environmentName is not ("Development" or "Testing")', source)

    def test_no_in_place_legacy_terraform_secret_update_in_this_slice(self):
        self.assertIn('name                = "postgres-connection"', TF)
        self.assertIn('key_vault_secret_id = azurerm_key_vault_secret.postgres_connection.versionless_id', TF)
        self.assertIn('secrets/postgres-runtime-connection/', TF)


if __name__ == "__main__":
    unittest.main()
