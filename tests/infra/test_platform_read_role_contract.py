"""Static/offline contracts for privileged PostgreSQL provisioning verification.

Actual grants/deny conditions are exercised against PostgreSQL 17 by the CI
backend job after both runtime roles are provisioned. No live credentials.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts/postgres/verify-platform-read-role.sql"
CI = (ROOT / ".github/workflows/ci.yml").read_text()
PROVISION = (ROOT / "scripts/postgres/provision-platform-read-role.sql").read_text()


class PlatformReaderRoleContractTests(unittest.TestCase):
    def test_independent_owner_role_preflight_exists_and_is_run_after_provision(self):
        self.assertTrue(CHECK.is_file(), "Owner-side read-only verifier is required")
        body = CHECK.read_text()
        self.assertIn("BEGIN READ ONLY", body)
        self.assertIn("comuni_platform_reader", body)
        self.assertIn("comuni_app_runtime", body)
        self.assertIn("platform.platform_organization_inventory", body)
        self.assertIn("platform.active_platform_operator_id", body)
        self.assertIn("platform.platform_operator_audit_events", body)
        self.assertIn("has_any_column_privilege", body)
        self.assertIn("rolbypassrls", body)
        self.assertIn("pg_auth_members", body)
        self.assertIn("protocol", body)
        self.assertNotIn("GRANT ALL", body)
        self.assertNotIn("ALTER ROLE", body)
        self.assertNotIn("PASSWORD", body)
        self.assertIn("verify-platform-read-role.sql", CI)
        self.assertLess(CI.index("provision-platform-read-role.sql"),
                        CI.index("verify-platform-read-role.sql"))
        self.assertLess(CI.index("verify-platform-read-role.sql"),
                        CI.index("API integration and isolation tests"))

    def test_sql_role_provision_remains_explicit_and_not_owner_or_bypass(self):
        self.assertIn("NOINHERIT", PROVISION)
        self.assertIn("NOBYPASSRLS", PROVISION)
        self.assertIn("NOCREATEROLE", PROVISION)
        # The plaintext key name is intentionally absent from the SQL script.
        # Only the fixed client-side helper reads this environment variable.
        source = (ROOT / "scripts/postgres/stream-private-input.py").read_text()
        self.assertIn("PLATFORM_READ_DB_PASSWORD", source)
        self.assertIn("stream-private-input.py platform-role", PROVISION)
        self.assertNotIn(":'platform_password'", PROVISION)
        self.assertNotIn("\\gexec", PROVISION)
        self.assertNotIn("GRANT ALL PRIVILEGES ON ALL TABLES", PROVISION)
        self.assertNotIn("GRANT SELECT ON TABLE platform.organizations", PROVISION)


if __name__ == "__main__":
    unittest.main()
