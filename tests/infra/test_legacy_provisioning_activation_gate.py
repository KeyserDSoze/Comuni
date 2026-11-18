"""TDD RED lifecycle regression for legacy owner-only provisioning (#102).

No real municipality data or Azure resources are involved.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROVISION = ROOT / "scripts/postgres/provision-organization.sql"
REGISTRATION = ROOT / "scripts/postgres/register-organization.sql"
MIGRATION = (
    ROOT / "src/backend/Infrastructures/Persistence/Migrations/"
    "202611150013_OrganizationActivationGate.cs"
)


class LegacyProvisioningActivationGateTests(unittest.TestCase):
    def test_legacy_provisioning_overrides_compat_default_only_for_new_tenants(self):
        sql = PROVISION.read_text(encoding="utf-8")
        insert = re.search(
            r"INSERT\s+INTO\s+platform\.organizations\s*"
            r"\(([^)]*)\)\s*VALUES\s*\(([^;]*)\);",
            sql, re.IGNORECASE | re.DOTALL,
        )
        self.assertIsNotNone(insert)
        columns = [column.strip().lower() for column in insert.group(1).split(",")]
        values = [value.strip().lower() for value in insert.group(2).split(",")]
        self.assertEqual(len(columns), len(values))
        self.assertIn("is_activated", columns)
        self.assertEqual("false", values[columns.index("is_activated")])
        self.assertNotRegex(sql, r"(?i)UPDATE\s+platform\.organizations\s+SET\s+is_activated")
        self.assertIn("platform.organization.created", sql)

    def test_canonical_registration_also_creates_pending_tenant(self):
        sql = REGISTRATION.read_text(encoding="utf-8")
        self.assertRegex(
            sql, r"(?is)INSERT\s+INTO\s+platform\.organizations\s*"
                 r"\([^)]*is_activated[^)]*\)\s*VALUES\s*"
                 r"\([^;]*FALSE\s*\)",
        )

    def test_migration_legacy_default_remains_true_and_no_backfill(self):
        migration = MIGRATION.read_text(encoding="utf-8")
        self.assertIn("ADD COLUMN is_activated boolean NOT NULL DEFAULT TRUE", migration)
        self.assertIn("CHECK (is_activated OR NOT is_suspended)", migration)


if __name__ == "__main__":
    unittest.main()
