"""RED-first pgAudit policy on Admin revocation and municipality suspension.

Synthetic contract only; the real PostgreSQL17/pgAudit Docker integration is
mandatory in the backend CI job. No PII, passwords or raw logs in test errors.
ADR 0102 / issue #118. Never invoke the COPY producer with live inputs.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SQL_ROOT = ROOT / "scripts/postgres"
REAL_GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
OPERATIONS = ("revoke-admin.sql", "set-organization-suspension.sql")


class OwnerRevocationAndSuspensionPrivacyTests(unittest.TestCase):
    def test_both_owner_operations_refuse_pgaudit_parameter_values_before_copy(self):
        for file in OPERATIONS:
            sql = (SQL_ROOT / file).read_text(encoding="utf-8")
            with self.subTest(file=file):
                begin = sql.find("\nBEGIN;\n")
                guard = sql.find("current_setting('pgaudit.log_parameter', true)")
                copy = sql.find(r"\copy pg_temp.comuni_private_input(payload)")
                self.assertGreaterEqual(begin, 0, "Missing transaction")
                self.assertGreater(guard, begin, "Missing on-parameter gate")
                self.assertGreater(copy, guard, "Gate must precede private COPY")
                self.assertTrue(
                    "Owner-only identity operation requires parameter-free audit metadata"
                    in sql[begin:copy], "Missing fixed fail-closed error"
                )
                self.assertTrue("ON COMMIT DROP" in sql, "Missing ephemeral table")

    def test_actual_postgresql17_fixture_executes_both_owner_scripts(self):
        source = REAL_GATE.read_text(encoding="utf-8")
        for snippet in (
            'private_owner_script("revoke-admin.sql", revocation)',
            'private_owner_script("set-organization-suspension.sql", suspension)',
            '"DO $revocation$"',
            '"DO $lifecycle$"',
            "'platform.membership.admin.revoked'",
            "'platform.organization.suspended'",
            "verify_identity_under_pgaudit(name)",
        ):
            with self.subTest(marker=snippet):
                self.assertTrue(snippet in source, "Real pgAudit path missing")
        self.assertTrue("metadata_only=False" in source, "Negative audit-on path missing")


if __name__ == "__main__":
    unittest.main()
