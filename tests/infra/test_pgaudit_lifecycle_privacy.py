"""RED-first owner-only activation / second OIDC Admin pgAudit privacy gate.

This static contract must fail on main until both reviewed SQL scripts reject
parameter-value audit logging BEFORE the existing private COPY, and the
PostgreSQL 17 pgAudit Docker fixture exercises actual end-to-end onboarding.
No user data, credentials, Azure access, or secret output. #117 / ADR 0101.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts/postgres"
FIXTURE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
FILES = ("activate-organization.sql", "enroll-additional-admin.sql")


class OwnerLifecycleAuditPrivacyContractTests(unittest.TestCase):
    def test_each_script_fails_closed_before_private_copy_on_pgaudit_parameters(self):
        for name in FILES:
            source = (SCRIPTS / name).read_text(encoding="utf-8")
            with self.subTest(script=name):
                transaction = source.index("BEGIN;\n")
                guard = source.find("current_setting('pgaudit.log_parameter', true)")
                copy = source.index(
                    r"\copy pg_temp.comuni_private_input(payload) FROM PROGRAM"
                )
                self.assertGreater(guard, transaction,
                                   "SQL must check parameter logging inside transaction")
                self.assertLess(guard, copy, "Guard must deny before COPY payload")
                self.assertIn(
                    "Owner-only identity operation requires parameter-free audit metadata",
                    source[transaction:copy],
                )
                self.assertIn("ON COMMIT DROP", source)
                self.assertIn("DO $", source)
                self.assertIn("COMMIT;", source)

    def test_real_postgresql_pgaudit_fixture_covers_both_operations(self):
        source = FIXTURE.read_text(encoding="utf-8")
        for required in (
            'private_owner_script("activate-organization.sql", activation)',
            'private_owner_script("enroll-additional-admin.sql", additional_admin)',
            '"DO $activation$"',
            '"DO $enrollment$"',
            'pgaudit.log_parameter=off',
            'pgaudit.log=role,ddl,write,function',
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertIn("verify_identity_under_pgaudit(name)", source)


if __name__ == "__main__":
    unittest.main()
