"""RED-first synthetic tests for owner-only identity operations under pgAudit.

The actual PostgreSQL 17 + pgAudit Docker fixture is mandatory in the backend
job. No real issuer/subject, secrets, municipal name or raw log is printed.
ADR 0099 / #116.
"""
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
spec = importlib.util.spec_from_file_location("comuni_pgaudit_identity", SOURCE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

# Match the exact nine canary categories checked by the integration gate.
CANARIES = (
    "2c4f8d0c-0b1e-4625-97bb-000000000116",
    "Comune-Fittizio-Canary",
    "https://issuer-synthetic.example.test",
    "private-sub-synthetic-2026",
    "REGISTER-2026-TEST",
    "BOOTSTRAP-2026-TEST",
    "synthetic-register-reviewer",
    "synthetic-bootstrap-reviewer",
    " invalid-subject-canary",
)


def log_with_audit() -> str:
    return "\n".join((
        "LOG: AUDIT: SESSION,11,1,FUNCTION,DO,,,,DO $register$; ,<not logged>",
        "LOG: AUDIT: SESSION,12,1,FUNCTION,DO,,,,DO $bootstrap$; ,<not logged>",
        "LOG: AUDIT: SESSION,13,1,WRITE,INSERT,,,,INSERT INTO platform.organizations SELECT ...,<not logged>",
        "LOG: AUDIT: SESSION,14,1,WRITE,INSERT,,,,INSERT INTO platform.organization_memberships SELECT ...,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
    ))


class PgAuditOwnerIdentityPrivacyTests(unittest.TestCase):
    def test_real_pg_audit_fixture_must_execute_both_owner_scripts(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertTrue("register-organization.sql" in source,
                        "Missing real registration script in pgAudit fixture")
        self.assertTrue("bootstrap-initial-admin.sql" in source,
                        "Missing real Admin bootstrap in pgAudit fixture")
        self.assertTrue("verify_identity_under_pgaudit(name)" in source,
                        "Owner-identity pgAudit integration is not invoked")
        self.assertTrue("assert_identity_privacy(" in source,
                        "Missing sensitive log privacy assertion")

    def test_scripts_reject_parameter_logging_before_private_copy(self):
        # pgAudit still records FUNCTION/WRITE; only the parameter *values*
        # cannot be logged by approved owner-only identity operations.
        for path in ("register-organization.sql", "bootstrap-initial-admin.sql"):
            sql = (ROOT / "scripts" / "postgres" / path).read_text(encoding="utf-8")
            guard = sql.find("current_setting('pgaudit.log_parameter', true)")
            copy = sql.find("\\copy pg_temp.comuni_private_input")
            with self.subTest(path=path):
                self.assertGreaterEqual(guard, 0)
                self.assertGreater(copy, guard)
                self.assertIn(
                    "Owner-only identity operation requires parameter-free audit metadata",
                    sql,
                )

    def test_clean_pgaudit_registration_and_bootstrap_are_accepted(self):
        gate.assert_identity_privacy(log_with_audit(), "", CANARIES)

    def test_each_identity_canary_in_server_log_or_client_output_is_rejected(self):
        for canary in CANARIES:
            with self.subTest(source="server", length=len(canary)):
                with self.assertRaises(AssertionError):
                    gate.assert_identity_privacy(
                        log_with_audit() + "\nLOG: " + canary, "", CANARIES)
            with self.subTest(source="client", length=len(canary)):
                with self.assertRaises(AssertionError):
                    gate.assert_identity_privacy(
                        log_with_audit(), "client trace: " + canary, CANARIES)

    def test_missing_copy_or_pg_audit_registration_and_bootstrap_is_rejected(self):
        lines = log_with_audit().splitlines()
        for substring in ("$register$", "$bootstrap$", ",FUNCTION,DO,",
                          ",WRITE,INSERT,", "statement: COPY"):
            with self.subTest(evidence=substring):
                without = "\n".join(line for line in lines
                                    if substring not in line)
                with self.assertRaises(AssertionError):
                    gate.assert_identity_privacy(without, "", CANARIES)


if __name__ == "__main__":
    unittest.main()
