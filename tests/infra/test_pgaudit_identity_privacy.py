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

CANARIES = (
    "Comune-Fittizio-Canary",
    "https://issuer-synthetic.example.test",
    "private-sub-synthetic-2026",
    "SYNTH-CHANGE-REVIEW-2026",
    "synthetic-independent-reviewer",
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
        self.assertIn("register-organization.sql", source)
        self.assertIn("bootstrap-initial-admin.sql", source)
        self.assertIn("verify_identity_under_pgaudit()", source)
        self.assertIn("assert_identity_privacy(", source)

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
