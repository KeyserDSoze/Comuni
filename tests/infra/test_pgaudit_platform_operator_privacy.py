"""RED-first pgAudit privacy contract for Superadmin operator and second Comune.

Actual PostgreSQL 17 pgAudit is exercised by the backend's disposable Docker
fixture. Inputs here are synthetic; never disclose server logs or COPY payload.
ADR 0103 / #119.
"""
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
spec = importlib.util.spec_from_file_location("comuni_audit_platform", SOURCE)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CANARIES = (
    "a118f8db-cd33-48b6-99f0-000000000119",
    "Secondo Comune Fittizio",
    "PROVISION-TEST-119",
    "reviewer-provision-119",
    "https://operator-ci.example.test/org",
    "platform-sub-119",
    "OP-ENROLL-119",
    "OP-REVOKE-119",
    "reviewer-operator-119",
    " invalid-operator-sub",
)


def synthetic_log() -> str:
    return "\n".join((
        "LOG: AUDIT: SESSION,23,1,FUNCTION,DO,,,,DO $provision$; ,<not logged>",
        "LOG: AUDIT: SESSION,24,1,FUNCTION,DO,,,,DO $operator$; ,<not logged>",
        "LOG: AUDIT: SESSION,25,1,WRITE,INSERT,,,,INSERT INTO platform.organizations ...,<not logged>",
        "LOG: AUDIT: SESSION,26,1,WRITE,INSERT,,,,INSERT INTO platform.platform_operators ...,<not logged>",
        "LOG: AUDIT: SESSION,27,1,WRITE,UPDATE,,,,UPDATE platform.platform_operators ...,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
    ))


class PlatformOperatorAndProvisionAuditTests(unittest.TestCase):
    def test_both_scripts_reject_parameter_value_logging_before_copy(self):
        for file in ("manage-platform-operator.sql", "provision-organization.sql"):
            source = (ROOT / "scripts" / "postgres" / file).read_text(encoding="utf-8")
            with self.subTest(script=file):
                begin = source.find("\nBEGIN;\n")
                guard = source.find("current_setting('pgaudit.log_parameter', true)")
                copy = source.find(r"\copy pg_temp.comuni_private_input(payload) FROM PROGRAM")
                self.assertGreaterEqual(begin, 0)
                self.assertGreater(guard, begin, "Parameter audit guard missing")
                self.assertGreater(copy, guard, "Guard must precede private COPY")
                self.assertTrue(
                    "Owner-only identity operation requires parameter-free audit metadata"
                    in source[begin:copy], "Missing constant denial"
                )

    def test_actual_pg_audit_fixture_executes_both_scripts(self):
        source = SOURCE.read_text(encoding="utf-8")
        for expected in (
            'private_owner_script("provision-organization.sql", second_provision)',
            'private_owner_script("manage-platform-operator.sql", operator_enroll)',
            "verify_platform_and_provision_under_pgaudit(name)",
            'assert_operator_provision_privacy(',
            '"DO $provision$"', '"DO $operator$"',
            "'platform.organization.created'",
            "'platform.operator.enrolled'",
            "'platform.operator.revoked'",
        ):
            with self.subTest(marker=expected):
                self.assertTrue(expected in source, "Missing real pgAudit integration")

    def test_privacy_requires_events_and_rejects_any_single_canary(self):
        gate.assert_operator_provision_privacy(synthetic_log(), "", CANARIES)
        for canary in CANARIES:
            with self.subTest(channel="server", size=len(canary)):
                with self.assertRaises(AssertionError):
                    gate.assert_operator_provision_privacy(
                        synthetic_log() + "\nLOG: " + canary, "", CANARIES)
            with self.subTest(channel="client", size=len(canary)):
                with self.assertRaises(AssertionError):
                    gate.assert_operator_provision_privacy(
                        synthetic_log(), "client:" + canary, CANARIES)
        lines = synthetic_log().splitlines()
        for marker in ("$provision$", "$operator$", ",FUNCTION,DO,",
                       ",WRITE,INSERT,", ",WRITE,UPDATE,"):
            with self.subTest(missing=marker):
                removed = "\n".join(line for line in lines if marker not in line)
                with self.assertRaises(AssertionError):
                    gate.assert_operator_provision_privacy(removed, "", CANARIES)
        lines = synthetic_log().splitlines()
        lines.pop(-1)
        with self.assertRaises(AssertionError):
            gate.assert_operator_provision_privacy("\n".join(lines), "", CANARIES)


if __name__ == "__main__":
    unittest.main()
