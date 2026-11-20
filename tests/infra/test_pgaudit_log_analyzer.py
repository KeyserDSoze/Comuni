"""Synthetic privacy regression tests for the real PostgreSQL17/pgAudit log gate.

Never use production secrets or print SQL logs. The independently executed
Docker pgAudit integration remains mandatory. ADR 0098 / issue #115.
"""
import base64
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
spec = importlib.util.spec_from_file_location("comuni_pgaudit_gate", GATE)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

ROLES = ("comuni_app_runtime", "comuni_platform_reader")
ACTIONS = ("CREATE ROLE", "ALTER ROLE")
# Canonical base64 matching the PostgreSQL17 pg_authid format.
SALT = base64.b64encode(bytes(range(16))).decode("ascii")
STORED_KEY = base64.b64encode(bytes(range(32))).decode("ascii")
SERVER_KEY = base64.b64encode(bytes(reversed(range(32)))).decode("ascii")
VERIFIER = f"SCRAM-SHA-256$4096:{SALT}${STORED_KEY}:{SERVER_KEY}"
PASSWORD = "synthetic-password-canary-not-used-outside-tests"


def audit_line(role: str, action: str, redacted: bool = True) -> str:
    suffix = " PASSWORD <REDACTED>" if redacted else " WITH LOGIN"
    return (f"LOG: AUDIT: SESSION,1,1,ROLE,{action},,,"
            f"{action} {role}{suffix},<not logged>")


def fixture(overrides: dict[tuple[str, str], bool] | None = None) -> str:
    overrides = overrides or {}
    lines = [audit_line(role, action, overrides.get((role, action), True))
             for role in ROLES for action in ACTIONS]
    lines += [
        "LOG: AUDIT: SESSION,8,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE test TO role,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input FROM STDIN",
    ]
    return "\n".join(lines)


class PgAuditLogAnalyzerTests(unittest.TestCase):
    def check(self, log: str) -> None:
        gate.assert_audits(log, [VERIFIER], [PASSWORD])

    def test_valid_pg_audit_metadata_and_copies_are_accepted(self):
        self.check(fixture())

    def test_every_role_create_and_alter_requires_its_own_redaction(self):
        for role in ROLES:
            for action in ACTIONS:
                with self.subTest(role=role, action=action):
                    log = fixture({(role, action): False})
                    with self.assertRaises(AssertionError):
                        self.check(log)

    def test_scram_components_are_not_safe_to_log_even_without_full_verifier(self):
        for component in (SALT, STORED_KEY, SERVER_KEY):
            with self.subTest(component_type=len(component)):
                log = fixture() + "\nLOG: sample nested statement: " + component
                with self.assertRaises(AssertionError):
                    self.check(log)

    def test_plaintext_password_or_complete_verifier_remain_forbidden(self):
        for candidate in (PASSWORD, VERIFIER):
            with self.subTest(candidate_length=len(candidate)):
                with self.assertRaises(AssertionError):
                    self.check(fixture() + "\nLOG: " + candidate)

    def test_role_grant_and_native_copy_must_still_be_logged(self):
        for missing in ("ROLE,GRANT", "statement: COPY"):
            with self.subTest(missing=missing):
                with self.assertRaises(AssertionError):
                    self.check("\n".join(line for line in fixture().splitlines()
                                         if missing not in line))


if __name__ == "__main__":
    unittest.main()
