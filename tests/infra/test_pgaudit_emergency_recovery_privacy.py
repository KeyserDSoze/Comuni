"""RED-first pgAudit privacy contract for suspended-tenant OIDC Admin recovery.

Only synthetic canaries are used; the real PostgreSQL 17+pgAudit execution is
mandatory in the backend Docker fixture. Never print raw server logs or
reversible private COPY envelopes. ADR 0105 / #121.
"""
import base64
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/postgres/stage-emergency-admin-replacement.sql"
GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
spec = importlib.util.spec_from_file_location("emergency_pgaudit_gate", GATE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CANARIES = (
    "91111111-2222-4333-a444-555555555121",
    "https://old-synthetic.example.test/tenant",
    "old-compromised-synthetic-sub",
    "https://new-synthetic.example.test/tenant",
    "new-verified-synthetic-sub",
    "INC-2026-SYNTH-121",
    "security-reviewer-ci-121",
    "municipal-reviewer-ci-121",
    "emergency-reason-synthetic",
    "INC-2026-REPLAY-121",
)


def safe_audit_log():
    return "\n".join((
        "LOG: AUDIT: SESSION,51,1,FUNCTION,DO,,,,DO $emergency$; ,<not logged>",
        "LOG: AUDIT: SESSION,52,1,WRITE,UPDATE,,,,UPDATE platform.organization_memberships...,<not logged>",
        "LOG: AUDIT: SESSION,53,1,WRITE,INSERT,,,,INSERT INTO platform.organization_memberships...,<not logged>",
        "LOG: AUDIT: SESSION,54,1,WRITE,INSERT,,,,INSERT INTO platform.audit_events...,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
    ))


class EmergencyAdminPgAuditTests(unittest.TestCase):
    def test_owner_emergency_script_must_guard_before_private_copy(self):
        source = SCRIPT.read_text(encoding="utf-8")
        begin = source.index("\nBEGIN;\n")
        guard = source.find("current_setting('pgaudit.log_parameter', true)")
        copy = source.find(r"\copy pg_temp.comuni_private_input(payload) FROM PROGRAM")
        self.assertGreater(guard, begin, "Missing pgAudit safety gate")
        self.assertGreater(copy, guard, "Guard must execute BEFORE COPY")
        self.assertIn(
            "Owner-only emergency operation requires parameter-free audit metadata",
            source[begin:copy],
        )
        self.assertIn("ON COMMIT DROP", source)
        self.assertIn("DO $emergency$", source)
        self.assertIn("platform.membership.admin.emergency.staged", source)

    def test_real_postgresql_fixture_must_execute_emergency_script(self):
        source = GATE.read_text(encoding="utf-8")
        for marker in (
            "verify_emergency_under_pgaudit(name, identity_context)",
            'private_owner_script("stage-emergency-admin-replacement.sql", emergency)',
            '"DO $emergency$"',
            "assert_emergency_privacy(",
            "'platform.membership.admin.emergency.revoked'",
            "'platform.membership.admin.emergency.staged'",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

    def test_clean_function_write_and_copy_are_accepted(self):
        gate.assert_emergency_privacy(safe_audit_log(), "", CANARIES)

    def test_each_raw_or_encoded_emergency_canary_is_denied(self):
        for canary in CANARIES:
            for value in (canary, base64.b64encode(canary.encode()).decode()):
                for channel in ("server", "client"):
                    with self.subTest(size=len(canary), encoded=value != canary,
                                      channel=channel):
                        with self.assertRaises(AssertionError):
                            gate.assert_emergency_privacy(
                                safe_audit_log() + ("\nLOG: " + value if channel == "server" else ""),
                                ("client:" + value if channel == "client" else ""),
                                CANARIES,
                            )

    def test_each_missing_audit_class_or_copy_fails(self):
        lines = safe_audit_log().splitlines()
        for marker in ("$emergency$", ",FUNCTION,DO,", ",WRITE,UPDATE,",
                       ",WRITE,INSERT,", "statement: COPY"):
            with self.subTest(missing=marker):
                without = "\n".join(x for x in lines if marker not in x)
                with self.assertRaises(AssertionError):
                    gate.assert_emergency_privacy(without, "", CANARIES)


if __name__ == "__main__":
    unittest.main()
