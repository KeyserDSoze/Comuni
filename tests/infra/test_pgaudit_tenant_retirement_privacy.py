"""RED-first owner-only tenant proof retirement pgAudit privacy gate.

The real PostgreSQL17+pgAudit Docker fixture must execute the reviewed SQL
against disposable staged keys. All sensitive canaries here are synthetic.
Never echo raw logs, COPY payloads or DB signing material. ADR 0106 / #122.
"""
import base64
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/retire-tenant-proof-key.sql"
GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
spec = importlib.util.spec_from_file_location("tenant_retirement_pgaudit", GATE)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CANARIES = (
    "synthetic_replacement_122",
    "synthetic_invalid_replacement_122",
)


def safe_log():
    return "\n".join((
        "LOG: AUDIT: SESSION,70,1,FUNCTION,DO,,,,DO $owner_audit_parameter_guard$; ,<not logged>",
        "LOG: AUDIT: SESSION,71,1,WRITE,UPDATE,,,,UPDATE platform.tenant_proof_keys ...,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
    ))


class TenantRetirementPgAuditTests(unittest.TestCase):
    def test_retire_script_must_deny_parameter_logging_before_private_copy(self):
        source = SQL.read_text(encoding="utf-8")
        begin = source.index("\nBEGIN;\n")
        guard = source.find("current_setting('pgaudit.log_parameter', true)")
        copy = source.find(r"\copy pg_temp.comuni_private_input(payload) FROM PROGRAM")
        self.assertGreater(guard, begin, "Missing retirement pgAudit profile guard")
        self.assertGreater(copy, guard, "Guard must run before private COPY")
        self.assertIn(
            "Owner-only retirement operation requires parameter-free audit metadata",
            source[begin:copy],
        )
        for required in ("ON COMMIT DROP", "SET LOCAL lock_timeout",
                         "LOCK TABLE platform.tenant_proof_keys",
                         "least(valid_until,"):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_real_postgresql17_fixture_must_exercise_retirement(self):
        source = GATE.read_text(encoding="utf-8")
        for required in (
            "verify_tenant_retirement_under_pgaudit(name, staged_id)",
            'private_owner_script("retire-tenant-proof-key.sql", retirement)',
            "assert_retirement_privacy(",
            '"DO $owner_audit_parameter_guard$"',
            "platform.tenant_proof_keys",
            "revoked_at IS NOT NULL",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_clean_pg_audit_retirement_metadata_is_accepted(self):
        gate.assert_retirement_privacy(safe_log(), "", CANARIES)

    def test_each_raw_and_base64_identifier_in_logs_or_client_is_rejected(self):
        for canary in CANARIES:
            for sensitive in (canary, base64.b64encode(canary.encode()).decode()):
                for channel in ("server", "client"):
                    with self.subTest(size=len(canary), encoded=sensitive != canary,
                                      channel=channel):
                        with self.assertRaises(AssertionError):
                            gate.assert_retirement_privacy(
                                safe_log() + ("\nLOG: " + sensitive if channel == "server" else ""),
                                ("client:" + sensitive if channel == "client" else ""),
                                CANARIES,
                            )

    def test_no_audit_class_or_missing_copy_is_rejected(self):
        lines = safe_log().splitlines()
        for marker in ("$owner_audit_parameter_guard$", ",FUNCTION,DO,",
                       ",WRITE,UPDATE,", "statement: COPY"):
            with self.subTest(missing=marker):
                modified = "\n".join(line for line in lines if marker not in line)
                with self.assertRaises(AssertionError):
                    gate.assert_retirement_privacy(modified, "", CANARIES)


if __name__ == "__main__":
    unittest.main()
