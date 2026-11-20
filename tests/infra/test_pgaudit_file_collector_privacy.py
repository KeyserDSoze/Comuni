"""RED-first PostgreSQL17 pgAudit *file logging collector* privacy contract (#125).

All data are disposable synthetic canaries. Do not print captured log files,
psql output, SCRAM verifiers, or private COPY payloads.
"""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
spec = importlib.util.spec_from_file_location("collector_pg_audit_gate", GATE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

from test_pgaudit_log_analyzer import VERIFIER, PASSWORD

OWNER_VALUES = {
    "TENANT_PROOF_KEY_ID": "synthetic-file-sink-125",
    "TENANT_PROOF_KEY": "synthetic-file-sink-only-key-material-125-no-production",
}
RAW = json.dumps(OWNER_VALUES, ensure_ascii=True, separators=(",", ":"),
                 sort_keys=True).encode("ascii")
ENVELOPE = base64.b64encode(RAW).decode("ascii")


def collector_log() -> str:
    return "\n".join((
        "LOG: AUDIT: SESSION,10,1,ROLE,ALTER ROLE,,,ALTER ROLE comuni_app_runtime PASSWORD <REDACTED>,<not logged>",
        "LOG: AUDIT: SESSION,11,1,ROLE,ALTER ROLE,,,ALTER ROLE comuni_platform_reader PASSWORD <REDACTED>,<not logged>",
        "LOG: AUDIT: SESSION,12,1,ROLE,GRANT,,,GRANT CONNECT ON DATABASE synthetic TO role,<not logged>",
        "LOG: AUDIT: SESSION,13,1,FUNCTION,DO,,,,DO $tenant_stage$; ,<not logged>",
        "LOG: AUDIT: SESSION,14,1,WRITE,INSERT,,,,INSERT INTO platform.tenant_proof_keys...,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
    ))


class PgAuditFileCollectorTests(unittest.TestCase):
    def check(self, log: str, client_output: str = "") -> None:
        gate.assert_file_collector_privacy(
            log, client_output, [VERIFIER], [PASSWORD], OWNER_VALUES,
        )

    def test_accepts_file_collector_with_redaction_and_metadata(self):
        self.check(collector_log(), "BEGIN\nCOMMIT\n")

    def test_rejects_scram_components_password_and_envelopes_in_both_sinks(self):
        salt, stored, server = gate.scram_components(VERIFIER)
        for canary in (PASSWORD, VERIFIER, salt, stored, server, ENVELOPE,
                       OWNER_VALUES["TENANT_PROOF_KEY"],
                       base64.b64encode(VERIFIER.encode("ascii")).decode("ascii")):
            for channel in ("file", "client"):
                with self.subTest(kind=len(canary), channel=channel):
                    with self.assertRaises(AssertionError):
                        self.check(
                            collector_log() + ("\nLOG: " + canary if channel == "file" else ""),
                            "psql: " + canary if channel == "client" else "",
                        )

    def test_rejects_missing_any_role_or_unredacted_alter(self):
        for role in ("comuni_app_runtime", "comuni_platform_reader"):
            with self.subTest(role=role):
                with self.assertRaises(AssertionError):
                    self.check("\n".join(line for line in collector_log().splitlines()
                                         if role not in line))
                with self.assertRaises(AssertionError):
                    self.check(collector_log().replace(
                        "ALTER ROLE " + role + " PASSWORD <REDACTED>",
                        "ALTER ROLE " + role + " WITH LOGIN",
                    ))

    def test_rejects_missing_metadata_and_empty_file(self):
        for marker in ("ROLE,GRANT", "FUNCTION,DO", "WRITE,INSERT", "statement: COPY"):
            with self.subTest(marker=marker):
                with self.assertRaises(AssertionError):
                    self.check("\n".join(x for x in collector_log().splitlines()
                                         if marker not in x))
        with self.assertRaises(AssertionError):
            self.check("")

    def test_real_backend_gate_reads_postgres_file_sink_not_only_docker_logs(self):
        source = GATE.read_text(encoding="utf-8")
        for required in (
            "verify_file_collector_under_pgaudit(name)",
            "logging_collector",
            "pg_current_logfile()",
            "audit-ci.log",
            '["docker", "exec", name, "cat"',
            "assert_file_collector_privacy(",
            "private_owner_script(\"stage-tenant-proof-key.sql\"",
            "assert_auth(",
        ):
            with self.subTest(required=required):
                self.assertTrue(required in source, "Missing file collector privacy gate")
        pipeline = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("tests/postgres/pgaudit/verify_role_audit.py", pipeline)


if __name__ == "__main__":
    unittest.main()
