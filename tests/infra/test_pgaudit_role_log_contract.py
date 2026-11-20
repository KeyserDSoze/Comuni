"""RED-first CI contract: PostgreSQL 17 pgAudit must be exercised, not assumed.

This static guard runs in the existing Terraform/Python unittest gate. The
real integration test is independently executed on disposable PostgreSQL 17.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github/workflows/ci.yml"
SMOKE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
DOCKERFILE = ROOT / "tests/postgres/pgaudit/Dockerfile"


class PgAuditRoleLoggingContractTests(unittest.TestCase):
    def test_real_postgresql_pgaudit_logging_gate_is_blocking_in_main_ci(self):
        self.assertTrue(SMOKE.is_file(), "No live pgAudit ROLE/DDL integration check")
        self.assertTrue(DOCKERFILE.is_file(), "No PostgreSQL 17+pgAudit isolated image")
        pipeline = CI.read_text(encoding="utf-8")
        self.assertIn("tests/postgres/pgaudit/verify_role_audit.py", pipeline)
        self.assertIn("tests/postgres/pgaudit/Dockerfile", pipeline)
        self.assertLess(
            pipeline.index("tests/postgres/pgaudit/verify_role_audit.py"),
            pipeline.index("API integration and isolation tests"),
        )

    def test_real_check_requires_redacted_verifier_but_preserves_role_audit(self):
        self.assertTrue(SMOKE.is_file())
        code = SMOKE.read_text(encoding="utf-8")
        for requirement in (
            "pgaudit.log", "role,ddl", "AUDIT: SESSION",
            "SCRAM-SHA-256$", "CREATE ROLE", "ALTER ROLE",
            "<REDACTED>", "log_statement=all",
            "log_parameter_max_length=-1",
            "pg_authid", "rollback", "comuni_app_runtime",
            "comuni_platform_reader", '["docker", "logs", name]',
        ):
            self.assertIn(requirement, code)
        for forbidden in ("SET pgaudit.log = 'none'", "SET log_statement = 'none'"):
            self.assertNotIn(forbidden, code)

    def test_scram_transport_and_psql_stderr_are_inspected_in_real_gate(self):
        code = SMOKE.read_text(encoding="utf-8")
        for requirement in (
            'include_stderr=True', 'client_outputs.append(script(',
            'client_output="".join(client_outputs)',
            'base64.b64encode(envelope)',
            'pgaudit.log_parameter=on',
        ):
            self.assertIn(requirement, code)


if __name__ == "__main__":
    unittest.main()
