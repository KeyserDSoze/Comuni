"""RED-first offline security contract for initial Admin OIDC bootstrap (#95)."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/bootstrap-initial-admin.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "COMUNI_BOOTSTRAP_ORGANIZATION_ID",
    "COMUNI_BOOTSTRAP_IDENTITY_ISSUER",
    "COMUNI_BOOTSTRAP_SUBJECT",
    "COMUNI_BOOTSTRAP_CHANGE_TICKET",
    "COMUNI_BOOTSTRAP_APPROVER",
)


def synthetic():
    return dict(zip(KEYS, (
        "5745867c-1f19-40b4-9a8d-9f557762584c",
        "https://identity.example.test/tenant",
        "synthetic-bootstrap-sub-'; SELECT pg_sleep(0);--",
        "CHANGE-2026-BOOT95",
        "independent-reviewer",
    ), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "bootstrap-admin"],
        env=env, cwd=ROOT, capture_output=True, text=True,
        timeout=10, check=False,
    )


class BootstrapAdminPrivateCopyTests(unittest.TestCase):
    def test_sql_uses_client_copy_and_no_psql_identity_literal(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py bootstrap-admin'",
            sql)
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old in (
            "bootstrap_org", "bootstrap_issuer", "bootstrap_subject",
            "bootstrap_ticket", "bootstrap_approver",
        ):
            self.assertNotIn(":'" + old + "'", sql)

    def test_exact_allowlist_single_record_preserves_opaque_subject(self):
        values = synthetic()
        values["UNRELATED_PRIVATE_VALUE"] = "must-not-reach-postgres"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        fields = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, fields)
        self.assertNotIn("UNRELATED_PRIVATE_VALUE", fields)

    def test_missing_empty_and_oversized_inputs_fail_without_logging(self):
        for key, replacement in (
            (KEYS[2], None),
            (KEYS[2], ""),
            (KEYS[2], "synthetic-private-canary" * 60),
            (KEYS[1], "synthetic-private-issuer" * 60),
        ):
            with self.subTest(key=key, value_present=replacement is not None):
                values = synthetic()
                if replacement is None:
                    values.pop(key)
                else:
                    values[key] = replacement
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("synthetic-private", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
