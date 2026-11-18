"""RED-first, synthetic contract for owner-only Admin enrollment private COPY (#94)."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
SQL = ROOT / "scripts/postgres/enroll-additional-admin.sql"
KEYS = (
    "COMUNI_ADD_ADMIN_ORGANIZATION_ID",
    "COMUNI_ADD_ADMIN_IDENTITY_ISSUER",
    "COMUNI_ADD_ADMIN_SUBJECT",
    "COMUNI_ADD_ADMIN_CHANGE_TICKET",
    "COMUNI_ADD_ADMIN_APPROVER",
)


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "add-admin"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
    )


class AdminEnrollmentPrivateCopyTests(unittest.TestCase):
    def fixture(self):
        return dict(zip(KEYS, (
            "63bbf5f6-bde9-4d85-bb5b-19cae19833a1",
            "https://identity.example.test/tenant",
            "synthetic-opaque-sub-'; SELECT 1; --",
            "CHANGE-2026-PRIVATE94",
            "two-person-review-ref",
        ), strict=True))

    def test_sql_has_only_static_copy_statement_not_psql_identity_literals(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py add-admin'",
            sql)
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old in (
            "add_admin_org", "add_admin_issuer", "add_admin_subject",
            "add_admin_ticket", "add_admin_approver",
        ):
            self.assertNotIn(":'" + old + "'", sql)

    def test_helper_returns_one_exact_allowlisted_record_without_echo(self):
        values = self.fixture()
        values["UNRELATED_SECRET"] = "this-must-stay-client-side"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        contents = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, contents)
        self.assertNotIn("UNRELATED_SECRET", contents)

    def test_bad_input_fails_closed_and_does_not_print_payload(self):
        for key, bad in (
            (KEYS[2], None),
            (KEYS[2], ""),
            (KEYS[2], "private-canary" * 100),
            (KEYS[1], "private-issuer-canary" * 100),
        ):
            with self.subTest(key=key, bad=bad):
                values = self.fixture()
                if bad is None:
                    values.pop(key)
                else:
                    values[key] = bad
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("private-canary", result.stderr)
                self.assertNotIn("private-issuer-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
