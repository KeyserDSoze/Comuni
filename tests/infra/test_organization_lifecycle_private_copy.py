"""TDD RED: owner-only municipality lifecycle private COPY contract (#98).

Uses synthetic IDs and change references only, never real municipality PII.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/set-organization-suspension.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "COMUNI_LIFECYCLE_ORGANIZATION_ID",
    "COMUNI_LIFECYCLE_ACTION",
    "COMUNI_LIFECYCLE_CHANGE_TICKET",
    "COMUNI_LIFECYCLE_APPROVER",
    "COMUNI_LIFECYCLE_REASON_CODE",
)


def synthetic():
    return dict(zip(KEYS, (
        "905da8c9-ef4a-47c9-b951-c36261006098",
        "suspend",
        "CHANGE-2026-LIFECYCLE98",
        "independent-reviewer",
        "security-incident",
    ), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "organization-lifecycle"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10,
        check=False,
    )


class OrganizationLifecyclePrivateCopyTests(unittest.TestCase):
    def test_lifecycle_sql_has_static_client_copy_without_inline_literals(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py organization-lifecycle'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old in (
            "lifecycle_org", "lifecycle_action", "lifecycle_ticket",
            "lifecycle_approver", "lifecycle_reason",
        ):
            self.assertNotIn(":'" + old + "'", sql)

    def test_helper_sends_only_five_fields_in_one_base64_json_record(self):
        values = synthetic()
        values["UNRELATED_PRIVATE_CANARY"] = "must-not-reach-server"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        payload = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, payload)
        self.assertNotIn("UNRELATED_PRIVATE_CANARY", payload)

    def test_missing_empty_and_oversized_values_fail_closed_without_echo(self):
        for key, bad in (
            (KEYS[0], None),
            (KEYS[2], None),
            (KEYS[3], None),
            (KEYS[4], None),
            (KEYS[2], ""),
            (KEYS[3], "private-reviewer-canary" * 100),
            (KEYS[2], "private-ticket-canary" * 100),
        ):
            with self.subTest(key=key, present=bad is not None):
                values = synthetic()
                if bad is None:
                    values.pop(key)
                else:
                    values[key] = bad
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("private-reviewer-canary", result.stderr)
                self.assertNotIn("private-ticket-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
