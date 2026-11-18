"""TDD RED: owner-only created->active activation uses private COPY (#99).

All inputs below are synthetic change references, not personal identities.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/activate-organization.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "COMUNI_ACTIVATE_ORGANIZATION_ID",
    "COMUNI_ACTIVATE_CHANGE_TICKET",
    "COMUNI_ACTIVATE_APPROVER",
)


def synthetic():
    return dict(zip(KEYS, (
        "3a25b894-04da-49b9-85e4-d57342620427",
        "CHANGE-2026-ACTIVATE99",
        "independent-reviewer",
    ), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "activate-organization"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10,
        check=False,
    )


class OrganizationActivationPrivateCopyTests(unittest.TestCase):
    def test_sql_uses_static_client_copy_without_interpolated_values(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py activate-organization'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old in ("activate_org", "activate_ticket", "activate_approver"):
            self.assertNotIn(":'" + old + "'", sql)

    def test_helper_emits_exact_three_allowlisted_fields_one_record(self):
        values = synthetic()
        values["UNRELATED_SECRET"] = "must-not-reach-PostgreSQL"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        record = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, record)
        self.assertNotIn("UNRELATED_SECRET", record)

    def test_missing_empty_and_oversized_input_is_rejected_without_echo(self):
        for key, bad in (
            (KEYS[0], None),
            (KEYS[1], None),
            (KEYS[2], None),
            (KEYS[1], ""),
            (KEYS[2], "private-reviewer-canary" * 100),
            (KEYS[1], "private-ticket-canary" * 100),
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
