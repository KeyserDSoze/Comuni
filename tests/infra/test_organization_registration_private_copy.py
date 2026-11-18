"""TDD RED: municipality registration inputs travel in private client COPY (#100).

Synthetic identifiers and change references only; no real municipal PII.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/register-organization.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "COMUNI_REGISTER_ORGANIZATION_ID",
    "COMUNI_REGISTER_ORGANIZATION_NAME",
    "COMUNI_REGISTER_CHANGE_TICKET",
    "COMUNI_REGISTER_APPROVER",
)


def synthetic():
    return dict(zip(KEYS, (
        "3a25b894-04da-49b9-85e4-d57342620427",
        "Comune Sintetico Privacy",
        "CHANGE-2026-REGISTER100",
        "synthetic-reviewer",
    ), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "register-organization"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10,
        check=False,
    )


class OrganizationRegistrationPrivateCopyTests(unittest.TestCase):
    def test_sql_uses_static_copy_not_psql_value_interpolation(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py register-organization'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        self.assertIn("WITH private_json AS", sql)
        for old in ("register_org", "register_name", "register_ticket", "register_approver"):
            self.assertNotIn(":'" + old + "'", sql)

    def test_helper_emits_one_exact_allowlisted_base64_json_record(self):
        values = synthetic()
        values["UNRELATED_SECRET"] = "never-forward-this-sentinel"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        record = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, record)
        self.assertNotIn("UNRELATED_SECRET", record)
        self.assertNotIn("never-forward-this-sentinel", result.stdout)

    def test_missing_empty_oversized_and_envelope_invalid_inputs_are_sanitized(self):
        cases = [(key, None) for key in KEYS]
        cases += [(key, "") for key in KEYS]
        cases += [(key, "private-registration-canary-" * 60) for key in KEYS]
        for key, bad in cases:
            with self.subTest(key=key, missing=bad is None):
                values = synthetic()
                if bad is None:
                    del values[key]
                else:
                    values[key] = bad
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("private-registration-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
