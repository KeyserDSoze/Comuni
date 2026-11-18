"""TDD RED: tenant proof retirement metadata must use private COPY (#103).

Inputs are synthetic identifiers, never signing keys or live municipal data.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/retire-tenant-proof-key.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "TENANT_PROOF_RETIRE_KEY_ID",
    "TENANT_PROOF_REPLACEMENT_KEY_ID",
    "TENANT_PROOF_GRACE_SECONDS",
)


def payload():
    return dict(zip(KEYS, ("retire-synthetic-103", "replace-synthetic-103", "300"), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "retire-tenant-proof"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
    )


class TenantRetirementPrivateCopyTests(unittest.TestCase):
    def test_retirement_uses_static_copy_and_no_sql_literals(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py retire-tenant-proof'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old in ("retire_id", "replacement_id", "grace_secs"):
            self.assertNotIn(":'" + old + "'", sql)
        self.assertIn("current_setting('comuni.retire_id', true)", sql)
        self.assertIn("LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE", sql)
        self.assertIn("interval '300 seconds'", sql)
        self.assertIn("least(valid_until,", sql)
        # PostgreSQL may reorder boolean AND terms, so bad grace values
        # must be protected by a nested CASE *before* integer casting.
        self.assertIn(
            "THEN CASE WHEN current_setting('comuni.grace_secs', true)::integer BETWEEN 0 AND 3600",
            sql,
        )

    def test_single_record_exact_allowlist_without_unrelated_environment(self):
        values = payload()
        values["UNRELATED_SECRET"] = "not-forward-this-103"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        parsed = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, parsed)
        self.assertNotIn("UNRELATED_SECRET", parsed)
        self.assertNotIn("not-forward-this-103", result.stdout)

    def test_missing_empty_and_oversized_input_rejected_without_echo(self):
        cases = [(key, None) for key in KEYS]
        cases += [(key, "") for key in KEYS]
        cases += [(key, "synthetic-private-retire-canary-" * 50) for key in KEYS]
        for key, invalid in cases:
            with self.subTest(key=key, missing=invalid is None):
                values = payload()
                if invalid is None:
                    values.pop(key)
                else:
                    values[key] = invalid
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("synthetic-private-retire-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
