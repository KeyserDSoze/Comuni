"""RED-first private COPY contract for owner-only platform operator management (#97).

These are synthetic values; no actual identity or production authorization.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "postgres" / "manage-platform-operator.sql"
HELPER = ROOT / "scripts" / "postgres" / "stream-private-input.py"
KEYS = (
    "COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER",
    "COMUNI_PLATFORM_OPERATOR_SUBJECT",
    "COMUNI_PLATFORM_OPERATOR_ACTION",
    "COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET",
    "COMUNI_PLATFORM_OPERATOR_APPROVER",
)


def synthetic():
    return dict(zip(KEYS, (
        "https://identity.example.test/tenant",
        "synthetic-platform-opaque-';SELECT pg_sleep(0);--",
        "enroll",
        "CHANGE-2026-OPERATOR97",
        "independent-reviewer",
    ), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "platform-operator"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10,
        check=False,
    )


class PlatformOperatorPrivateCopyTests(unittest.TestCase):
    def test_sql_uses_static_client_copy_and_no_inline_psql_identity(self):
        sql = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py platform-operator'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old_name in (
            "operator_issuer", "operator_subject", "operator_action",
            "operator_ticket", "operator_approver",
        ):
            self.assertNotIn(":'" + old_name + "'", sql)

    def test_helper_emits_one_exact_allowlisted_envelope_without_leaking_extra_env(self):
        values = synthetic()
        values["UNRELATED_PRIVATE_CANARY"] = "must-not-reach-the-server"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        contents = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, contents)
        self.assertNotIn("UNRELATED_PRIVATE_CANARY", contents)

    def test_missing_empty_or_oversized_input_is_refused_with_static_error(self):
        cases = (
            (KEYS[1], None),
            (KEYS[1], ""),
            (KEYS[1], "private-sub-canary" * 110),
            (KEYS[0], "private-issuer-canary" * 110),
            (KEYS[2], None),
            (KEYS[3], None),
            (KEYS[4], None),
        )
        for key, bad_value in cases:
            with self.subTest(key=key, present=bad_value is not None):
                values = synthetic()
                if bad_value is None:
                    values.pop(key)
                else:
                    values[key] = bad_value
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("private-sub-canary", result.stderr)
                self.assertNotIn("private-issuer-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
