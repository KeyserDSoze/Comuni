"""TDD RED: owner-only Admin OIDC revocation COPY envelope contract (#96).

All inputs are synthetic; no real IdP, person or production secret.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/revoke-admin.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "COMUNI_REVOKE_ADMIN_ORGANIZATION_ID",
    "COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER",
    "COMUNI_REVOKE_ADMIN_SUBJECT",
    "COMUNI_REVOKE_ADMIN_CHANGE_TICKET",
    "COMUNI_REVOKE_ADMIN_APPROVER",
    "COMUNI_REVOKE_ADMIN_REASON_CODE",
)


def sample():
    return dict(zip(KEYS, (
        "ecfbad91-2b81-480b-969e-de9d024212fb",
        "https://identity.example.test/tenant",
        "synthetic-revoke-opaque-';SELECT pg_sleep(0);--",
        "CHANGE-2026-REVOKE96",
        "independent-reviewer",
        "operator-departure",
    ), strict=True))


def run(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "revoke-admin"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10,
        check=False,
    )


class AdminRevocationPrivateCopyTests(unittest.TestCase):
    def test_sql_uses_fixed_client_copy_without_inline_oidc_identity(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py revoke-admin'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for name in (
            "revoke_org", "revoke_issuer", "revoke_subject",
            "revoke_ticket", "revoke_approver", "revoke_reason",
        ):
            self.assertNotIn(":'" + name + "'", sql)

    def test_exact_six_fields_and_single_reversible_copy_record(self):
        values = sample()
        values["UNRELATED_PRIVATE_DATA"] = "never-sent-to-server"
        result = run(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        payload = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, payload)
        self.assertNotIn("UNRELATED_PRIVATE_DATA", payload)

    def test_missing_empty_oversized_or_unknown_operation_fail_without_echo(self):
        cases = (
            (KEYS[2], None),
            (KEYS[2], ""),
            (KEYS[2], "private-canary" * 100),
            (KEYS[1], "private-issuer-canary" * 100),
            (KEYS[5], None),
        )
        for key, replacement in cases:
            with self.subTest(key=key, present=replacement is not None):
                values = sample()
                if replacement is None:
                    values.pop(key)
                else:
                    values[key] = replacement
                result = run(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("private-canary", result.stderr)
                self.assertNotIn("private-issuer-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
