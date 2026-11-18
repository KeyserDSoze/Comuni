"""TDD RED: owner-only legacy provisioning must use private COPY (#101).

Only synthetic municipality and approval references are used.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = ROOT / "scripts/postgres/provision-organization.sql"
HELPER = ROOT / "scripts/postgres/stream-private-input.py"
KEYS = (
    "COMUNI_PROVISION_ORGANIZATION_ID",
    "COMUNI_PROVISION_ORGANIZATION_NAME",
    "COMUNI_PROVISION_CHANGE_TICKET",
    "COMUNI_PROVISION_APPROVER",
)


def synthetic():
    return dict(zip(KEYS, (
        "3a25b894-04da-49b9-85e4-d57342620427",
        "Comune Sintetico Legacy",
        "CHANGE-2026-PROVISION101",
        "synthetic-reviewer",
    ), strict=True))


def invoke(values):
    env = os.environ.copy()
    for key in KEYS:
        env.pop(key, None)
    env.update(values)
    return subprocess.run(
        [sys.executable, str(HELPER), "provision-organization"],
        env=env, cwd=ROOT, capture_output=True, text=True, timeout=10,
        check=False,
    )


class OrganizationProvisioningPrivateCopyTests(unittest.TestCase):
    def test_sql_has_static_private_copy_without_sql_literals(self):
        sql = SQL.read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py provision-organization'",
            sql,
        )
        self.assertIn("FROM pg_temp.comuni_private_input", sql)
        for old in ("provision_org", "provision_name", "provision_ticket", "provision_approver"):
            self.assertNotIn(":'" + old + "'", sql)

    def test_exact_four_inputs_one_base64_json_record_no_environment_forwarding(self):
        values = synthetic()
        values["UNRELATED_SECRET"] = "must-not-leave-client-101"
        result = invoke(values)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        record = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
        self.assertEqual({key: values[key] for key in KEYS}, record)
        self.assertNotIn("UNRELATED_SECRET", record)
        self.assertNotIn("must-not-leave-client-101", result.stdout)

    def test_all_missing_empty_oversized_inputs_rejected_without_echo(self):
        cases = [(key, None) for key in KEYS]
        cases += [(key, "") for key in KEYS]
        cases += [(key, "private-provision-canary-" * 80) for key in KEYS]
        for key, bad in cases:
            with self.subTest(key=key, missing=bad is None):
                values = synthetic()
                if bad is None:
                    values.pop(key)
                else:
                    values[key] = bad
                result = invoke(values)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertEqual("Private input transport rejected", result.stderr.strip())
                self.assertNotIn("private-provision-canary", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_utf8_json_escape_expansion_over_envelope_cap_is_rejected(self):
        values = {key: "漢" * 341 for key in KEYS}
        result = invoke(values)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("Private input transport rejected", result.stderr.strip())
        self.assertNotIn("漢", result.stderr)


if __name__ == "__main__":
    unittest.main()
