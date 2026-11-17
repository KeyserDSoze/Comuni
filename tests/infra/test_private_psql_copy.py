"""Synthetic, non-production security contract for client-side private psql COPY.

Runs in the Terraform/infra gate with Python stdlib only. The envelope is
base64 transport encoding, not secrecy from the receiver.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "postgres" / "stream-private-input.py"
KEYS = (
    "COMUNI_EMERGENCY_ORGANIZATION_ID",
    "COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER",
    "COMUNI_EMERGENCY_OLD_SUBJECT",
    "COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER",
    "COMUNI_EMERGENCY_NEW_SUBJECT",
    "COMUNI_EMERGENCY_INCIDENT_TICKET",
    "COMUNI_EMERGENCY_SECURITY_REVIEWER",
    "COMUNI_EMERGENCY_MUNICIPAL_REVIEWER",
    "COMUNI_EMERGENCY_REASON_CODE",
)


def synthetic():
    return dict(zip(KEYS, (
        "1dd097f8-36d4-460d-828f-b6cf1e03f97e",
        "https://identity.example.test",
        "former-admin",
        "https://identity.example.test",
        "opaque-sub-';DROP TABLE platform.organizations;--",
        "INC-2026-00088",
        "sec-reviewer",
        "municipal-reviewer",
        "admin-compromise",
    ), strict=True))


def invoke(operation="emergency", values=None):
    env = os.environ.copy()
    env.update(synthetic() if values is None else values)
    return subprocess.run(
        [sys.executable, str(SCRIPT), operation],
        env=env, cwd=REPO, capture_output=True, text=True, timeout=10,
        check=False,
    )


class PrivatePostgresCopySourceTests(unittest.TestCase):
    def test_exact_allowlist_one_copy_record_no_error_or_injection(self):
        values = synthetic()
        values["COMUNI_EMERGENCY_EXTRA_PII"] = "must-never-be-sent-to-the-server"
        result = invoke(values=values)
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        self.assertEqual(1, len(result.stdout.splitlines()))
        envelope = base64.b64decode(result.stdout.strip(), validate=True)
        fields = json.loads(envelope)
        self.assertEqual(set(KEYS), set(fields))
        for key in KEYS:
            self.assertEqual(values[key], fields[key])
        self.assertNotIn("COMUNI_EMERGENCY_EXTRA_PII", fields)

    def test_missing_and_oversized_inputs_fail_without_echo_or_traceback(self):
        for change in ("missing", "oversized", "empty"):
            with self.subTest(change=change):
                values = synthetic()
                if change == "missing":
                    values.pop("COMUNI_EMERGENCY_OLD_SUBJECT")
                elif change == "empty":
                    values["COMUNI_EMERGENCY_OLD_SUBJECT"] = ""
                else:
                    values["COMUNI_EMERGENCY_OLD_SUBJECT"] = "private-sentinel" * 90
                env = os.environ.copy()
                for key in KEYS:
                    env.pop(key, None)
                env.update(values)
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), "emergency"],
                    env=env, cwd=REPO, capture_output=True, text=True,
                    timeout=10, check=False,
                )
                self.assertNotEqual(0, proc.returncode)
                self.assertEqual("", proc.stdout)
                self.assertEqual("Private input transport rejected", proc.stderr.strip())
                self.assertNotIn("private-sentinel", proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)

    def test_unknown_operation_fails_closed_and_no_payload_is_emitted(self):
        result = invoke(operation="unreviewed-owner-script")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("Private input transport rejected", result.stderr.strip())

    def test_tenant_proof_keys_use_exact_copy_allowlists_not_literal_sql(self):
        cases = (
            (
                "tenant-legacy", "provision-tenant-proof.sql",
                {"TENANT_PROOF_KEY": "test-only-legacy-key-for-copy-proof-2026-11-17"},
                ("tenant_proof_key",),
            ),
            (
                "tenant-stage", "stage-tenant-proof-key.sql",
                {
                    "TENANT_PROOF_KEY_ID": "test_copy_key",
                    "TENANT_PROOF_KEY": "test-only-staged-key-for-copy-proof-2026-11-17",
                },
                ("new_key", "new_key_id"),
            ),
        )
        for operation, filename, values, legacy_literals in cases:
            with self.subTest(operation=operation):
                result = invoke(operation=operation, values=values)
                self.assertEqual(0, result.returncode)
                self.assertEqual("", result.stderr)
                self.assertEqual(1, len(result.stdout.splitlines()))
                envelope = json.loads(base64.b64decode(result.stdout.strip(), validate=True))
                self.assertEqual(values, envelope)
                sql = (REPO / "scripts" / "postgres" / filename).read_text(
                    encoding="utf-8")
                self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
                self.assertIn(
                    "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py "
                    + operation + "'", sql)
                self.assertIn("ON COMMIT DROP", sql)
                self.assertIn("FROM pg_temp.comuni_private_input", sql)
                for key in legacy_literals:
                    self.assertNotIn(":'" + key + "'", sql)

    def test_tenant_proof_copy_errors_never_echo_key_material(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory():
            for operation, values in (
                ("tenant-legacy", {"TENANT_PROOF_KEY": "private-canary" * 200}),
                ("tenant-stage", {"TENANT_PROOF_KEY_ID": "synthetic"}),
                ("tenant-stage", {
                    "TENANT_PROOF_KEY_ID": "synthetic",
                    "TENANT_PROOF_KEY": "",
                }),
            ):
                with self.subTest(operation=operation, values=values):
                    env = os.environ.copy()
                    for key in ("TENANT_PROOF_KEY", "TENANT_PROOF_KEY_ID"):
                        env.pop(key, None)
                    env.update(values)
                    proc = subprocess.run(
                        [sys.executable, str(SCRIPT), operation], env=env,
                        cwd=REPO, capture_output=True, text=True, timeout=10,
                        check=False)
                    self.assertNotEqual(0, proc.returncode)
                    self.assertEqual("", proc.stdout)
                    self.assertEqual(
                        "Private input transport rejected", proc.stderr.strip())
                    self.assertNotIn("private-canary", proc.stderr)
                    self.assertNotIn("Traceback", proc.stderr)

    def test_sql_cannot_use_inline_psql_secret_literals(self):
        sql = (REPO / "scripts/postgres" /
               "stage-emergency-admin-replacement.sql").read_text(encoding="utf-8")
        self.assertIn("CREATE TEMP TABLE pg_temp.comuni_private_input", sql)
        self.assertIn(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py emergency'",
            sql,
        )
        for var in (
            "emergency_org", "emergency_old_issuer", "emergency_old_subject",
            "emergency_new_issuer", "emergency_new_subject", "emergency_ticket",
            "emergency_security_reviewer", "emergency_municipal_reviewer",
            "emergency_reason",
        ):
            self.assertNotIn(":'" + var + "'", sql)
        self.assertIn("ON COMMIT DROP", sql)
        self.assertIn("FROM pg_temp.comuni_private_input", sql)


if __name__ == "__main__":
    unittest.main()
