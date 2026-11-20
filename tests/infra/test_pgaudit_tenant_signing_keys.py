"""RED: tenant signing secrets must be private under real PostgreSQL 17+pgAudit.

This deterministic analyzer uses only synthetic canaries; actual key staging
and provision are mandatory in the disposable pgAudit backend integration.
Neither key values nor captured pgAudit/server log lines may be printed.
ADR 0104 / #120.
"""
import base64
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
SCRIPTS = ROOT / "scripts/postgres"
spec = importlib.util.spec_from_file_location("tenant_signing_key_audit", GATE)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CANARIES = (
    "legacy-synthetic-signing-key-2026-red-first-not-real",
    "staged-synthetic-signing-key-2026-red-first-not-real",
    "synthetic_r120",
    "different-legacy-signing-key-2026-red-first-not-real",
    "different-staged-signing-key-2026-red-first-not-real",
)


def synthetic_log():
    return "\n".join((
        "LOG: AUDIT: SESSION,40,1,FUNCTION,DO,,,,DO $tenant_legacy$; ,<not logged>",
        "LOG: AUDIT: SESSION,41,1,FUNCTION,DO,,,,DO $tenant_stage$; ,<not logged>",
        "LOG: AUDIT: SESSION,42,1,WRITE,INSERT,,,,INSERT INTO platform.tenant_proof_secret ...,<not logged>",
        "LOG: AUDIT: SESSION,43,1,WRITE,INSERT,,,,INSERT INTO platform.tenant_proof_keys ...,<not logged>",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
        "LOG: statement: COPY pg_temp.comuni_private_input(payload) FROM STDIN",
    ))


class TenantSigningKeyPgAuditTests(unittest.TestCase):
    def test_both_scripts_fail_closed_before_receiving_private_key_copy(self):
        for filename in ("provision-tenant-proof.sql", "stage-tenant-proof-key.sql"):
            text = (SCRIPTS / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                begin = text.find("\nBEGIN;")
                check = text.find("current_setting('pgaudit.log_parameter', true)")
                copy = text.find(r"\copy pg_temp.comuni_private_input(payload) FROM PROGRAM")
                self.assertGreaterEqual(begin, 0)
                self.assertGreater(check, begin, "Missing parameter-value audit guard")
                self.assertGreater(copy, check, "Guard must run before COPY")
                self.assertIn(
                    "Owner-only signing key operation requires parameter-free audit metadata",
                    text[begin:copy],
                )
                self.assertIn("ON COMMIT DROP", text)
                self.assertIn("COMMIT;", text)

    def test_real_postgresql17_gate_must_execute_both_true_owner_scripts(self):
        source = GATE.read_text(encoding="utf-8")
        for signature in (
            'verify_tenant_signing_keys_under_pgaudit(name)',
            'private_owner_script("provision-tenant-proof.sql", legacy)',
            'private_owner_script("stage-tenant-proof-key.sql", staged)',
            '"DO $tenant_legacy$"', '"DO $tenant_stage$"',
            'assert_tenant_signing_key_privacy(',
            "tenant_proof_secret", "tenant_proof_keys",
        ):
            with self.subTest(marker=signature):
                self.assertIn(signature, source)

    def test_pg_audit_signing_key_analyzer_accepts_metadata_only(self):
        gate.assert_tenant_signing_key_privacy(synthetic_log(), "", CANARIES)

    def test_canaries_and_encoded_canaries_in_server_and_client_are_denied(self):
        for canary in CANARIES:
            encoded = base64.b64encode(canary.encode("utf-8")).decode("ascii")
            for value in (canary, encoded):
                for channel in ("server", "client"):
                    with self.subTest(length=len(canary), encoded=value != canary,
                                      channel=channel):
                        with self.assertRaises(AssertionError):
                            if channel == "server":
                                gate.assert_tenant_signing_key_privacy(
                                    synthetic_log() + "\nLOG: " + value, "", CANARIES)
                            else:
                                gate.assert_tenant_signing_key_privacy(
                                    synthetic_log(), "client:" + value, CANARIES)

    def test_missing_do_function_insert_or_single_copy_is_denied(self):
        lines = synthetic_log().splitlines()
        for marker in ("$tenant_legacy$", "$tenant_stage$",
                       ",FUNCTION,DO,", ",WRITE,INSERT,"):
            with self.subTest(missing=marker):
                without = "\n".join(line for line in lines if marker not in line)
                with self.assertRaises(AssertionError):
                    gate.assert_tenant_signing_key_privacy(without, "", CANARIES)
        without_one_copy = "\n".join(lines[:-1])
        with self.assertRaises(AssertionError):
            gate.assert_tenant_signing_key_privacy(without_one_copy, "", CANARIES)


if __name__ == "__main__":
    unittest.main()
