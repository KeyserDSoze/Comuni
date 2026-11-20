"""RED-first privacy contract for reversible owner-only COPY envelopes (#124).

Synthetic values only. Never print a live input payload, log, or secret.
The backend Docker fixture must cover all 12 non-SCRAM operations.
"""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "tests/postgres/pgaudit/verify_role_audit.py"
PRODUCER = ROOT / "scripts/postgres/stream-private-input.py"

spec = importlib.util.spec_from_file_location("owner_envelope_pgaudit_gate", GATE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

FIXTURES = (
    {
        "COMUNI_BOOTSTRAP_IDENTITY_ISSUER": "https://issuer-synthetic.example.test",
        "COMUNI_BOOTSTRAP_SUBJECT": "owner-subject-124-synthetic",
        "COMUNI_BOOTSTRAP_CHANGE_TICKET": "SYNTH-124-OWNER",
    },
    {
        "TENANT_PROOF_KEY_ID": "synthetic_124",
        "TENANT_PROOF_KEY": "synthetic-stage-key-for-audit-contract-not-real-124",
    },
    {
        "TENANT_PROOF_RETIRE_KEY_ID": "legacy",
        "TENANT_PROOF_REPLACEMENT_KEY_ID": "synthetic_124",
        "TENANT_PROOF_GRACE_SECONDS": "0",
    },
)


def canonical_copy_envelope(values: dict[str, str]) -> str:
    payload = json.dumps(values, ensure_ascii=True, separators=(",", ":"),
                         sort_keys=True).encode("ascii")
    return base64.b64encode(payload).decode("ascii")


class OwnerCopyEnvelopePgAuditTests(unittest.TestCase):
    def test_canonical_fixture_is_reversible_without_individual_canary_substrings(self):
        for values in FIXTURES:
            with self.subTest(fields=len(values)):
                encoded = canonical_copy_envelope(values)
                self.assertTrue(encoded)
                # Short public metadata (e.g. grace='0') may occur by chance
                # in base64; only long private canaries prove the gap.
                self.assertFalse(any(value in encoded for value in values.values()
                                     if len(value) >= 12))
                recovered = json.loads(base64.b64decode(encoded, validate=True))
                self.assertEqual(values, recovered)

    def test_clean_metadata_audit_and_client_output_accepted(self):
        gate.assert_private_copy_envelopes_absent(
            "LOG: statement: COPY pg_temp.comuni_private_input FROM STDIN",
            "BEGIN\nCOMMIT\n",
            list(FIXTURES),
        )

    def test_every_canonical_envelope_rejected_in_server_and_client(self):
        for values in FIXTURES:
            envelope = canonical_copy_envelope(values)
            for channel in ("server", "client"):
                with self.subTest(fields=len(values), channel=channel):
                    with self.assertRaises(AssertionError):
                        gate.assert_private_copy_envelopes_absent(
                            "LOG: statement: COPY FROM STDIN" +
                            ("\nLOG: " + envelope if channel == "server" else ""),
                            "psql: " + envelope if channel == "client" else "",
                            list(FIXTURES),
                        )

    def test_empty_or_invalid_inventory_is_denied_without_echo(self):
        for envelopes in ([], [{}], [{"value": ""}], [{"value": None}]):
            with self.subTest(count=len(envelopes)):
                with self.assertRaises(AssertionError):
                    gate.assert_private_copy_envelopes_absent(
                        "LOG: statement: COPY", "", envelopes,
                    )

    def test_real_fixture_must_track_every_owner_script_and_scan_final_logs(self):
        script = GATE.read_text(encoding="utf-8")
        for required in (
            "PRIVATE_OWNER_INPUTS.append(",
            "PRIVATE_OWNER_CLIENT_OUTPUTS.append(",
            "assert_private_copy_envelopes_absent(",
            "private_owner_script(",
            "verify_tenant_retirement_under_pgaudit(name, staged_id)",
            "verify_emergency_under_pgaudit(name, identity_context)",
            "verify_tenant_signing_keys_under_pgaudit(name)",
            "verify_identity_under_pgaudit(name)",
            "verify_platform_and_provision_under_pgaudit(name)",
            "assert_audits(",
        ):
            with self.subTest(required=required):
                self.assertTrue(required in script, "Missing owner COPY privacy gate marker")
        producer = PRODUCER.read_text(encoding="utf-8")
        self.assertIn('sort_keys=True', producer)
        self.assertIn('separators=(",", ":")', producer)


if __name__ == "__main__":
    unittest.main()
