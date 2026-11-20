"""Test-first SCRAM transport privacy contract for issue #123.

All fixtures are synthetic. Never print the reversible transport envelope,
verifier, plaintext password or full PostgreSQL logs.
"""
import base64
import json
import unittest

from test_pgaudit_log_analyzer import PASSWORD, VERIFIER, fixture, gate


def encoded_forms(value: str) -> tuple[str, ...]:
    """Reversible representations that the private role COPY path can emit."""
    direct = base64.b64encode(value.encode("ascii")).decode("ascii")
    envelope = json.dumps(
        {"SCRAM_VERIFIER": value}, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return direct, base64.b64encode(envelope).decode("ascii")


class PgAuditScramTransportPrivacyTests(unittest.TestCase):
    def check(self, server_log: str, client_output: str = "") -> None:
        gate.assert_audits(
            server_log, [VERIFIER], [PASSWORD], client_output=client_output,
        )

    def test_sanitized_client_and_role_audit_are_accepted(self):
        self.check(fixture(), "BEGIN\nCOMMIT\n")

    def test_reversible_scram_verifier_in_server_log_is_rejected(self):
        for candidate in encoded_forms(VERIFIER):
            with self.subTest(form_length=len(candidate)):
                with self.assertRaises(AssertionError):
                    self.check(fixture() + "\nLOG: COPY payload " + candidate)

    def test_reversible_scram_verifier_in_psql_output_is_rejected(self):
        for candidate in (VERIFIER, *encoded_forms(VERIFIER)):
            with self.subTest(form_length=len(candidate)):
                with self.assertRaises(AssertionError):
                    self.check(fixture(), "psql: synthetic error " + candidate)

    def test_password_canary_in_client_output_is_rejected(self):
        for candidate in (PASSWORD, *encoded_forms(PASSWORD)):
            with self.subTest(form_length=len(candidate)):
                with self.assertRaises(AssertionError):
                    self.check(fixture(), "psql: synthetic error " + candidate)


if __name__ == "__main__":
    unittest.main()
