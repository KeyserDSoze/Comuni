"""Fail-closed owner-only psql TLS runbook contract (#49).

PostgreSQL 17 libpq uses verify-full for server certificate + hostname
verification. This checks documentation; it does not test live Azure TLS.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT = ROOT / "docs/deployment.md"
OWNER_EXAMPLE = re.compile(
    r'^\s*psql\s+"([^"\n]*\bsslmode=[^"\n]+)"\s*\\\s*$',
    re.MULTILINE,
)


class OwnerPsqlVerifyFullRunbookTests(unittest.TestCase):
    def test_all_documented_owner_psql_tls_examples_verify_ca_and_hostname(self):
        text = DEPLOYMENT.read_text(encoding="utf-8")
        examples = OWNER_EXAMPLE.findall(text)
        # Guard the real inventory so a missing/removed example cannot
        # silently pass or accidentally weaken to a bare psql command.
        self.assertEqual(10, len(examples))
        self.assertNotIn("sslmode=require", text.lower())
        for connection in examples:
            with self.subTest(connection=connection.split(" dbname=")[0]):
                self.assertIn("sslmode=verify-full", connection.lower())
                self.assertIn("sslrootcert=<approved-ca-bundle>", connection)
                self.assertIn("host=<private-postgres-fqdn>", connection)
                self.assertNotIn("trustservercertificate", connection.lower())

    def test_runbook_warns_about_hostname_and_ca_rotation(self):
        text = DEPLOYMENT.read_text(encoding="utf-8")
        self.assertIn("hostname del certificato", text)
        self.assertIn("CA radice", text)
        self.assertIn("CA precedenti e nuove", text)
        self.assertIn("ADR 0044", text)


if __name__ == "__main__":
    unittest.main()
