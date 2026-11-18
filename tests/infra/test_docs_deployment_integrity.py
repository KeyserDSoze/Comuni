"""TDD RED: deployment runbook must not be truncated or duplicated (#104).

The guard is offline, deterministic and keeps sensitive operational docs
unambiguous. No Azure credentials or live infrastructure are used.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = {
    "deployment.md": "# Deployment Azure",
    "security.md": "# Sicurezza: baseline e gap obbligatori prima del go-live",
    "testing.md": "# Strategia TDD e verifica",
    "api.md": "# API REST — primo incremento",
    "development.md": "# Avvio locale",
    "architecture.md": "# Architettura implementata — prima vertical slice",
}
REQUIRED_DEPLOYMENT_SECTIONS = (
    "## Registrazione owner-only con input privato COPY (#100 / ADR 0084)",
    "## Provisioning legacy owner-only: trasporto privato #101 (ADR 0085)",
    "## #102 — Gate created → active obbligatorio anche per provisioning legacy (ADR 0086)",
    "## Ritiro chiave tenant RLS: COPY privato per metadati (#103 / ADR 0087)",
)


class DeploymentDocumentIntegrityTests(unittest.TestCase):
    def test_one_unambiguous_primary_title_for_each_core_runbook(self):
        for filename, title in DOCUMENTS.items():
            with self.subTest(filename=filename):
                text = (ROOT / "docs" / filename).read_text(encoding="utf-8")
                self.assertTrue(text.startswith(title + "\n"))
                self.assertEqual(1, text.count(title), "Duplicate or embedded main title")

    def test_deployment_keeps_only_one_copy_of_recent_security_runbooks(self):
        text = (ROOT / "docs" / "deployment.md").read_text(encoding="utf-8")
        for heading in REQUIRED_DEPLOYMENT_SECTIONS:
            with self.subTest(heading=heading):
                self.assertEqual(1, text.count(heading))
        self.assertNotIn("DO $provision# Deployment Azure", text)


if __name__ == "__main__":
    unittest.main()
