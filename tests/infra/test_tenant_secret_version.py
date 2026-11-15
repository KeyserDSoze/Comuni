"""Fail-closed contract for revision-pinned tenant proof keys, without Azure credentials."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = (ROOT / "infra/main.tf").read_text()
VARIABLES = (ROOT / "infra/variables.tf").read_text()
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
PREFLIGHT = ROOT / "scripts/azure/check-tenant-proof-secret.sh"
VERSION = "a" * 32
VAULT = "comuni-itn-001-kv"
SECRET_URI = f"https://{VAULT}.vault.azure.net/secrets/tenant-proof-key/{VERSION}"


class TenantSecretVersionTests(unittest.TestCase):
    def test_required_terraform_version_pins_key_vault_uri_with_no_secret_value(self):
        self.assertRegex(VARIABLES, r'variable\s+"tenant_proof_secret_version"\s*\{')
        self.assertIn("tenant_proof_secret_version", TERRAFORM)
        self.assertIn("secrets/tenant-proof-key/" + "$" + "{var.tenant_proof_secret_version}", TERRAFORM)
        self.assertNotIn("var.tenant_proof_key\n", TERRAFORM)
        self.assertNotIn("vault_uri}secrets/tenant-proof-key\"", TERRAFORM)

    def test_workflow_requires_version_from_approved_environment_and_passes_it_to_preflight(self):
        self.assertIn("TF_VAR_tenant_proof_secret_version: " + "$" + "{{ vars.TENANT_PROOF_SECRET_VERSION }}", DEPLOY)
        self.assertIn('check-tenant-proof-secret.sh "' + "$" + '{{ vars.AZURE_PREFIX }}-kv" "' + "$" + '{{ vars.TENANT_PROOF_SECRET_VERSION }}"', DEPLOY)
        self.assertLess(DEPLOY.index("check-tenant-proof-secret.sh"), DEPLOY.index("terraform -chdir=infra plan"))
        self.assertNotIn("TF_VAR_tenant_proof_key:", DEPLOY)

    def run_check(self, version=VERSION, enabled="true", error=0, vault=VAULT):
        with tempfile.TemporaryDirectory() as folder:
            fake_az = Path(folder) / "az"
            fake_az.write_text(
                "#!/bin/sh\n"
                'case " $* " in *" list-versions "*) ;; *) exit 12;; esac\n'
                'case " $* " in *" --vault-name comuni-itn-001-kv "*) ;; *) exit 13;; esac\n'
                'case " $* " in *" --name tenant-proof-key "*) ;; *) exit 14;; esac\n'
                f'case " $* " in *"{SECRET_URI}"*) ;; *) exit 16;; esac\n'
                'case " $* " in *"attributes.enabled"*) ;; *) exit 17;; esac\n'
                'case " $* " in *" --output tsv "*) ;; *) exit 15;; esac\n'
                f"printf '%s\\n' '{enabled}'\n"
                f"exit {error}\n"
            )
            fake_az.chmod(0o700)
            return subprocess.run(
                ["bash", str(PREFLIGHT), vault, version],
                env={**os.environ, "PATH": folder + os.pathsep + os.environ.get("PATH", "")},
                capture_output=True, text=True, check=False,
            )

    def test_preflight_accepts_only_approved_enabled_version(self):
        completed = self.run_check()
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertNotIn(SECRET_URI, completed.stdout)

    def test_preflight_rejects_disabled_missing_wrong_or_invalid_version(self):
        for result in [
            self.run_check(enabled="false"),
            self.run_check(error=1, enabled=""),
            self.run_check(version="b" * 32),
            self.run_check(version=""),
            self.run_check(version="xyz"),
            self.run_check(version="a" * 31),
            self.run_check(version="a" * 32 + ";echo hacked"),
            self.run_check(vault="unsafe;vault"),
        ]:
            self.assertNotEqual(0, result.returncode, (result.stdout, result.stderr))

    def test_secret_preflight_does_not_read_or_log_the_value(self):
        script = PREFLIGHT.read_text()
        self.assertIn("secret list-versions", script)
        self.assertNotIn("secret show", script)
        self.assertIn("--vault-name", script)
        self.assertIn("attributes.enabled", script)
        self.assertNotIn("--query value", script)
        self.assertNotIn("--query 'value'", script)
        self.assertNotIn("set -x", script)


if __name__ == "__main__":
    unittest.main()
