"""TDD: temporary sensitive Terraform binary plans are always cleaned up.

Execute the REAL Azure staging step with fake Terraform and Python gate; no
network, Terraform backend, Azure, secret store, or production credentials.
"""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
SENTINEL = "synthetic-runtime-sql-password-never-echo"


def stage_script():
    start = WORKFLOW.index(
        "      - name: Plan and stage candidate at zero traffic (no automatic promotion)"
    )
    next_step = WORKFLOW.find("      - name:", start + 6)
    block = WORKFLOW[start:next_step if next_step != -1 else None]
    lines = block.split("        run: |\n", 1)
    if len(lines) != 2:
        raise AssertionError("stage step must contain exactly one run script")
    script_lines = lines[1].splitlines()
    if not script_lines or any(not line.startswith("          ") for line in script_lines):
        raise AssertionError("stage step shell script indentation changed")
    return "\n".join(line[10:] for line in script_lines) + "\n"


FAKE_TERRAFORM = """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$2" >> "$CALL_LOG"
case "$2" in
  plan)
    printf '%s\\n' "$TEST_SENTINEL" > infra/deploy.tfplan
    stat -c '%a' infra/deploy.tfplan > "$MODE_LOG"
    if [[ "$FAIL_STAGE" == "plan" ]]; then exit 17; fi
    ;;
  show)
    cat infra/deploy.tfplan
    if [[ "$FAIL_STAGE" == "show" ]]; then exit 18; fi
    ;;
  apply)
    if [[ ! -f infra/deploy.tfplan ]]; then exit 19; fi
    if [[ "$FAIL_STAGE" == "apply" ]]; then exit 20; fi
    ;;
  *) exit 21;;
esac
"""
FAKE_PYTHON = """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "gate" >> "$CALL_LOG"
cat > /dev/null
if [[ "$FAIL_STAGE" == "gate" ]]; then exit 22; fi
"""


def run_stage(fail="", stale=False, symlink=False):
    with tempfile.TemporaryDirectory() as tmp:
        wd = Path(tmp)
        (wd / "infra").mkdir()
        binpath = wd / "bin"
        binpath.mkdir()
        terraform = binpath / "terraform"
        terraform.write_text(FAKE_TERRAFORM, encoding="utf-8")
        terraform.chmod(0o700)
        py = binpath / "python3"
        py.write_text(FAKE_PYTHON, encoding="utf-8")
        py.chmod(0o700)
        secret = wd / "infra" / "deploy.tfplan"
        if stale:
            secret.write_text(SENTINEL, encoding="utf-8")
        if symlink:
            target = wd / "external-plan-target"
            target.write_text(SENTINEL, encoding="utf-8")
            secret.symlink_to(target)
        env = {
            **os.environ,
            "PATH": str(binpath) + os.pathsep + os.environ.get("PATH", ""),
            "TEST_SENTINEL": SENTINEL,
            "FAIL_STAGE": fail,
            "CALL_LOG": str(wd / "calls"),
            "MODE_LOG": str(wd / "mode"),
        }
        env.update({
            "STABLE_REVISION_SUFFIX": "r000000000001",
            "TF_VAR_candidate_revision_suffix": "r000000000002",
            "STABLE_TENANT_PROOF_SECRET_VERSION": "a" * 32,
            "CANDIDATE_TENANT_PROOF_SECRET_VERSION": "b" * 32,
            "CANDIDATE_TENANT_PROOF_KEY_ID": "candidate2026",
            "RUNTIME_POSTGRES_CONNECTION_SECRET_VERSION": "d" * 32,
            "PLATFORM_INVENTORY_ENABLED": "false",
            "PLATFORM_INVENTORY_SECRET_VERSION": "",
        })
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", stage_script()],
            cwd=wd, env=env, capture_output=True, text=True, timeout=15,
        )
        calls = (wd / "calls").read_text().splitlines() if (wd / "calls").exists() else []
        mode = (wd / "mode").read_text().strip() if (wd / "mode").exists() else ""
        exists = secret.exists() or secret.is_symlink()
        target_kept = (wd / "external-plan-target").exists()
        return result, calls, mode, exists, target_kept


class SensitiveStagePlanCleanupTests(unittest.TestCase):
    def test_stage_has_strict_shell_umask_and_exit_cleanup_before_plan(self):
        script = stage_script()
        self.assertIn("set -euo pipefail", script)
        self.assertIn("umask 077", script)
        self.assertIn("trap ", script)
        self.assertIn(" EXIT", script)
        self.assertIn("rm -f", script)
        self.assertNotIn("set -x", script)
        self.assertNotIn("upload-artifact", WORKFLOW)
        self.assertLess(script.index("umask 077"), script.index("terraform -chdir=infra plan"))
        self.assertLess(script.index("trap "), script.index("terraform -chdir=infra plan"))
        self.assertIn("terraform -chdir=infra show -json deploy.tfplan | python3 scripts/azure/check-staged-rollout-plan.py", script)
        self.assertIn("terraform -chdir=infra apply -input=false -auto-approve deploy.tfplan", script)
        self.assertEqual(1, script.count("terraform -chdir=infra apply"))
        self.assertLess(script.index("check-staged-rollout-plan.py"),
                        script.index("terraform -chdir=infra apply"))

    def test_sensitive_plan_is_removed_on_success_and_every_failure(self):
        for failure, expected_calls in (
            ("", ["plan", "show", "gate", "apply"]),
            ("plan", ["plan"]),
            ("show", ["plan", "show", "gate"]),
            ("gate", ["plan", "show", "gate"]),
            ("apply", ["plan", "show", "gate", "apply"]),
        ):
            with self.subTest(failure=failure):
                result, calls, mode, exists, _ = run_stage(failure)
                self.assertEqual(failure == "", result.returncode == 0)
                self.assertEqual(expected_calls, calls)
                self.assertFalse(exists, "sensitive binary plan survived the step")
                self.assertEqual("600", mode, "Terraform plan must be created private")
                self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_existing_plan_is_not_reused_or_followed_via_symlink(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                result, calls, _, exists, target_kept = run_stage(
                    stale=not symlink, symlink=symlink)
                self.assertNotEqual(0, result.returncode)
                self.assertNotIn("apply", calls)
                self.assertNotIn("plan", calls)
                self.assertFalse(exists)
                self.assertNotIn(SENTINEL, result.stdout + result.stderr)
                if symlink:
                    self.assertTrue(target_kept)


if __name__ == "__main__":
    unittest.main()
