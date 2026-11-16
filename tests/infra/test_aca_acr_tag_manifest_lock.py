"""RED-first: ACR tag AND manifest locks must be verified before staging (#68).

All commands use a strict fake Azure CLI; no registry, secrets or Azure mutation
is ever accessed. No failure may print the fake CLI's sensitive diagnostics.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_staged_rollout import SOURCE_COMMIT_SHA, SOURCE_IMAGE_DIGEST, MANAGED_REGISTRY

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/azure/lock-approved-image.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
REGISTRY = "synthetic"
DIGEST = SOURCE_IMAGE_DIGEST
IMAGE = MANAGED_REGISTRY + "/comuni@" + DIGEST
SENTINEL = "secret-token-never-print-in-acr-logs"

LOCKED = {
    "writeEnabled": False, "deleteEnabled": False,
    "readEnabled": True, "listEnabled": True,
}
UNLOCKED = {**LOCKED, "writeEnabled": True}
DENIED_READ = {**LOCKED, "readEnabled": False}

FAKE_AZ = '''#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
sha = os.environ["EXPECT_SHA"]
digest = os.environ["EXPECT_DIGEST"]
registry = os.environ["EXPECT_REGISTRY"]
common = ["--name", registry, "--output", "none", "--only-show-errors"]
calls = [
    ["acr", "manifest", "show-metadata", "--registry", registry,
     "--name", "comuni:" + sha, "--query", "digest",
     "--output", "tsv", "--only-show-errors"],
    ["acr", "repository", "update", "--name", registry,
     "--image", "comuni:" + sha,
     "--write-enabled", "false", "--delete-enabled", "false",
     "--output", "none", "--only-show-errors"],
    ["acr", "repository", "update", "--name", registry,
     "--image", "comuni@" + digest,
     "--write-enabled", "false", "--delete-enabled", "false",
     "--output", "none", "--only-show-errors"],
    ["acr", "manifest", "show-metadata", "--registry", registry,
     "--name", "comuni:" + sha, "--query", "digest",
     "--output", "tsv", "--only-show-errors"],
    ["acr", "repository", "show", "--name", registry,
     "--image", "comuni:" + sha, "--query", "changeableAttributes",
     "--output", "json", "--only-show-errors"],
    ["acr", "repository", "show", "--name", registry,
     "--image", "comuni@" + digest, "--query", "changeableAttributes",
     "--output", "json", "--only-show-errors"],
]
with open(os.environ["CALL_LOG"], "a", encoding="utf-8") as logfile:
    logfile.write(json.dumps(args) + "\\n")
n = len(open(os.environ["CALL_LOG"], encoding="utf-8").readlines()) - 1
if n >= len(calls) or args != calls[n]:
    sys.stderr.write(os.environ["SENSITIVE_ERROR"])
    sys.exit(93)
if os.environ["FAIL_AT"] == str(n):
    sys.stderr.write(os.environ["SENSITIVE_ERROR"])
    sys.exit(66)
if n == 0:
    print(os.environ["BEFORE_DIGEST"])
elif n == 3:
    print(os.environ["AFTER_DIGEST"])
elif n == 4:
    print(os.environ["TAG_ATTR"])
elif n == 5:
    print(os.environ["MANIFEST_ATTR"])
'''


def lock(*, image=IMAGE, sha=SOURCE_COMMIT_SHA, registry=REGISTRY,
         host=MANAGED_REGISTRY, digest=DIGEST, before=DIGEST, after=DIGEST,
         tag_attrs=LOCKED, manifest_attrs=LOCKED, fail_at=-1):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        fake = root / "az"
        fake.write_text(FAKE_AZ, encoding="utf-8")
        fake.chmod(0o700)
        log = root / "calls.jsonl"
        env = os.environ.copy()
        env.update({
            "PATH": str(root) + os.pathsep + env.get("PATH", ""),
            "EXPECT_SHA": SOURCE_COMMIT_SHA, "EXPECT_DIGEST": DIGEST,
            "EXPECT_REGISTRY": REGISTRY, "CALL_LOG": str(log),
            "BEFORE_DIGEST": before, "AFTER_DIGEST": after,
            "TAG_ATTR": json.dumps(tag_attrs) if not isinstance(tag_attrs, str) else tag_attrs,
            "MANIFEST_ATTR": (json.dumps(manifest_attrs) if not isinstance(manifest_attrs, str)
                               else manifest_attrs),
            "FAIL_AT": str(fail_at), "SENSITIVE_ERROR": SENTINEL,
        })
        result = subprocess.run(
            [sys.executable, str(SCRIPT),
             "--registry-name", registry, "--registry-host", host,
             "--image", image, "--candidate-image-digest", digest,
             "--source-commit-sha", sha],
            capture_output=True, text=True, env=env, check=False, timeout=10,
        )
        calls = ([json.loads(line) for line in log.read_text().splitlines()]
                 if log.exists() else [])
        return result, calls


class ACROciLockTests(unittest.TestCase):
    def assert_rejected(self, **kwargs):
        result, calls = lock(**kwargs)
        self.assertNotEqual(0, result.returncode, "unsafe ACR state accepted")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("sha256:", result.stdout + result.stderr)
        self.assertTrue(all("--write-enabled" not in call or
                            "true" not in call for call in calls),
                        "never unlock the tag/manifest on failure")
        self.assertTrue(all("--repository" not in call for call in calls),
                        "never alter attributes of the whole repository")
        return calls

    def test_locks_tag_and_manifest_then_verifies_both_and_digest(self):
        result, calls = lock()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(6, len(calls))
        self.assertEqual("comuni:" + SOURCE_COMMIT_SHA,
                         calls[1][calls[1].index("--image") + 1])
        self.assertEqual("comuni@" + DIGEST,
                         calls[2][calls[2].index("--image") + 1])
        for call in (calls[1], calls[2]):
            self.assertEqual("false", call[call.index("--write-enabled") + 1])
            self.assertEqual("false", call[call.index("--delete-enabled") + 1])
        self.assertEqual("comuni:" + SOURCE_COMMIT_SHA,
                         calls[4][calls[4].index("--image") + 1])
        self.assertEqual("comuni@" + DIGEST,
                         calls[5][calls[5].index("--image") + 1])

    def test_refuses_wrong_sha_host_repository_digest_and_mutable_tag(self):
        for variation in (
            {"sha": SOURCE_COMMIT_SHA.upper()},
            {"sha": SOURCE_COMMIT_SHA[:12] + "f" * 28},
            {"sha": SENTINEL},
            {"registry": "attacker"},
            {"registry": ""},
            {"host": "attacker.azurecr.io"},
            {"host": "synthetic.azurecr.io:443"},
            {"image": MANAGED_REGISTRY + "/comuni:" + SOURCE_COMMIT_SHA},
            {"image": MANAGED_REGISTRY + "/other@" + DIGEST},
            {"image": "attacker.azurecr.io/comuni@" + DIGEST},
            {"digest": "sha256:" + "b" * 64},
            {"digest": "sha256:" + "A" * 64},
            {"digest": SENTINEL},
        ):
            with self.subTest(variation=next(iter(variation))):
                self.assert_rejected(**variation)

    def test_refuses_changed_or_missing_tag_digest_before_any_lock(self):
        for response in ("", "sha256:" + "b" * 64, SENTINEL,
                         DIGEST + "\n" + DIGEST):
            with self.subTest(response_length=len(response)):
                calls = self.assert_rejected(before=response)
                self.assertEqual(1, len(calls))

    def test_refuses_any_azure_cli_failure_and_never_relays_diagnostics(self):
        for failing_call in range(6):
            with self.subTest(call=failing_call):
                calls = self.assert_rejected(fail_at=failing_call)
                self.assertEqual(failing_call + 1, len(calls))

    def test_refuses_tag_rewrite_after_lock(self):
        self.assert_rejected(after="sha256:" + "b" * 64)
        self.assert_rejected(after=SENTINEL)

    def test_rejects_missing_or_unsafe_tag_and_manifest_attributes(self):
        for attrs in (UNLOCKED, DENIED_READ, {}, None, "", "{}", "{bad",
                      {"writeEnabled": False, "deleteEnabled": False},
                      {**LOCKED, "deleteEnabled": "false"}):
            with self.subTest(attrs_type=str(type(attrs))):
                self.assert_rejected(tag_attrs=attrs)
                self.assert_rejected(manifest_attrs=attrs)

    def test_workflow_executes_lock_before_trivy_attestations_and_terraform(self):
        self.assertIn("scripts/azure/lock-approved-image.py", WORKFLOW)
        self.assertIn('--source-commit-sha "$GITHUB_SHA"', WORKFLOW)
        self.assertIn('--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"', WORKFLOW)
        self.assertIn('--image "$TF_VAR_image"', WORKFLOW)
        self.assertLess(WORKFLOW.index("resolve-pushed-image-digest.py"),
                        WORKFLOW.index("lock-approved-image.py"))
        self.assertLess(WORKFLOW.index("lock-approved-image.py"),
                        WORKFLOW.index("trivy image"))
        self.assertLess(WORKFLOW.index("lock-approved-image.py"),
                        WORKFLOW.index("actions/attest@"))
        self.assertLess(WORKFLOW.index("lock-approved-image.py"),
                        WORKFLOW.index("terraform -chdir=infra plan"))
        self.assertNotIn("az acr repository update --repository comuni", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
