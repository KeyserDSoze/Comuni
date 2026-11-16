"""Offline TDD for content-addressed ACA image release (issue #64).

The GitHub workflow must prove that the digest produced by its own Docker push
matches ACR tag metadata, then hand a digest-only URI to Terraform. No Azure
access or real credentials: fake 'az' is isolated on PATH.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_staged_rollout import SOURCE_COMMIT_SHA, MANAGED_REGISTRY

ROOT = Path(__file__).resolve().parents[2]
RESOLVE = ROOT / "scripts/azure/resolve-pushed-image-digest.py"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
ACR = "synthetic"
SENTINEL = "private-credential-never-echo-me"
FAKE_AZ = '''#!/usr/bin/env python3
import os
import sys

expected = [
    "acr", "manifest", "show-metadata", "--registry", os.environ["FAKE_ACR_NAME"],
    "--name", "comuni:" + os.environ["FAKE_SHA"],
    "--query", "digest", "--output", "tsv", "--only-show-errors",
]
if sys.argv[1:] != expected:
    print("wrong mocked registry/repository request", file=sys.stderr)
    sys.exit(73)
print(os.environ.get("FAKE_DIGEST", ""))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
'''


def push_receipt(digest=DIGEST, tag=SOURCE_COMMIT_SHA):
    return ("The push refers to repository [synthetic.azurecr.io/comuni]\n"
            "layer: Pushed\n"
            + tag + ": digest: " + digest + " size: 1234\n")


def run_resolve(*, output=None, remote=DIGEST, sha=SOURCE_COMMIT_SHA,
                registry=ACR, host=MANAGED_REGISTRY, az_exit=0,
                fake_az=True, missing_push=False):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "az").write_text(FAKE_AZ, encoding="utf-8")
        (root / "az").chmod(0o700)
        receipt = root / "push.txt"
        if not missing_push:
            receipt.write_text(output if output is not None else push_receipt(),
                               encoding="utf-8")
        envfile = root / "github-env"
        envfile.write_text("EXISTING_VALUE=preserve\n", encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "PATH": str(root) + os.pathsep + env.get("PATH", ""),
            "FAKE_ACR_NAME": ACR,
            "FAKE_SHA": SOURCE_COMMIT_SHA,
            "FAKE_DIGEST": remote,
            "FAKE_EXIT": str(az_exit),
        })
        if not fake_az:
            env["FAKE_SHA"] = "not-the-requested-repository"
        result = subprocess.run(
            [sys.executable, str(RESOLVE),
             "--source-commit-sha", sha,
             "--registry-name", registry,
             "--registry-host", host,
             "--push-output-file", str(receipt),
             "--github-env", str(envfile)],
            env=env, capture_output=True, text=True, check=False,
        )
        return result, envfile.read_text(encoding="utf-8")


class ApprovedImageDigestTests(unittest.TestCase):
    def reject(self, **kwargs):
        result, envfile = run_resolve(**kwargs)
        self.assertNotEqual(result.returncode, 0,
                            "untrusted push/registry digest accepted")
        self.assertEqual(envfile, "EXISTING_VALUE=preserve\n")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("sha256:", result.stdout + result.stderr)

    def test_real_push_receipt_matching_acr_writes_digest_pinned_image(self):
        result, envfile = run_resolve()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")
        self.assertEqual(
            envfile,
            "EXISTING_VALUE=preserve\n"
            + "TF_VAR_image=" + MANAGED_REGISTRY + "/comuni@" + DIGEST + "\n"
            + "CANDIDATE_IMAGE_DIGEST=" + DIGEST + "\n",
        )

    def test_rejects_tag_rewritten_in_acr_after_push(self):
        self.reject(remote=OTHER)
        self.reject(remote="")
        self.reject(remote="\n" + DIGEST + "\n" + OTHER)
        self.reject(remote=SENTINEL)
        self.reject(remote="sha256:" + "A" * 64)

    def test_rejects_missing_untrusted_or_ambiguous_push_receipt(self):
        cases = (
            "", SENTINEL,
            push_receipt(tag="not-source-commit"),
            push_receipt(digest=OTHER) + push_receipt(digest=DIGEST),
            "not-the-sha: digest: " + DIGEST + " size: 99\n",
            push_receipt(digest="sha256:" + "A" * 64),
            push_receipt(digest="sha256:123"),
            push_receipt().replace("size: 1234", "size: unknown"),
            "random\ndigest: " + DIGEST + "\n",
        )
        for output in cases:
            with self.subTest(length=len(output)):
                self.reject(output=output)
        self.reject(missing_push=True)

    def test_rejects_wrong_registry_or_source_sha(self):
        cases = (
            {"sha": "b" * 40}, {"sha": ""}, {"sha": SOURCE_COMMIT_SHA.upper()},
            {"registry": "different"}, {"registry": "../synthetic"},
            {"host": "evil.azurecr.io"}, {"host": "synthetic.azurecr.io/other"},
            {"host": "synthetic.azurecr.io:443"}, {"host": SENTINEL},
        )
        for kwargs in cases:
            with self.subTest(kwargs=list(kwargs.keys())):
                self.reject(**kwargs)

    def test_rejects_cli_failure_or_wrong_repository_query(self):
        self.reject(az_exit=1)
        self.reject(fake_az=False)

    def test_workflow_must_pin_verified_digest_not_a_mutable_tag(self):
        self.assertIn("scripts/azure/resolve-pushed-image-digest.py", DEPLOY)
        self.assertIn('--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"', DEPLOY)
        self.assertIn('"$GITHUB_SHA"', DEPLOY)
        self.assertNotIn('echo "TF_VAR_image=$IMAGE"', DEPLOY)
        self.assertLess(DEPLOY.index("resolve-pushed-image-digest.py"),
                        DEPLOY.index("terraform -chdir=infra plan"))


if __name__ == "__main__":
    unittest.main()
