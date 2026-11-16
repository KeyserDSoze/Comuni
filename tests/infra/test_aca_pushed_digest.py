"""ACR digest integrity tests (#64/#74), now backed by mocked REST data-plane.

The receipt from the actual Docker push is independent of the ACR tag
properties returned over OAuth2 HTTPS. No Azure or registry access in tests.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

from test_staged_rollout import SOURCE_COMMIT_SHA, MANAGED_REGISTRY
from test_acr_registry_data_plane_rest import HTTPS, reply, tag_object

ROOT = Path(__file__).resolve().parents[2]
RESOLVE = ROOT / "scripts/azure/resolve-pushed-image-digest.py"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
ACR = "synthetic"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SENTINEL = "private-credential-never-echo-me"

spec = importlib.util.spec_from_file_location("resolve_pushed", RESOLVE)
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)


def push_receipt(digest=DIGEST, tag=SOURCE_COMMIT_SHA):
    return ("The push refers to repository [synthetic.azurecr.io/comuni]\n"
            "layer: Pushed\n"
            + tag + ": digest: " + digest + " size: 1234\n")


def run_resolve(*, output=None, remote=DIGEST, sha=SOURCE_COMMIT_SHA,
                registry=ACR, host=MANAGED_REGISTRY, az_exit=0,
                fake_az=True, missing_push=False):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        receipt = root / "push.txt"
        if not missing_push:
            receipt.write_text(output if output is not None else push_receipt())
        envfile = root / "github-env"
        envfile.write_text("EXISTING_VALUE=preserve\n")

        def token_cli(argv, **kwargs):
            return SimpleNamespace(returncode=az_exit or (1 if not fake_az else 0),
                                   stdout="eyJ.AADTEST.SIGNATURE", stderr=SENTINEL)

        response = tag_object(remote)
        network = HTTPS([reply({"refresh_token": "eyJ.ACRREFRESH.SIGNATURE"}),
                         reply({"access_token": "eyJ.ACRACCESS.SIGNATURE"}),
                         reply(response)])
        opener = mock.Mock()
        opener.open = network.open
        argv = ["resolve-pushed-image-digest.py", "--source-commit-sha", sha,
                "--registry-name", registry, "--registry-host", host,
                "--tenant-id", TENANT,
                "--push-output-file", str(receipt), "--github-env", str(envfile)]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(resolver._acr.subprocess, "run",
                               side_effect=token_cli), \
             mock.patch.object(resolver._acr.urllib.request, "build_opener",
                               return_value=opener), \
             mock.patch.object(sys, "argv", argv), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = resolver.main()
        return SimpleNamespace(returncode=status, stdout=out.getvalue(),
                               stderr=err.getvalue()), envfile.read_text()


class ApprovedImageDigestTests(unittest.TestCase):
    def reject(self, **kwargs):
        result, envfile = run_resolve(**kwargs)
        self.assertNotEqual(result.returncode, 0,
                            "untrusted push/registry digest accepted")
        self.assertEqual(envfile, "EXISTING_VALUE=preserve\n")
        for private in (SENTINEL, "sha256:", TENANT, "eyJ."):
            self.assertNotIn(private, result.stdout + result.stderr)

    def test_real_push_receipt_matching_acr_writes_digest_pinned_image(self):
        result, envfile = run_resolve()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(
            envfile,
            "EXISTING_VALUE=preserve\n"
            + "TF_VAR_image=" + MANAGED_REGISTRY + "/comuni@" + DIGEST + "\n"
            + "CANDIDATE_IMAGE_DIGEST=" + DIGEST + "\n",
        )

    def test_rejects_tag_rewritten_in_acr_after_push(self):
        for remote in (OTHER, "", "\n" + DIGEST + "\n" + OTHER,
                       SENTINEL, "sha256:" + "A" * 64):
            with self.subTest(response_length=len(remote)):
                self.reject(remote=remote)

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
            {"sha": "b" * 40}, {"sha": ""},
            {"sha": SOURCE_COMMIT_SHA.upper()},
            {"registry": "different"}, {"registry": "../synthetic"},
            {"host": "evil.azurecr.io"},
            {"host": "synthetic.azurecr.io/other"},
            {"host": "synthetic.azurecr.io:443"}, {"host": SENTINEL},
        )
        for kwargs in cases:
            with self.subTest(kwargs=list(kwargs.keys())):
                self.reject(**kwargs)

    def test_rejects_azure_token_failure_or_wrong_repository_query(self):
        self.reject(az_exit=1)
        self.reject(fake_az=False)

    def test_workflow_must_pin_verified_digest_not_a_mutable_tag(self):
        self.assertIn("scripts/azure/resolve-pushed-image-digest.py", DEPLOY)
        self.assertIn('--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"', DEPLOY)
        self.assertIn('"$GITHUB_SHA"', DEPLOY)
        self.assertIn('--tenant-id "$ARM_TENANT_ID"', DEPLOY)
        self.assertNotIn('echo "TF_VAR_image=$IMAGE"', DEPLOY)
        self.assertLess(DEPLOY.index("resolve-pushed-image-digest.py"),
                        DEPLOY.index("terraform -chdir=infra plan"))


if __name__ == "__main__":
    unittest.main()
