"""Offline ACR tag+manifest lock tests (#68/#74) using mocked HTTPS data plane.

No Azure network, ARM control-plane read or role writes. Ensure tag and
manifest are locked separately with digest and read-back integrity.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import sys
from unittest import mock
import unittest

from test_staged_rollout import SOURCE_COMMIT_SHA, SOURCE_IMAGE_DIGEST, MANAGED_REGISTRY
from test_acr_registry_data_plane_rest import HTTPS, reply, tag_object, manifest_object

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "scripts/azure/lock-approved-image.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
REGISTRY = "synthetic"
HOST = MANAGED_REGISTRY
DIGEST = SOURCE_IMAGE_DIGEST
OTHER = "sha256:" + "b" * 64
IMAGE = HOST + "/comuni@" + DIGEST
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SENTINEL = "private-acr-token-never-print"
LOCKED = {"writeEnabled": False, "deleteEnabled": False,
          "readEnabled": True, "listEnabled": True}
UNLOCKED = {**LOCKED, "writeEnabled": True}
DENIED_READ = {**LOCKED, "readEnabled": False}

spec = importlib.util.spec_from_file_location("lock_approved", LOCK)
locker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(locker)


def lock(*, image=IMAGE, sha=SOURCE_COMMIT_SHA, registry=REGISTRY,
         host=HOST, digest=DIGEST, before=DIGEST, after=DIGEST,
         tag_attrs=LOCKED, manifest_attrs=LOCKED, fail_at=-1):
    # HTTP actions: exchange, access token, tag preflight, PATCH tag,
    # PATCH manifest, GET tag read-back, GET manifest read-back.
    responses = [
        reply({"refresh_token": "eyJ.ACRREFRESH.SIGNATURE"}),
        reply({"access_token": "eyJ.ACRACCESS.SIGNATURE"}),
        reply(tag_object(before)),
        reply(tag_object(attr=tag_attrs)),
        reply(manifest_object(attr=manifest_attrs)),
        reply(tag_object(after, attr=tag_attrs)),
        reply(manifest_object(attr=manifest_attrs)),
    ]
    if fail_at in range(7):
        responses[fail_at] = reply({ "errors": [{"message": SENTINEL}] }, 500)
    # Malformed JSON simulation is passed through as an opaque bytes response.
    for i, response in enumerate(responses):
        if isinstance(response[0], str):
            responses[i] = reply(response[0].encode())
    network = HTTPS(responses)
    opener = mock.Mock()
    opener.open = network.open
    def az_token(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout="eyJ.AADTEST.SIGNATURE",
                               stderr=SENTINEL)

    argv = ["lock-approved-image.py", "--registry-name", registry,
            "--registry-host", host, "--tenant-id", TENANT,
            "--image", image, "--candidate-image-digest", digest,
            "--source-commit-sha", sha]
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(locker._acr.subprocess, "run", side_effect=az_token), \
         mock.patch.object(locker._acr.urllib.request, "build_opener",
                           return_value=opener), \
         mock.patch.object(sys, "argv", argv), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = locker.main()
    return SimpleNamespace(returncode=result, stdout=out.getvalue(),
                           stderr=err.getvalue()), network.requests


class ACROciLockTests(unittest.TestCase):
    def assert_rejected(self, **kwargs):
        result, requests = lock(**kwargs)
        self.assertNotEqual(0, result.returncode, "unsafe registry accepted")
        for private in (SENTINEL, DIGEST, "eyJ.", TENANT):
            self.assertNotIn(private, result.stdout + result.stderr)
        self.assertEqual("", result.stdout)
        for request, _ in requests:
            if request.get_method() == "PATCH":
                self.assertIn("/acr/v1/comuni/", request.full_url)
                self.assertNotIn("/acr/v1/comuni?api-version", request.full_url)
        return requests

    def test_locks_tag_and_manifest_then_verifies_both_and_digest(self):
        result, requests = lock()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(7, len(requests))
        self.assertEqual(["POST", "POST", "GET", "PATCH", "PATCH", "GET", "GET"],
                         [r.get_method() for r, _ in requests])
        self.assertIn("/_tags/" + SOURCE_COMMIT_SHA, requests[3][0].full_url)
        self.assertIn("/_manifests/" + DIGEST, requests[4][0].full_url)
        self.assertIn("/_tags/" + SOURCE_COMMIT_SHA, requests[5][0].full_url)
        self.assertIn("/_manifests/" + DIGEST, requests[6][0].full_url)

    def test_rejects_wrong_sha_registry_host_digest_or_image(self):
        for change in (
            {"sha": SOURCE_COMMIT_SHA.upper()}, {"sha": SOURCE_COMMIT_SHA[:12] + "f" * 28},
            {"sha": SENTINEL}, {"registry": "attacker"}, {"host": "attacker.azurecr.io"},
            {"host": "synthetic.azurecr.io:443"},
            {"image": HOST + "/comuni:" + SHA if False else HOST + "/comuni:latest"},
            {"image": HOST + "/other@" + DIGEST}, {"image": "evil.azurecr.io/comuni@" + DIGEST},
            {"digest": OTHER}, {"digest": "sha256:" + "A" * 64}, {"digest": SENTINEL},
        ):
            with self.subTest(field=next(iter(change))):
                self.assert_rejected(**change)

    def test_swapped_tag_before_lock_causes_no_patch(self):
        for value in ("", OTHER, SENTINEL, DIGEST + "\n" + OTHER):
            with self.subTest(value_len=len(value)):
                requests = self.assert_rejected(before=value)
                self.assertTrue(all(r.get_method() != "PATCH" for r, _ in requests))

    def test_failures_during_any_http_stage_never_expose_private_metadata(self):
        for stage in range(7):
            with self.subTest(stage=stage):
                requests = self.assert_rejected(fail_at=stage)
                self.assertEqual(stage + 1, len(requests))

    def test_changed_tag_on_readback_is_rejected(self):
        self.assert_rejected(after=OTHER)
        self.assert_rejected(after=SENTINEL)

    def test_unlocked_or_unreadable_tag_and_manifest_are_rejected(self):
        for attrs in (UNLOCKED, DENIED_READ, {},
                      {"writeEnabled": False, "deleteEnabled": False},
                      {**LOCKED, "deleteEnabled": "false"}):
            with self.subTest(attrs=attrs):
                self.assert_rejected(tag_attrs=attrs)
                self.assert_rejected(manifest_attrs=attrs)

    def test_workflow_lock_precedes_scan_and_plan(self):
        self.assertIn("scripts/azure/lock-approved-image.py", WORKFLOW)
        self.assertIn('--tenant-id "$ARM_TENANT_ID"', WORKFLOW)
        self.assertIn('--source-commit-sha "$GITHUB_SHA"', WORKFLOW)
        self.assertIn('--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"', WORKFLOW)
        self.assertLess(WORKFLOW.index("resolve-pushed-image-digest.py"),
                        WORKFLOW.index("lock-approved-image.py"))
        self.assertLess(WORKFLOW.index("lock-approved-image.py"),
                        WORKFLOW.index("trivy image"))
        self.assertLess(WORKFLOW.index("lock-approved-image.py"),
                        WORKFLOW.index("terraform -chdir=infra plan"))


if __name__ == "__main__":
    unittest.main()
