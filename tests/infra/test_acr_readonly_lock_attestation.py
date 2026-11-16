"""RED-first read-only ACR lock attestation, separate from release writer (#75).

All Azure CLI + HTTPS effects are simulated. The auditor must have ONLY
repository:comuni:pull, support GET properties and never issue a PATCH,
including when the caller tries to invoke the writer API by mistake.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import unittest
import urllib.parse

from test_acr_registry_data_plane_rest import (
    AAD, REFRESH, BEARER, HOST, REGISTRY, TENANT,
    SHA, DIGEST, WRONG, SECRET, HTTPS, reply, tag_object, manifest_object, LOCKED,
)

ROOT = Path(__file__).resolve().parents[2]
LIBRARY = ROOT / "scripts/azure/acr-registry-data-plane.py"
CHECKER = ROOT / "scripts/azure/check-acr-readonly-lock.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()


class ACRReadOnlyAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("acr_data_readonly", LIBRARY)
        cls.client_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.client_module)
        spec = importlib.util.spec_from_file_location("acr_check_readonly", CHECKER)
        cls.cli_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cli_module)

    def scenario(self, *, tag=None, manifest=None, token=None, http_status=200,
                 expected=DIGEST):
        responses = [
            reply({"refresh_token": REFRESH}),
            reply({"access_token": BEARER} if token is None else token),
            reply(tag_object() if tag is None else tag, http_status),
            reply(manifest_object() if manifest is None else manifest),
        ]
        network = HTTPS(responses)
        opener = mock.Mock()
        opener.open = network.open
        commands = []
        def az(argv, **kwargs):
            commands.append(argv)
            self.assertTrue(kwargs["capture_output"])
            return SimpleNamespace(returncode=0, stdout=AAD, stderr=SECRET)

        with mock.patch.object(self.client_module.urllib.request, "build_opener",
                               return_value=opener), \
             mock.patch.object(self.client_module.subprocess, "run", side_effect=az):
            client = self.client_module.ACRClient(REGISTRY, HOST, TENANT,
                                                   read_only=True)
            client.authenticate()
            client.verify_locked(SHA, expected)
        return network.requests, commands

    def reject(self, **kwargs):
        with self.assertRaises(Exception):
            self.scenario(**kwargs)

    def test_repository_pull_token_and_two_get_requests_only(self):
        calls, commands = self.scenario()
        self.assertEqual(1, len(commands))
        self.assertEqual(["POST", "POST", "GET", "GET"],
                         [r.get_method() for r, _ in calls])
        self.assertEqual({
            "grant_type": ["refresh_token"], "service": [HOST],
            "scope": ["repository:comuni:pull"], "refresh_token": [REFRESH],
        }, urllib.parse.parse_qs(calls[1][0].data.decode()))
        self.assertEqual(
            "https://" + HOST + "/acr/v1/comuni/_tags/" + SHA +
            "?api-version=2021-07-01", calls[2][0].full_url)
        self.assertEqual(
            "https://" + HOST + "/acr/v1/comuni/_manifests/" + DIGEST +
            "?api-version=2021-07-01", calls[3][0].full_url)
        for request, timeout in calls:
            self.assertLessEqual(timeout, 30)
            self.assertGreater(timeout, 0)
        for request, _ in calls[2:]:
            self.assertEqual("Bearer " + BEARER,
                             request.get_header("Authorization"))

    def test_mutable_or_unreadable_tag_or_manifest_is_rejected(self):
        cases = (
            {**LOCKED, "writeEnabled": True},
            {**LOCKED, "deleteEnabled": True},
            {**LOCKED, "readEnabled": False},
            {**LOCKED, "writeEnabled": "false"},
            {"writeEnabled": False, "deleteEnabled": False},
            {},
        )
        for attrs in cases:
            with self.subTest(attrs=str(attrs)):
                self.reject(tag=tag_object(attr=attrs))
                self.reject(manifest=manifest_object(attr=attrs))

    def test_wrong_digest_registry_identity_token_or_http_denied(self):
        self.reject(tag=tag_object(WRONG))
        self.reject(manifest=manifest_object(WRONG))
        self.reject(tag={**tag_object(), "registry": "evil.azurecr.io"})
        self.reject(manifest={**manifest_object(), "imageName": "other"})
        self.reject(token={"access_token": ""})
        self.reject(token={"access_token": SECRET + " bad"})
        self.reject(http_status=401)
        self.reject(http_status=307)
        self.reject(expected=WRONG)

    def test_caller_cannot_modify_tag_or_manifest_in_read_only_mode(self):
        network = HTTPS([reply({"refresh_token": REFRESH}),
                         reply({"access_token": BEARER})])
        opener = mock.Mock()
        opener.open = network.open
        with mock.patch.object(self.client_module.urllib.request, "build_opener",
                               return_value=opener), \
             mock.patch.object(self.client_module.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0,
                                                            stdout=AAD,
                                                            stderr=SECRET)):
            client = self.client_module.ACRClient(REGISTRY, HOST, TENANT,
                                                  read_only=True)
            client.authenticate()
            with self.assertRaises(ValueError):
                client.lock(SHA, DIGEST)
            with self.assertRaises(ValueError):
                client._request("PATCH", self.client_module.tag_path(SHA),
                                json_body={"writeEnabled": True},
                                authenticated=True)
        self.assertEqual(2, len(network.requests))
        self.assertEqual(["POST", "POST"],
                         [request.get_method() for request, _ in network.requests])

    def test_manual_script_enforces_approved_image_and_hides_tokens(self):
        checker = self.cli_module
        image = HOST + "/comuni@" + DIGEST
        validated = []
        class Client:
            def __init__(self, name, host, tenant, *, read_only=False):
                validated.append(("client", name, host, tenant, read_only))
            def authenticate(self):
                validated.append(("auth",))
            def verify_locked(self, sha, digest):
                validated.append(("verify", sha, digest))
        with mock.patch.object(checker, "ACRClient", Client):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = checker.main([
                    "--registry-name", REGISTRY, "--registry-host", HOST,
                    "--tenant-id", TENANT, "--source-commit-sha", SHA,
                    "--candidate-image-digest", DIGEST, "--image", image,
                ])
            self.assertEqual(0, status, err.getvalue())
            self.assertEqual("", out.getvalue())
        self.assertEqual([("client", REGISTRY, HOST, TENANT, True),
                          ("auth",), ("verify", SHA, DIGEST)], validated)
        for variation in (
            ("--image", "evil.azurecr.io/comuni@" + DIGEST),
            ("--image", HOST + "/other@" + DIGEST),
            ("--image", HOST + "/comuni:" + SHA),
            ("--source-commit-sha", SHA.upper()),
            ("--candidate-image-digest", WRONG),
        ):
            args = [
                "--registry-name", REGISTRY, "--registry-host", HOST,
                "--tenant-id", TENANT, "--source-commit-sha", SHA,
                "--candidate-image-digest", DIGEST, "--image", image,
            ]
            args[args.index(variation[0]) + 1] = variation[1]
            with mock.patch.object(checker, "ACRClient", Client):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    status = checker.main(args)
                self.assertNotEqual(0, status)
                self.assertEqual("", out.getvalue())
                for secret in (SECRET, DIGEST, TENANT):
                    self.assertNotIn(secret, err.getvalue())

    def test_release_workflow_remains_writer_and_auditor_is_not_called_in_staging(self):
        self.assertNotIn("check-acr-readonly-lock.py", WORKFLOW)
        self.assertIn("scripts/azure/lock-approved-image.py", WORKFLOW)
        self.assertIn("scripts/azure/resolve-pushed-image-digest.py", WORKFLOW)
        self.assertEqual("repository:comuni:pull,push",
                         self.client_module.SCOPE)


if __name__ == "__main__":
    unittest.main()
