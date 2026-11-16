"""RED-first ACR OAuth2 tests. All Azure CLI, HTTPS and Docker calls are mocked."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import urllib.parse
import unittest

ROOT = Path(__file__).resolve().parents[2]
LOGIN = ROOT / "scripts/azure/login-acr-oauth.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
REGISTRY = "synthetic"
HOST = REGISTRY + ".azurecr.io"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AAD_TOKEN = "eyJ.AAD_TEST_ONLY.SIGNATURE"
ACR_REFRESH = "eyJ.ACR_REFRESH_TEST_ONLY.SIGNATURE"
SENTINEL = "private-entra-token-never-print"
NULL_GUID = "00000000-0000-0000-0000-000000000000"
AZ = ["az", "account", "get-access-token", "--resource",
      "https://containerregistry.azure.net", "--query", "accessToken",
      "--output", "tsv", "--only-show-errors"]
DOCKER = ["docker", "login", HOST, "--username", NULL_GUID, "--password-stdin"]


class FakeResponse(io.BytesIO):
    def __init__(self, value, status=200):
        super().__init__(value)
        self.status = status


class FakeOpener:
    def __init__(self, value, status=200, raised=None):
        self.value, self.status, self.raised = value, status, raised
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.raised is not None:
            raise self.raised
        return FakeResponse(self.value, self.status)


class OAuthDockerLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("acr_login_oauth", LOGIN)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def invoke(self, *, registry=REGISTRY, host=HOST, tenant=TENANT,
               aad=AAD_TOKEN, refresh=ACR_REFRESH, az_failure=False,
               docker_failure=False, response=None, status=200,
               raised=None):
        body = (json.dumps({"refresh_token": refresh}).encode()
                if response is None else response)
        fake = FakeOpener(body, status=status, raised=raised)
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            self.assertTrue(kwargs.get("capture_output"))
            if args[0] == "az":
                self.assertEqual(AZ, args)
                return SimpleNamespace(returncode=int(az_failure), stdout=aad,
                                       stderr=SENTINEL)
            if args[0] == "docker":
                self.assertEqual(DOCKER, args)
                self.assertEqual(ACR_REFRESH, kwargs.get("input"))
                self.assertTrue(kwargs.get("text"))
                self.assertNotIn(ACR_REFRESH, repr(args))
                return SimpleNamespace(returncode=int(docker_failure),
                                       stdout=SENTINEL, stderr=SENTINEL)
            self.fail("unexpected subprocess")

        with mock.patch.object(self.module.subprocess, "run", side_effect=run), \
             mock.patch.object(self.module.urllib.request, "build_opener",
                               return_value=fake) as opener:
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = self.module.main([
                    "--registry-name", registry, "--registry-host", host,
                    "--tenant-id", tenant])
        return result, stdout.getvalue(), stderr.getvalue(), calls, fake, opener

    def denied(self, **kwargs):
        code, out, err, calls, _, _ = self.invoke(**kwargs)
        self.assertNotEqual(0, code, "unsafe registry login accepted")
        for value in (SENTINEL, AAD_TOKEN, ACR_REFRESH, TENANT):
            self.assertNotIn(value, out + err)
        self.assertNotIn("Traceback", out + err)
        self.assertEqual("", out)
        return calls

    def test_success_enforces_token_audience_https_host_and_docker_stdin(self):
        code, out, err, calls, fake, opener = self.invoke()
        self.assertEqual(0, code, err)
        self.assertEqual("", out)
        self.assertEqual("", err)
        self.assertEqual([AZ, DOCKER], [x[0] for x in calls])
        request, timeout = fake.requests[0]
        self.assertEqual("https://" + HOST + "/oauth2/exchange", request.full_url)
        self.assertEqual("POST", request.get_method())
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)
        self.assertEqual("application/x-www-form-urlencoded",
                         request.get_header("Content-type"))
        self.assertEqual({
            "grant_type": ["access_token"], "service": [HOST],
            "tenant": [TENANT], "access_token": [AAD_TOKEN],
        }, urllib.parse.parse_qs(request.data.decode()))
        self.assertEqual(1, opener.call_count)
        self.assertTrue(any(isinstance(h, self.module.NoRedirect)
                            for h in opener.call_args.args))
        self.assertIsNone(self.module.NoRedirect().redirect_request(
            None, None, 307, "redirect", {}, "https://attacker.example/"))

    def test_invalid_host_registry_or_tenant_denied_before_any_cli(self):
        for case in ({"registry": "evil"}, {"registry": ""},
                     {"registry": "ACR-unsafe"}, {"host": "attacker.azurecr.io"},
                     {"host": "synthetic.azurecr.io:443"},
                     {"host": "http://synthetic.azurecr.io"},
                     {"host": "synthetic.azurecr.io/other"},
                     {"tenant": ""}, {"tenant": "bad"}, {"tenant": SENTINEL}):
            with self.subTest(case=case):
                self.assertEqual([], self.denied(**case))

    def test_bad_aad_token_and_azure_cli_failure_do_not_open_https(self):
        for case in ({"az_failure": True}, {"aad": ""}, {"aad": "\r\n"},
                     {"aad": SENTINEL + " space"}, {"aad": "x" * 17000}):
            with self.subTest(case=list(case.keys())):
                code, out, err, calls, fake, _ = self.invoke(**case)
                self.assertNotEqual(0, code)
                self.assertEqual("", out)
                self.assertNotIn(SENTINEL, err)
                self.assertEqual(1, len(calls))
                self.assertEqual([], fake.requests)

    def test_rejects_http_error_redirect_invalid_json_and_malformed_refresh(self):
        for case in ({"status": 301}, {"status": 307},
                     {"status": 308}, {"status": 401}, {"status": 500},
                     {"raised": OSError(SENTINEL)}, {"response": b""},
                     {"response": b"null"}, {"response": b"[]"},
                     {"response": b"{}"}, {"response": b"{bad"},
                     {"response": b'{"refresh_token":null}'},
                     {"response": b'{"refresh_token":""}'},
                     {"response": b" " * 100000},
                     {"refresh": SENTINEL + " whitespace"},
                     {"refresh": "x" * 18000}):
            with self.subTest(case=list(case.keys())):
                self.assertEqual(1, len(self.denied(**case)))

    def test_docker_failure_does_not_print_tokens_or_put_them_on_argv(self):
        calls = self.denied(docker_failure=True)
        self.assertEqual(2, len(calls))
        self.assertEqual(ACR_REFRESH, calls[1][1]["input"])
        self.assertNotIn(ACR_REFRESH, repr(calls[1][0]))

    def test_workflow_requires_oauth_after_oidc_guard_before_build(self):
        self.assertIn("scripts/azure/login-acr-oauth.py", WORKFLOW)
        self.assertNotIn("az acr login --name", WORKFLOW)
        self.assertNotIn("docker login --password ", WORKFLOW)
        self.assertLess(WORKFLOW.index("Verify ACR build CLI OIDC session"),
                        WORKFLOW.index("login-acr-oauth.py"))
        self.assertLess(WORKFLOW.index("login-acr-oauth.py"),
                        WORKFLOW.index("docker build"))
        self.assertLess(WORKFLOW.index("login-acr-oauth.py"),
                        WORKFLOW.index("docker push"))
        self.assertLess(WORKFLOW.index("docker push"),
                        WORKFLOW.index("Lock and verify approved ACR tag"))
        self.assertIn('docker logout "$REGISTRY_HOST"', WORKFLOW)
        self.assertIn('--registry-host "$REGISTRY_HOST"', WORKFLOW)


if __name__ == "__main__":
    unittest.main()
