"""RED first: ACR OAuth2 data-plane metadata + tag/manifest lock (#74).

Mocked Entra/Azure CLI and HTTPS only. The official ACR REST response has
registry, imageName, tag/manifest wrappers and changeableAttributes.
"""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest import mock
import unittest
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts" / "azure"
LIBRARY = SCRIPTS / "acr-registry-data-plane.py"
RESOLVER = (SCRIPTS / "resolve-pushed-image-digest.py").read_text()
LOCKER = (SCRIPTS / "lock-approved-image.py").read_text()
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
HOST, REGISTRY = "synthetic.azurecr.io", "synthetic"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SHA = "123456789abc" + "d" * 28
DIGEST = "sha256:" + "a" * 64
WRONG = "sha256:" + "b" * 64
AAD = "eyJ.AAD_FAKETOKEN.SIGN"
REFRESH = "eyJ.ACR_REFRESH_FAKETOKEN.SIGN"
BEARER = "eyJ.ACR_BEARER_FAKETOKEN.SIGN"
SECRET = "private-token-from-acr-error-never-print"
LOCKED = {"writeEnabled": False, "deleteEnabled": False,
          "readEnabled": True, "listEnabled": True}
UNLOCKED = {**LOCKED, "writeEnabled": True}


def tag_object(digest=DIGEST, attr=None):
    return {"registry": HOST, "imageName": "comuni",
            "tag": {"name": SHA, "digest": digest,
                    "changeableAttributes": LOCKED if attr is None else attr}}


def manifest_object(digest=DIGEST, attr=None):
    return {"registry": HOST, "imageName": "comuni",
            "manifest": {"digest": digest,
                         "changeableAttributes": LOCKED if attr is None else attr}}


class Response(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status


class HTTPS:
    def __init__(self, responses=None):
        self.requests = []
        self.responses = list(responses or [])

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if not self.responses:
            raise RuntimeError("unanticipated network request")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        body, status = item
        return Response(json.dumps(body).encode() if not isinstance(body, bytes) else body,
                        status)


def reply(payload, status=200):
    return (payload, status)


class ACRRestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("acr_data_plane", LIBRARY)
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def create(self, *, name=REGISTRY, host=HOST, tenant=TENANT, responses=None):
        network = HTTPS(responses)
        commands = []
        def run(argv, **kwargs):
            commands.append(argv)
            if argv[0] != "az":
                self.fail("unexpected command: " + argv[0])
            self.assertEqual(["az", "account", "get-access-token",
                              "--resource", "https://containerregistry.azure.net",
                              "--query", "accessToken", "--output", "tsv",
                              "--only-show-errors"], argv)
            self.assertTrue(kwargs["capture_output"])
            return SimpleNamespace(returncode=0, stdout=AAD, stderr=SECRET)
        opener = mock.Mock()
        opener.open = network.open
        build = mock.patch.object(self.mod.urllib.request, "build_opener",
                                  return_value=opener)
        az = mock.patch.object(self.mod.subprocess, "run", side_effect=run)
        with build, az:
            client = self.mod.ACRClient(name, host, tenant)
            client.authenticate()
        return client, network, commands, opener, build, az

    def success(self, responses=None):
        responses = responses or [
            reply({"refresh_token": REFRESH}),
            reply({"access_token": BEARER}),
            reply(tag_object()),
            reply(tag_object()),
            reply(tag_object()),
            reply(manifest_object()),
            reply(tag_object()),
            reply(manifest_object()),
        ]
        network = HTTPS(responses)
        commands = []
        def run(argv, **kwargs):
            commands.append(argv)
            if argv[0] != "az":
                self.fail("unexpected invocation")
            self.assertIn("--resource", argv)
            self.assertEqual("https://containerregistry.azure.net",
                             argv[argv.index("--resource") + 1])
            self.assertTrue(kwargs.get("capture_output"))
            return SimpleNamespace(returncode=0, stdout=AAD, stderr=SECRET)
        opener = mock.Mock()
        opener.open = network.open
        with mock.patch.object(self.mod.urllib.request, "build_opener",
                               return_value=opener) as build, \
             mock.patch.object(self.mod.subprocess, "run", side_effect=run):
            client = self.mod.ACRClient(REGISTRY, HOST, TENANT)
            client.authenticate()
            self.assertEqual(DIGEST, client.tag_digest(SHA, expected_digest=DIGEST))
            client.lock(SHA, DIGEST)
            self.assertEqual([], network.responses)
            return network.requests, commands, build

    def test_oauth_scope_and_exact_six_data_plane_endpoints(self):
        requests, commands, build = self.success()
        self.assertEqual(1, len(commands))
        self.assertEqual(8, len(requests))
        self.assertEqual(["POST", "POST", "GET", "GET", "PATCH", "PATCH", "GET", "GET"],
                         [r.get_method() for r, _ in requests])
        expected = [
            "/oauth2/exchange", "/oauth2/token",
            "/acr/v1/comuni/_tags/" + SHA + "?api-version=2021-07-01",
            "/acr/v1/comuni/_tags/" + SHA + "?api-version=2021-07-01",
            "/acr/v1/comuni/_tags/" + SHA + "?api-version=2021-07-01",
            "/acr/v1/comuni/_manifests/" + DIGEST + "?api-version=2021-07-01",
            "/acr/v1/comuni/_tags/" + SHA + "?api-version=2021-07-01",
            "/acr/v1/comuni/_manifests/" + DIGEST + "?api-version=2021-07-01",
        ]
        for index, (request, timeout) in enumerate(requests):
            self.assertEqual("https://" + HOST + expected[index], request.full_url)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 30)
        self.assertEqual({
            "grant_type": ["access_token"], "service": [HOST],
            "tenant": [TENANT], "access_token": [AAD],
        }, urllib.parse.parse_qs(requests[0][0].data.decode()))
        self.assertEqual({
            "grant_type": ["refresh_token"], "service": [HOST],
            "scope": ["repository:comuni:pull,push"], "refresh_token": [REFRESH],
        }, urllib.parse.parse_qs(requests[1][0].data.decode()))
        for request, _ in requests[2:]:
            self.assertEqual("Bearer " + BEARER,
                             request.get_header("Authorization"))
        for request, _ in requests[4:6]:
            self.assertEqual({"writeEnabled": False, "deleteEnabled": False},
                             json.loads(request.data))
        self.assertTrue(any(isinstance(h, self.mod.NoRedirect) for h in
                            build.call_args.args))

    def test_invalid_host_tenant_commit_and_digest_rejected_before_network(self):
        for name, host, tenant in (
            ("evil", HOST, TENANT), (REGISTRY, "evil.azurecr.io", TENANT),
            (REGISTRY, HOST + ":443", TENANT), (REGISTRY, HOST, "invalid-tenant"),
            (REGISTRY, "http://" + HOST, TENANT),
        ):
            with self.subTest(name=name, host=host):
                with self.assertRaises(ValueError):
                    self.mod.ACRClient(name, host, tenant)
        # A client is valid but only exact, lowercase SHA and OCI digest
        # may construct metadata paths.
        for sha in ("bad", SHA.upper(), "../" + SHA):
            with self.subTest(sha=sha):
                with self.assertRaises(ValueError):
                    self.mod.tag_path(sha)
        for digest in (WRONG.upper(), "sha256:short", "../" + DIGEST):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    self.mod.manifest_path(digest)

    def test_response_wrapper_and_tag_digest_must_be_consistent(self):
        for bad in (
            {"registry": HOST, "tag": {"name": SHA, "digest": DIGEST}},
            tag_object(WRONG), tag_object(attr={"writeEnabled": False}),
            {**tag_object(), "registry": "attacker.azurecr.io"},
            {**tag_object(), "imageName": "other"},
            {**tag_object(), "tag": {**tag_object()["tag"], "name": "other"}},
            None, [], SECRET,
        ):
            with self.subTest(bad=str(type(bad))):
                network = HTTPS([reply({"refresh_token": REFRESH}),
                                 reply({"access_token": BEARER}), reply(bad)])
                opener = mock.Mock()
                opener.open = network.open
                with mock.patch.object(self.mod.urllib.request, "build_opener",
                                       return_value=opener), \
                     mock.patch.object(self.mod.subprocess, "run",
                                       return_value=SimpleNamespace(
                                           returncode=0, stdout=AAD, stderr=SECRET)):
                    client = self.mod.ACRClient(REGISTRY, HOST, TENANT)
                    client.authenticate()
                    with self.assertRaises(Exception):
                        client.tag_digest(SHA, expected_digest=DIGEST)

    def test_tag_swap_during_patch_blocks_manifest_mutation(self):
        # The PATCH tag response already reveals a changed digest; do not
        # proceed to PATCH manifest even if the first preflight GET matched.
        network = HTTPS([
            reply({"refresh_token": REFRESH}),
            reply({"access_token": BEARER}),
            reply(tag_object()),
            reply(tag_object(WRONG)),
        ])
        opener = mock.Mock()
        opener.open = network.open
        with mock.patch.object(self.mod.urllib.request, "build_opener",
                               return_value=opener), \
             mock.patch.object(self.mod.subprocess, "run",
                               return_value=SimpleNamespace(
                                   returncode=0, stdout=AAD, stderr=SECRET)):
            client = self.mod.ACRClient(REGISTRY, HOST, TENANT)
            client.authenticate()
            with self.assertRaises(Exception):
                client.lock(SHA, DIGEST)
        self.assertEqual(["POST", "POST", "GET", "PATCH"],
                         [r.get_method() for r, _ in network.requests])
        self.assertEqual([], network.responses)

    def test_bad_http_status_and_duplicate_json_keys_fail_closed(self):
        for body, status in (
            ({"refresh_token": REFRESH}, 301),
            ({"refresh_token": REFRESH}, 307),
            ({"refresh_token": REFRESH}, 401),
            ({"refresh_token": REFRESH}, 500),
            (b'{"refresh_token":"eyJ.valid.sig","refresh_token":"eyJ.evil.sig"}', 200),
            (b"[]" , 200), (b"null", 200),
            (b" " * 66000, 200),
        ):
            with self.subTest(status=status, payload_type=type(body).__name__):
                fake = HTTPS([reply(body, status)])
                opener = mock.Mock()
                opener.open = fake.open
                with mock.patch.object(self.mod.urllib.request, "build_opener",
                                       return_value=opener), \
                     mock.patch.object(self.mod.subprocess, "run",
                                       return_value=SimpleNamespace(
                                           returncode=0, stdout=AAD, stderr=SECRET)):
                    client = self.mod.ACRClient(REGISTRY, HOST, TENANT)
                    with self.assertRaises(Exception):
                        client.authenticate()
                self.assertEqual(1, len(fake.requests))

    def test_workflow_and_scripts_must_never_use_control_plane_cli(self):
        self.assertNotIn("az acr login", WORKFLOW)
        for content in (RESOLVER, LOCKER):
            self.assertNotIn('"acr", "manifest"', content)
            self.assertNotIn('"acr", "repository"', content)
            self.assertIn("ACRClient", content)
            self.assertIn("--tenant-id", content)
        self.assertIn('--tenant-id "$ARM_TENANT_ID"', WORKFLOW)
        self.assertLess(WORKFLOW.index("resolve-pushed-image-digest.py"),
                        WORKFLOW.index("lock-approved-image.py"))
        self.assertLess(WORKFLOW.index("lock-approved-image.py"),
                        WORKFLOW.index("trivy image"))


if __name__ == "__main__":
    unittest.main()
