"""Offline TDD tests of an OIDC/RLS canary smoke checker with two synthetic tenants."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/azure/smoke-candidate-oidc.py"
APP = "comuni-itn-001-app"
LABEL = "r123456789abc"
HOST = f"{APP}---{LABEL}.lovely-12345.westeurope.azurecontainerapps.io"
URL = f"https://{HOST}"
A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
TOKEN_A = "oidc-token-for-tenant-a"
TOKEN_B = "oidc-token-for-tenant-b"
MARK_A = "comuni-test-fixture-a-2026"
MARK_B = "comuni-test-fixture-b-2026"

spec = importlib.util.spec_from_file_location("candidate_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = smoke
spec.loader.exec_module(smoke)


class FakeResponse:
    def __init__(self, status, payload, url):
        self.status = status
        self.payload = json.dumps(payload).encode("utf-8") if not isinstance(payload, bytes) else payload
        self.url = url
        self.headers = {"Content-Type": "application/json", "Cache-Control": "no-store"}

    def read(self, amount=-1):
        return self.payload if amount < 0 else self.payload[:amount]

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, *, leak=False, bad_tenant=False, http_fail=False,
                 redirect=False, marker_missing=False, error_json=False):
        self.requests = []
        self.leak = leak
        self.bad_tenant = bad_tenant
        self.http_fail = http_fail
        self.redirect = redirect
        self.marker_missing = marker_missing
        self.error_json = error_json

    def open(self, request, timeout):
        self.requests.append(request)
        self.ensure_safe(request)
        path = urlsplit(request.full_url).path
        auth = request.get_header("Authorization")
        if self.redirect:
            return FakeResponse(302, {"status": "redirect"}, "https://evil.example.com/")
        if self.http_fail:
            return FakeResponse(503, {"status": "unavailable"}, request.full_url)
        if path == "/health/ready":
            return FakeResponse(200, {"status": "ready"}, request.full_url)
        if path == "/api/v1/context":
            if not auth:
                return FakeResponse(401, {}, request.full_url)
            tenant = A if auth == "Bearer " + TOKEN_A else B
            if self.bad_tenant and auth.endswith(TOKEN_B):
                tenant = A
            return FakeResponse(200, {"organizationId": tenant, "organizationName": "Comune Test",
                                       "roles": ["Reader"], "modules": ["protocol"]}, request.full_url)
        if path == "/api/v1/protocol/records":
            marker = MARK_A if auth.endswith(TOKEN_A) else MARK_B
            records = [] if self.marker_missing else [{"id": A, "subject": marker, "registeredAt": "2026-01-01T00:00:00Z"}]
            if self.leak and auth.endswith(TOKEN_A):
                records.append({"id": B, "subject": MARK_B, "registeredAt": "2026-01-01T00:00:00Z"})
            if self.error_json:
                return FakeResponse(200, b"{broken", request.full_url)
            return FakeResponse(200, records, request.full_url)
        raise AssertionError("Unexpected endpoint")

    def ensure_safe(self, request):
        assert request.get_method() == "GET"
        assert urlsplit(request.full_url).scheme == "https"
        assert urlsplit(request.full_url).hostname == HOST
        assert request.get_header("X-Organization-Id") is None


def run(opener=None, **kw):
    params = {
        "url": URL, "app": APP, "label": LABEL,
        "environment_domain": "lovely-12345.westeurope.azurecontainerapps.io",
        "org_a": A, "org_b": B,
        "marker_a": MARK_A, "marker_b": MARK_B,
        "token_a": TOKEN_A, "token_b": TOKEN_B,
        "opener": opener or FakeOpener(),
    }
    params.update(kw)
    return smoke.run_smoke(**params)


class CandidateSmokeTests(unittest.TestCase):
    def test_candidate_url_is_https_exact_label_without_redirect_or_external_host(self):
        self.assertEqual(URL, smoke.validate_candidate_url(URL, APP, LABEL, "lovely-12345.westeurope.azurecontainerapps.io"))
        for url in [
            "http://" + HOST,
            "https://evil.example.com/",
            "https://" + APP + ".lovely-12345.westeurope.azurecontainerapps.io",
            "https://" + APP + "---wrong.lovely-12345.westeurope.azurecontainerapps.io",
            URL + "/api/v1/context",
            URL + "?token=test",
            URL + "#fragment",
            "https://name:pass@" + HOST,
            "https://" + HOST + ":8443",
        ]:
            with self.assertRaises(smoke.SmokeRejected):
                smoke.validate_candidate_url(url, APP, LABEL, "lovely-12345.westeurope.azurecontainerapps.io")

    def test_rejects_an_unapproved_azure_environment_domain(self):
        with self.assertRaises(smoke.SmokeRejected):
            smoke.validate_candidate_url(
                URL, APP, LABEL, "attacker-55555.westeurope.azurecontainerapps.io"
            )
        with self.assertRaises(smoke.SmokeRejected):
            run(environment_domain="attacker-55555.westeurope.azurecontainerapps.io")

    def test_two_tenant_read_only_smoke_succeeds_and_never_uses_token_in_url(self):
        opener = FakeOpener()
        run(opener)
        self.assertEqual(6, len(opener.requests))
        urls = [req.full_url for req in opener.requests]
        self.assertTrue(all(TOKEN_A not in u and TOKEN_B not in u for u in urls))
        self.assertTrue(all(req.get_method() == "GET" for req in opener.requests))
        self.assertTrue(any(not req.get_header("Authorization") for req in opener.requests))
        self.assertTrue(all(not req.get_header("Authorization") for req in opener.requests[:2]))

    def test_wrong_tenant_context_and_cross_tenant_record_are_rejected(self):
        for opener in [FakeOpener(bad_tenant=True), FakeOpener(leak=True),
                       FakeOpener(marker_missing=True)]:
            with self.assertRaises(smoke.SmokeRejected):
                run(opener)

    def test_failure_on_bad_status_malformed_json_or_redirect(self):
        for opener in [FakeOpener(http_fail=True), FakeOpener(error_json=True),
                       FakeOpener(redirect=True)]:
            with self.assertRaises(smoke.SmokeRejected):
                run(opener)

    def test_token_reuse_or_same_tenant_is_rejected(self):
        with self.assertRaises(smoke.SmokeRejected):
            run(token_b=TOKEN_A)
        with self.assertRaises(smoke.SmokeRejected):
            run(org_b=A)

    def test_error_paths_do_not_print_tokens_or_synthetic_subjects(self):
        opener = FakeOpener(leak=True)
        stream = io.StringIO()
        with mock.patch("sys.stdout", stream), mock.patch("sys.stderr", stream):
            with self.assertRaises(smoke.SmokeRejected):
                run(opener)
        leaked = stream.getvalue()
        for secret in (TOKEN_A, TOKEN_B, MARK_A, MARK_B):
            self.assertNotIn(secret, leaked)


if __name__ == "__main__":
    unittest.main()
