"""RED-first, fully offline adversarial contract for Superadmin candidate smoke (#40).

No Azure, provider, database, tokens or live HTTP calls; the fake opener
models backend-authorized responses to a labelled ACA revision.
"""
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/azure/smoke-candidate-platform.py"
APP = "comuni-itn-001-app"
LABEL = "r123456789abc"
DOMAIN = "lovely-12345.westeurope.azurecontainerapps.io"
URL = f"https://{APP}---{LABEL}.{DOMAIN}"
A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
C = "cccccccc-cccc-cccc-cccc-cccccccccccc"
TOKEN_A = "tenant-alpha-test-access-token"
TOKEN_B = "tenant-beta-test-access-token"
TOKEN_PLATFORM = "platform-operator-test-access-token"


_LOADED_SMOKE = None

def module():
    global _LOADED_SMOKE
    if _LOADED_SMOKE is not None:
        return _LOADED_SMOKE
    if not SCRIPT.is_file():
        raise AssertionError("RED: missing dedicated platform candidate smoke script")
    spec = importlib.util.spec_from_file_location("platform_candidate_smoke", SCRIPT)
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    spec.loader.exec_module(result)
    _LOADED_SMOKE = result
    return result


class FakeResponse:
    def __init__(self, status, payload, url):
        self.status = status
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.url = url
        self.headers = {"Content-Type": "application/json"}

    def read(self, n=-1):
        return self.payload if n == -1 else self.payload[:n]

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def item(id, **changes):
    return dict(id=id, name="Comune sintetico test", isSuspended=False,
                protocolEnabled=True, **changes)


class FakeOpener:
    def __init__(self, *, platform_role="Superadmin", deny_tenants=True,
                 extra_field=False, bad_cursor=False, wrong_order=False,
                 leak_field=False, redirect=False, bad_json=False,
                 missing_tenant=False, always_next=False,
                 deny_platform=False, http_status=200):
        self.requests = []
        self.platform_role = platform_role
        self.deny_tenants = deny_tenants
        self.extra_field = extra_field
        self.bad_cursor = bad_cursor
        self.wrong_order = wrong_order
        self.leak_field = leak_field
        self.redirect = redirect
        self.bad_json = bad_json
        self.missing_tenant = missing_tenant
        self.always_next = always_next
        self.deny_platform = deny_platform
        self.http_status = http_status

    def open(self, req, timeout=8):
        assert timeout <= 10
        assert req.get_method() == "GET"
        assert urlsplit(req.full_url).scheme == "https"
        assert urlsplit(req.full_url).hostname == urlsplit(URL).hostname
        assert req.get_header("X-Organization-Id") is None
        assert req.get_header("Authorization") != "Bearer "
        if urlsplit(req.full_url).path == "/health/ready":
            raise AssertionError("health should not have a bearer header")
        self.requests.append(req)
        auth = req.get_header("Authorization")
        path = urlsplit(req.full_url).path
        if self.redirect:
            return FakeResponse(302, {}, "https://redirect-attack.example.test/")
        if path == "/api/v1/platform/session":
            if not auth:
                return FakeResponse(401, {}, req.full_url)
            if auth != "Bearer " + TOKEN_PLATFORM:
                return FakeResponse(200 if not self.deny_tenants else 403,
                                    {"role": self.platform_role}, req.full_url)
            return FakeResponse(403 if self.deny_platform else self.http_status,
                                {"role": self.platform_role}, req.full_url)
        if path == "/api/v1/context":
            return FakeResponse(403 if auth == "Bearer " + TOKEN_PLATFORM else 200,
                                {}, req.full_url)
        if path == "/api/v1/platform/organizations":
            if not auth:
                return FakeResponse(401, {}, req.full_url)
            if auth != "Bearer " + TOKEN_PLATFORM:
                return FakeResponse(403 if self.deny_tenants else 200,
                                    {"organizations": [], "nextCursor": None}, req.full_url)
            if self.deny_platform:
                return FakeResponse(403, {}, req.full_url)
            after = parse_qs(urlsplit(req.full_url).query).get("after", [None])[0]
            rows = ([item(B), item(A)] if self.wrong_order else [item(A), item(B)])
            if self.missing_tenant:
                rows = [item(A), item(C)]
            else:
                rows.append(item(C))
            if after is None:
                page, next_cursor = rows[:2], rows[1]["id"]
            else:
                page, next_cursor = rows[2:], None
            if self.always_next:
                next_cursor = A
            if self.bad_cursor:
                next_cursor = "untrusted-cursor"
            if self.leak_field and page:
                page[0]["subject"] = "personal-identifier-should-not-be-visible"
            result = {"organizations": page, "nextCursor": next_cursor}
            if self.extra_field:
                result["operators"] = ["secret"]
            if self.bad_json:
                return FakeResponse(200, b'{"organizations":[], "organizations":[]}', req.full_url)
            return FakeResponse(self.http_status, result, req.full_url)
        raise AssertionError(f"unexpected endpoint {path}")


class Opener(FakeOpener):
    def open(self, req, timeout=8):
        # The real smoke calls /health/ready with no Authorization.
        self.requests.append(req)
        if urlsplit(req.full_url).path == "/health/ready":
            return FakeResponse(200, {"status": "ready"}, req.full_url)
        self.requests.pop()
        return super().open(req, timeout)


def run(opener=None, **kwargs):
    values = {
        "url": URL, "app": APP, "label": LABEL,
        "environment_domain": DOMAIN, "org_a": A, "org_b": B,
        "token_a": TOKEN_A, "token_b": TOKEN_B,
        "platform_token": TOKEN_PLATFORM,
        "opener": opener or Opener()
    }
    values.update(kwargs)
    return module().run_smoke(**values)


class PlatformCandidateTests(unittest.TestCase):
    def test_three_distinct_valid_oidc_tokens_and_minimal_paginated_inventory(self):
        opener = Opener()
        run(opener)
        reqs = opener.requests
        urls = [x.full_url for x in reqs]
        self.assertTrue(all(t not in u for u in urls
                            for t in (TOKEN_A, TOKEN_B, TOKEN_PLATFORM)))
        self.assertTrue(all(x.get_method() == "GET" for x in reqs))
        self.assertEqual(2, sum(
            1 for req in reqs
            if "/api/v1/platform/organizations?limit=2" in req.full_url
            and req.get_header("Authorization") == "Bearer " + TOKEN_PLATFORM))
        self.assertTrue(any("after=" + B in u for u in urls))
        self.assertTrue(all(x.get_header("Authorization") is None
                            for x in reqs if urlsplit(x.full_url).path == "/health/ready"))

    def test_requires_all_three_tokens_distinct_and_strict_candidate_origin(self):
        smoke = module()
        for kw in [
            {"token_a": TOKEN_PLATFORM},
            {"token_b": TOKEN_A},
            {"platform_token": TOKEN_B},
            {"platform_token": ""},
            {"platform_token": "not enough"},
            {"org_b": A},
            {"url": "https://evil.example.test/"},
            {"url": URL + "/api/v1/context"},
            {"url": URL + "?authorization=xxx"},
            {"url": URL.replace("https://", "http://")},
            {"environment_domain": "other.westeurope.azurecontainerapps.io"},
        ]:
            with self.subTest(kw=list(kw)), self.assertRaises(smoke.SmokeRejected):
                run(**kw)

    def test_denies_tenant_platform_escalation_and_platform_as_municipal(self):
        smoke = module()
        for o in [Opener(deny_tenants=False), Opener(deny_platform=True),
                  Opener(platform_role="Admin")]:
            with self.assertRaises(smoke.SmokeRejected):
                run(o)

    def test_rejects_unauthorized_or_unavailable_inventory(self):
        smoke = module()
        for o in [Opener(http_status=503), Opener(http_status=401),
                  Opener(http_status=403)]:
            with self.assertRaises(smoke.SmokeRejected):
                run(o)

    def test_rejects_extra_fields_pii_reused_cursors_and_missing_fixtures(self):
        smoke = module()
        for o in [Opener(extra_field=True), Opener(leak_field=True),
                  Opener(bad_cursor=True), Opener(wrong_order=True),
                  Opener(missing_tenant=True), Opener(always_next=True),
                  Opener(bad_json=True)]:
            with self.subTest(o=o.__dict__.keys()), self.assertRaises(smoke.SmokeRejected):
                run(o)

    def test_redirect_never_forwards_a_bearer_token(self):
        smoke = module()
        with self.assertRaises(smoke.SmokeRejected):
            run(Opener(redirect=True))

    def test_errors_do_not_print_tokens_or_organization_metadata(self):
        smoke = module()
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf), mock.patch("sys.stderr", buf):
            with self.assertRaises(smoke.SmokeRejected):
                run(Opener(leak_field=True))
        for value in (TOKEN_A, TOKEN_B, TOKEN_PLATFORM, "personal-identifier",
                      A, B, C):
            self.assertNotIn(value, buf.getvalue())

    def test_script_has_manual_only_cli_and_never_executes_write_ops(self):
        self.assertTrue(SCRIPT.exists())
        text = SCRIPT.read_text()
        self.assertIn("COMUNI_SMOKE_OIDC_TOKEN_PLATFORM", text)
        self.assertIn("COMUNI_SMOKE_OIDC_TOKEN_A", text)
        self.assertIn("COMUNI_SMOKE_OIDC_TOKEN_B", text)
        self.assertIn("urllib.request.ProxyHandler({})", text)
        self.assertNotIn('method="POST"', text)
        self.assertNotIn('method="PUT"', text)
        self.assertNotIn('method="DELETE"', text)


if __name__ == "__main__":
    unittest.main()
