#!/usr/bin/env python3
"""Manual, read-only platform-inventory OIDC smoke against a *labelled* ACA candidate.

This is NOT a deployment workflow, an OIDC issuer, or a provider token validator.
Run after independent ACA metadata, IdP/MFA, SQL role and KV approvals using
three short-lived delegated API access tokens: two synthetic municipal users and
one active, tenantless platform operator. Never supply real municipality data.

All GET requests use the approved HTTPS origin and system CA store, without
proxies or redirects. No bodies, token claims, names or UUIDs are printed.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

# Reuse the existing, reviewed candidate hostname/label validator and
# no-redirect HTTPS behavior from the two-tenant OIDC smoke (ADR 0019).
spec = importlib.util.spec_from_file_location(
    "comuni_candidate_oidc_shared", Path(__file__).with_name("smoke-candidate-oidc.py"))
shared = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = shared
spec.loader.exec_module(shared)
SmokeRejected = shared.SmokeRejected
PAGE_LIMIT = 2
MAX_PAGES = 20
UUID_D = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def _canonical_uuid(value):
    if not isinstance(value, str) or not UUID_D.fullmatch(value):
        raise SmokeRejected("Invalid synthetic or inventory organization UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError):
        raise SmokeRejected("Invalid synthetic or inventory organization UUID")
    if parsed.int == 0 or str(parsed) != value:
        raise SmokeRejected("Non-canonical or zero organization UUID")
    return value


def _check_token(value):
    if not (
        isinstance(value, str) and 12 <= len(value) <= 16384
        and value.isascii() and not any(ch.isspace() for ch in value)
    ):
        raise SmokeRejected("Invalid or absent short-lived delegated OIDC token")


def _request(origin, path, token, opener):
    if not path.startswith("/api/v1/") and path != "/health/ready":
        raise SmokeRejected("Unsupported smoke API path")
    if "\x00" in path or "#" in path or "://" in path:
        raise SmokeRejected("Invalid smoke API path")

    url = origin + path
    headers = {"Accept": "application/json", "Cache-Control": "no-store"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, method="GET", headers=headers)
    try:
        with opener.open(request, timeout=shared.TIMEOUT) as response:
            if response.geturl() != url:
                raise SmokeRejected("Candidate returned a redirect")
            status = response.status
            if status in (401, 403):
                return status, None
            if status != 200:
                raise SmokeRejected("Candidate returned unexpected HTTP status")
            content_type = response.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                raise SmokeRejected("Candidate returned invalid content type")
            payload = response.read(shared.MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403) and exc.url == url:
            return exc.code, None
        raise SmokeRejected("Candidate denied the smoke request unexpectedly")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise SmokeRejected("Candidate HTTPS transport failed")

    if len(payload) > shared.MAX_RESPONSE:
        raise SmokeRejected("Candidate response exceeded maximum safe size")
    try:
        parsed = json.loads(payload.decode("utf-8"), object_pairs_hook=shared._json_unique)
    except (ValueError, UnicodeDecodeError, TypeError):
        raise SmokeRejected("Candidate returned malformed or duplicate JSON")
    return status, parsed


def _require_status(origin, path, token, expected, opener):
    status, value = _request(origin, path, token, opener)
    if status != expected:
        raise SmokeRejected("Candidate authentication boundary failed")
    return value


def _validate_row(row):
    if not isinstance(row, dict) or set(row) != {
        "id", "name", "isSuspended", "protocolEnabled"
    }:
        raise SmokeRejected("Platform inventory exposed unexpected fields")
    identity = _canonical_uuid(row["id"])
    name = row["name"]
    if not (
        isinstance(name, str) and 1 <= len(name) <= 200
        and name.strip() and all(ord(character) >= 32 for character in name)
    ):
        raise SmokeRejected("Platform inventory contains invalid municipality name")
    if type(row["isSuspended"]) is not bool or type(row["protocolEnabled"]) is not bool:
        raise SmokeRejected("Platform inventory flags are invalid")
    # Only the ID survives validation. Never retain/print organization names.
    return identity


def run_smoke(*, url, app, label, environment_domain, org_a, org_b,
              token_a, token_b, platform_token, opener):
    origin = shared.validate_candidate_url(url, app, label, environment_domain)
    org_a = _canonical_uuid(org_a)
    org_b = _canonical_uuid(org_b)
    if org_a == org_b:
        raise SmokeRejected("Two different synthetic municipalities are required")
    for token in (token_a, token_b, platform_token):
        _check_token(token)
    if len({token_a, token_b, platform_token}) != 3:
        raise SmokeRejected("Three independent short-lived OIDC tokens are required")

    health = _require_status(origin, "/health/ready", None, 200, opener)
    if not isinstance(health, dict) or health.get("status") != "ready":
        raise SmokeRejected("Candidate readiness not verified")

    # Every HTTP request (even the denied ones) goes to EXACTLY the trusted
    # labelled candidate; no token is ever sent in a path or query string.
    _require_status(origin, "/api/v1/platform/session", None, 401, opener)
    _require_status(origin, "/api/v1/platform/session", token_a, 403, opener)
    _require_status(origin, "/api/v1/platform/session", token_b, 403, opener)
    platform_session = _require_status(
        origin, "/api/v1/platform/session", platform_token, 200, opener)
    if not isinstance(platform_session, dict) or platform_session != {"role": "Superadmin"}:
        raise SmokeRejected("Platform session contract mismatch")

    # A tenantless operator must never gain a municipal context or tenant role.
    _require_status(origin, "/api/v1/context", platform_token, 403, opener)

    inventory_root = "/api/v1/platform/organizations"
    _require_status(origin, inventory_root + "?limit=2", None, 401, opener)
    _require_status(origin, inventory_root + "?limit=2", token_a, 403, opener)
    _require_status(origin, inventory_root + "?limit=2", token_b, 403, opener)

    previous = None
    visited = set()
    after = None
    for _ in range(MAX_PAGES):
        path = inventory_root + "?limit=2"
        if after is not None:
            path += "&after=" + urllib.parse.quote(after, safe="")
        response = _require_status(origin, path, platform_token, 200, opener)
        if not isinstance(response, dict) or set(response) != {"organizations", "nextCursor"}:
            raise SmokeRejected("Platform inventory response has unexpected fields")
        records = response["organizations"]
        next_cursor = response["nextCursor"]
        if not isinstance(records, list) or not (1 <= len(records) <= PAGE_LIMIT):
            raise SmokeRejected("Platform inventory page length is invalid")

        for row in records:
            identity = _validate_row(row)
            if (previous is not None and identity <= previous) or identity in visited:
                raise SmokeRejected("Platform inventory cursor or ordering is invalid")
            previous = identity
            visited.add(identity)

        if next_cursor is None:
            if not {org_a, org_b}.issubset(visited):
                raise SmokeRejected("Two synthetic municipalities missing from inventory")
            return None

        next_cursor = _canonical_uuid(next_cursor)
        if len(records) != PAGE_LIMIT or next_cursor != previous or next_cursor == after:
            raise SmokeRejected("Platform inventory next cursor is inconsistent")
        after = next_cursor

    raise SmokeRejected("Inventory exceeded the approved bounded smoke pagination limit")


def main():
    parser = argparse.ArgumentParser(
        description="Manual OIDC platform-inventory smoke for an approved 0%-traffic ACA candidate")
    parser.add_argument("--candidate-url", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--revision-label", required=True)
    parser.add_argument("--environment-domain", required=True)
    parser.add_argument("--org-a", required=True, help="First synthetic municipality UUID")
    parser.add_argument("--org-b", required=True, help="Second synthetic municipality UUID")
    args = parser.parse_args()

    try:
        tokens = (
            os.environ.get("COMUNI_SMOKE_OIDC_TOKEN_A", ""),
            os.environ.get("COMUNI_SMOKE_OIDC_TOKEN_B", ""),
            os.environ.get("COMUNI_SMOKE_OIDC_TOKEN_PLATFORM", ""),
        )
        # Ignore HTTP_PROXY / HTTPS_PROXY and do not follow redirects with JWT.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            shared.NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        run_smoke(
            url=args.candidate_url, app=args.app, label=args.revision_label,
            environment_domain=args.environment_domain,
            org_a=args.org_a, org_b=args.org_b,
            token_a=tokens[0], token_b=tokens[1], platform_token=tokens[2],
            opener=opener,
        )
    except SmokeRejected:
        print("Platform candidate smoke FAILED. Check approved label, synthetic fixtures and identities.",
              file=sys.stderr)
        return 1
    print("Platform candidate smoke OK: OIDC denies, paginated minimal inventory and tenant boundaries.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
