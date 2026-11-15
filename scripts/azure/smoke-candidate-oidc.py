#!/usr/bin/env python3
"""Read-only two-tenant OIDC + RLS smoke test for a 0%-traffic ACA revision label.

Run manually from an approved operator runner with two freshly issued real OIDC
access tokens for disposable synthetic tenants, never on a production account.
This script never creates documents, issues tokens, writes to PostgreSQL, changes
revision traffic, or prints token/record data. A separate Azure metadata gate
must verify the label targets the expected candidate before execution.
"""
import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

HOST_SEGMENT = re.compile(r"[a-z][a-z0-9-]{2,60}[a-z0-9]\Z")
REVISION = re.compile(r"r[0-9a-f]{12}\Z")
MARKER = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
MAX_RESPONSE = 512 * 1024
TIMEOUT = 8


class SmokeRejected(Exception):
    """Deliberately generic errors; no JWT, URL query, or data in messages."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # Never forward Authorization to a 3xx destination.
        return None


def validate_candidate_url(url, app, label, environment_domain):
    if not isinstance(app, str) or not HOST_SEGMENT.fullmatch(app) or "--" in app:
        raise SmokeRejected("Invalid Container App name")
    if not isinstance(label, str) or not REVISION.fullmatch(label):
        raise SmokeRejected("Invalid immutable revision label")
    if (
        not isinstance(environment_domain, str)
        or not re.fullmatch(
            r"[a-z0-9-]+(?:\.[a-z0-9-]+){1,}\.azurecontainerapps\.io\Z",
            environment_domain,
        )
    ):
        raise SmokeRejected("Invalid approved Azure environment domain")
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if parsed.port is not None:
            raise SmokeRejected("Candidate URL must use default HTTPS port")
    except (ValueError, AttributeError, TypeError):
        raise SmokeRejected("Invalid candidate URL")
    if not (
        parsed.scheme == "https" and parsed.netloc == host and host
        and host == app + "---" + label + "." + environment_domain
        and len(host.split(".")) >= 4
        and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
        and parsed.username is None and parsed.password is None
    ):
        raise SmokeRejected("Candidate URL is not an approved Azure revision label HTTPS origin")
    return "https://" + host


def _json_unique(pairs):
    values = {}
    for k, v in pairs:
        if k in values:
            raise ValueError("duplicate JSON property")
        values[k] = v
    return values


def _get(origin, path, token, opener):
    headers = {"Accept": "application/json", "Cache-Control": "no-store"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    url = origin + path
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=TIMEOUT) as response:
            status = response.status
            if response.geturl() != url:
                raise SmokeRejected("Unexpected HTTP redirect")
            if status == 401:
                return status, None
            if status != 200:
                raise SmokeRejected("Candidate API returned unexpected HTTP status")
            content_type = response.headers.get("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                raise SmokeRejected("Candidate API returned unexpected content type")
            payload = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 401 and exc.url == url:
            return 401, None
        raise SmokeRejected("Candidate API returned unexpected HTTP error")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise SmokeRejected("Candidate API transport or TLS verification failed")
    if len(payload) > MAX_RESPONSE:
        raise SmokeRejected("Candidate API response exceeds safe size limit")
    try:
        result = json.loads(payload.decode("utf-8"), object_pairs_hook=_json_unique)
    except (ValueError, UnicodeDecodeError, TypeError):
        raise SmokeRejected("Candidate API returned invalid JSON")
    return status, result


def run_smoke(*, url, app, label, environment_domain, org_a, org_b, marker_a, marker_b,
              token_a, token_b, opener):
    origin = validate_candidate_url(url, app, label, environment_domain)
    try:
        expected_a = str(uuid.UUID(org_a))
        expected_b = str(uuid.UUID(org_b))
    except (ValueError, AttributeError, TypeError):
        raise SmokeRejected("Expected tenant IDs must be UUIDs")
    if expected_a == expected_b:
        raise SmokeRejected("Two different synthetic tenants are required")
    if not all(
        isinstance(marker, str) and MARKER.fullmatch(marker)
        for marker in (marker_a, marker_b)
    ) or marker_a == marker_b:
        raise SmokeRejected("Two distinct synthetic fixture markers are required")
    if not all(isinstance(token, str) and 12 <= len(token) <= 16384
               and token.isascii() and not any(ch.isspace() for ch in token)
               for token in (token_a, token_b)) or token_a == token_b:
        raise SmokeRejected("Two distinct short-lived OIDC access tokens are required")

    status, health = _get(origin, "/health/ready", None, opener)
    if status != 200 or not isinstance(health, dict) or health.get("status") != "ready":
        raise SmokeRejected("Candidate readiness failed")
    status, _ = _get(origin, "/api/v1/context", None, opener)
    if status != 401:
        raise SmokeRejected("Candidate incorrectly allows anonymous tenant context")

    for token, tenant, own_marker, other_marker in (
        (token_a, expected_a, marker_a, marker_b),
        (token_b, expected_b, marker_b, marker_a),
    ):
        status, context = _get(origin, "/api/v1/context", token, opener)
        if status != 200 or not isinstance(context, dict):
            raise SmokeRejected("Authenticated tenant context is unavailable")
        try:
            actual_tenant = str(uuid.UUID(context["organizationId"]))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise SmokeRejected("Invalid authenticated tenant identifier")
        roles = context.get("roles")
        modules = context.get("modules")
        if (
            actual_tenant != tenant
            or not isinstance(context.get("organizationName"), str)
            or not context["organizationName"].strip()
            or not isinstance(roles, list)
            or not all(isinstance(role, str) for role in roles)
            or not set(roles).intersection({"Admin", "Officer", "Reader"})
            or not isinstance(modules, list)
            or not all(isinstance(module, str) for module in modules)
            or "protocol" not in modules
        ):
            raise SmokeRejected("Authenticated tenant identity, membership or module mismatch")
        status, records = _get(origin, "/api/v1/protocol/records", token, opener)
        if status != 200 or not isinstance(records, list) or not all(
            isinstance(row, dict) and isinstance(row.get("subject"), str)
            for row in records
        ):
            raise SmokeRejected("Tenant protocol metadata is unavailable")
        subjects = {row["subject"] for row in records}
        if own_marker not in subjects or other_marker in subjects:
            raise SmokeRejected("Tenant-specific synthetic fixture missing or cross-tenant data visible")
    # Deliberately return no personally identifying data or HTTP responses.
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Read-only OIDC/RLS canary test. Provide real short-lived tokens via environment."
    )
    parser.add_argument("--candidate-url", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--revision-label", required=True)
    parser.add_argument(
        "--environment-domain", required=True,
        help="Approved Azure Container Apps environment default domain, not a URL"
    )
    parser.add_argument("--org-a", required=True)
    parser.add_argument("--org-b", required=True)
    parser.add_argument("--marker-a", required=True)
    parser.add_argument("--marker-b", required=True)
    args = parser.parse_args()
    try:
        token_a = os.environ.get("COMUNI_SMOKE_OIDC_TOKEN_A", "")
        token_b = os.environ.get("COMUNI_SMOKE_OIDC_TOKEN_B", "")
        # Do not honor HTTP_PROXY, HTTPS_PROXY or redirects when forwarding JWTs.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        run_smoke(
            url=args.candidate_url, app=args.app, label=args.revision_label,
            environment_domain=args.environment_domain,
            org_a=args.org_a, org_b=args.org_b,
            marker_a=args.marker_a, marker_b=args.marker_b,
            token_a=token_a, token_b=token_b, opener=opener,
        )
    except SmokeRejected:
        print("Candidate smoke FAILED. Check operator-approved URL, test fixture and auth.", file=sys.stderr)
        return 1
    print("Candidate smoke OK: OIDC tenant A/B, read-only RLS isolation and readiness verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
