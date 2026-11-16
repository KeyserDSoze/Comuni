#!/usr/bin/env python3
"""Allowlisted ACR OAuth2 data-plane client for OCI metadata and locks (#74).

No ARM registry lookup, privileged az acr command, or registry-wide write
scope. Secrets are handled only in memory. No HTTP/CLI diagnostics are logged.
"""
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

REGISTRY_NAME = re.compile(r"[a-z0-9]{5,50}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TENANT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)
TOKEN = re.compile(r"[A-Za-z0-9._~-]{16,16000}\Z")
API_VERSION = "2021-07-01"
SCOPE = "repository:comuni:pull,push"
MAX_BODY = 65536
TIMEOUT = 20


class ACRRejected(ValueError):
    """Only static errors, never HTTP request/response or token content."""


def require(ok, message):
    if not ok:
        raise ACRRejected(message)


def tag_path(sha):
    require(isinstance(sha, str) and bool(COMMIT.fullmatch(sha)),
            "invalid source commit for ACR tag metadata")
    return "/acr/v1/comuni/_tags/" + sha + "?api-version=" + API_VERSION


def manifest_path(digest):
    require(isinstance(digest, str) and bool(DIGEST.fullmatch(digest)),
            "invalid approved OCI manifest digest")
    return "/acr/v1/comuni/_manifests/" + digest + "?api-version=" + API_VERSION


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def parse_json(data):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "ambiguous ACR metadata")
            result[key] = value
        return result
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)


def checked_token(value):
    require(isinstance(value, str) and bool(TOKEN.fullmatch(value)),
            "missing or malformed registry OAuth2 token")
    return value


class ACRClient:
    def __init__(self, registry_name, registry_host, tenant_id):
        require(isinstance(registry_name, str) and
                bool(REGISTRY_NAME.fullmatch(registry_name)) and
                registry_host == registry_name + ".azurecr.io",
                "unapproved managed Azure registry")
        require(isinstance(tenant_id, str) and bool(TENANT.fullmatch(tenant_id)),
                "invalid approved Entra tenant")
        self.host = registry_host
        self.tenant = tenant_id
        self.token = None
        self.opener = urllib.request.build_opener(NoRedirect())

    def _request(self, method, path, *, fields=None, json_body=None, authenticated=False):
        require(path in ("/oauth2/exchange", "/oauth2/token") or
                path.startswith("/acr/v1/comuni/_tags/") or
                path.startswith("/acr/v1/comuni/_manifests/"),
                "unexpected registry request path")
        headers = {"Accept": "application/json"}
        if fields is not None:
            data = urllib.parse.urlencode(fields).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            data = json.dumps(json_body, separators=(",", ":")).encode("ascii")
            headers["Content-Type"] = "application/json"
        else:
            data = None
        if authenticated:
            headers["Authorization"] = "Bearer " + checked_token(self.token)
        request = urllib.request.Request(
            "https://" + self.host + path, data=data, headers=headers, method=method)
        with self.opener.open(request, timeout=TIMEOUT) as response:
            require(response.status == 200, "unexpected ACR REST HTTP status")
            body = response.read(MAX_BODY + 1)
        require(len(body) <= MAX_BODY, "oversized ACR REST metadata")
        result = parse_json(body)
        require(isinstance(result, dict), "invalid ACR REST response")
        return result

    def authenticate(self):
        cli = subprocess.run(
            ["az", "account", "get-access-token", "--resource",
             "https://containerregistry.azure.net", "--query", "accessToken",
             "--output", "tsv", "--only-show-errors"],
            capture_output=True, text=True, check=False, timeout=30)
        require(cli.returncode == 0, "approved builder Entra token unavailable")
        aad = checked_token(cli.stdout.strip())
        refresh_info = self._request(
            "POST", "/oauth2/exchange",
            fields={"grant_type": "access_token", "service": self.host,
                    "tenant": self.tenant, "access_token": aad})
        refresh = checked_token(refresh_info.get("refresh_token"))
        access_info = self._request(
            "POST", "/oauth2/token",
            fields={"grant_type": "refresh_token", "service": self.host,
                    "scope": SCOPE, "refresh_token": refresh})
        self.token = checked_token(access_info.get("access_token"))

    def _properties(self, method, path, kind, reference, update=False):
        data = self._request(
            method, path,
            json_body={"writeEnabled": False, "deleteEnabled": False} if update else None,
            authenticated=True)
        require(data.get("registry") == self.host and
                data.get("imageName") == "comuni",
                "ACR returned unrelated repository metadata")
        record = data.get(kind)
        require(isinstance(record, dict), "ACR missing tag or manifest metadata")
        if kind == "tag":
            require(record.get("name") == reference and
                    isinstance(record.get("digest"), str) and
                    bool(DIGEST.fullmatch(record["digest"])),
                    "ACR tag identity or digest invalid")
        else:
            require(record.get("digest") == reference,
                    "ACR manifest identity differs from approved digest")
        attrs = record.get("changeableAttributes")
        require(isinstance(attrs, dict) and
                all(type(attrs.get(key)) is bool for key in (
                    "writeEnabled", "deleteEnabled", "readEnabled", "listEnabled")),
                "ACR metadata attributes are incomplete or ambiguous")
        require(attrs["readEnabled"] is True,
                "approved image not readable from ACR")
        if update:
            self._require_locked(attrs)
        return record

    @staticmethod
    def _require_locked(attrs):
        require(attrs["writeEnabled"] is False and attrs["deleteEnabled"] is False
                and attrs["readEnabled"] is True,
                "ACR tag or manifest remains mutable or unreadable")

    def tag_digest(self, sha, expected_digest=None):
        record = self._properties("GET", tag_path(sha), "tag", sha)
        digest = record["digest"]
        if expected_digest is not None:
            require(isinstance(expected_digest, str) and
                    bool(DIGEST.fullmatch(expected_digest)) and digest == expected_digest,
                    "registry tag digest differs from approved Docker push")
        return digest

    def lock(self, sha, approved_digest):
        tag, manifest = tag_path(sha), manifest_path(approved_digest)
        self.tag_digest(sha, expected_digest=approved_digest)
        self._properties("PATCH", tag, "tag", sha, update=True)
        self._properties("PATCH", manifest, "manifest", approved_digest, update=True)
        readback = self._properties("GET", tag, "tag", sha)
        self._require_locked(readback["changeableAttributes"])
        require(readback["digest"] == approved_digest,
                "ACR tag changed after protected manifest update")
        manifest_readback = self._properties("GET", manifest, "manifest", approved_digest)
        self._require_locked(manifest_readback["changeableAttributes"])
