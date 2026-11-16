#!/usr/bin/env python3
"""Authenticate Docker to the approved Azure Container Registry via Entra OAuth2.

Only Azure account get-access-token for the ACR audience is needed; there is
no az acr login and no registry control-plane lookup. Exchange the short-lived
Entra access token over pinned HTTPS for an ACR refresh token, then send it
only through Docker's --password-stdin. Never echo tokens or CLI/HTTP errors.

Reference: Azure/acr/docs/AAD-OAuth.md and Microsoft ACR dataplane REST
POST /oauth2/exchange. Requires previously verified GitHub OIDC CLI session.
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

NAME = re.compile(r"[a-z0-9]{5,50}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z", re.I)
TOKEN = re.compile(r"[A-Za-z0-9._~-]{16,16000}\Z")
MAX_RESPONSE = 32768
NULL_GUID = "00000000-0000-0000-0000-000000000000"


class LoginRejected(Exception):
    """Safe constant errors; never expose registry HTTP or CLI diagnostics."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        # A 30x following the POST would disclose the Entra bearer token to
        # a different server. Refuse *all* redirects, even same-host.
        return None


def require(ok, reason):
    if not ok:
        raise LoginRejected(reason)


def valid_token(value):
    return isinstance(value, str) and bool(TOKEN.fullmatch(value))


def acr_oauth_login(args):
    require(bool(NAME.fullmatch(args.registry_name)) and
            args.registry_host == args.registry_name + ".azurecr.io",
            "invalid approved Azure managed registry hostname")
    require(bool(UUID.fullmatch(args.tenant_id)),
            "missing or invalid Azure tenant ID")

    result = subprocess.run(
        ["az", "account", "get-access-token", "--resource",
         "https://containerregistry.azure.net", "--query", "accessToken",
         "--output", "tsv", "--only-show-errors"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    require(result.returncode == 0, "cannot obtain short-lived Entra ACR token")
    aad_token = result.stdout.strip()
    require(valid_token(aad_token), "invalid Entra token from approved Azure OIDC session")

    # The registry hostname is constructed from validated alphanumeric input:
    # never accept URL components, ports, paths, or user-provided redirects.
    endpoint = "https://" + args.registry_host + "/oauth2/exchange"
    form = urllib.parse.urlencode({
        "grant_type": "access_token",
        "service": args.registry_host,
        "tenant": args.tenant_id,
        "access_token": aad_token,
    }).encode("ascii")
    request = urllib.request.Request(
        endpoint, data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=20) as response:
        require(response.status == 200, "ACR OAuth2 exchange rejected")
        body = response.read(MAX_RESPONSE + 1)
    require(len(body) <= MAX_RESPONSE, "oversized ACR OAuth2 response")
    result_json = json.loads(body.decode("utf-8"))
    require(isinstance(result_json, dict) and
            valid_token(result_json.get("refresh_token")),
            "missing or invalid ACR refresh token")
    refresh_token = result_json["refresh_token"]

    # Never use --password: subprocess argument arrays can be inspected.
    # Docker's credentials are erased by the existing mandatory docker
    # logout at the boundary before the infrastructure login.
    docker = subprocess.run(
        ["docker", "login", args.registry_host,
         "--username", NULL_GUID, "--password-stdin"],
        input=refresh_token, capture_output=True, text=True,
        check=False, timeout=30,
    )
    require(docker.returncode == 0,
            "Docker could not authenticate to approved Azure registry")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Login Docker to managed ACR using Entra OIDC without ARM registry permissions")
    parser.add_argument("--registry-name", required=True)
    parser.add_argument("--registry-host", required=True)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args(argv)
    try:
        acr_oauth_login(args)
    except (LoginRejected, OSError, ValueError, TypeError, UnicodeError,
            subprocess.TimeoutExpired, urllib.error.URLError,
            urllib.error.HTTPError, json.JSONDecodeError) as error:
        reason = (str(error) if isinstance(error, LoginRejected)
                  else "unavailable or invalid registry authentication response")
        print("ACR OAuth2 login rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
