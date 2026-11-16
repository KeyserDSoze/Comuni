#!/usr/bin/env python3
"""Block manual Azure deployment unless all seven CI jobs passed on this main SHA.

GitHub Actions API is read-only; the fixed repository/workflow endpoints
are queried with the ephemeral GITHUB_TOKEN (actions:read). No Azure login,
docker build, or Terraform operation is needed. Never emit HTTP diagnostics,
identities, commit hashes, or authorization values in errors.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "KeyserDSoze/Comuni"
WORKFLOW_PATH = ".github/workflows/ci.yml"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,5000}\Z")
EXPECTED_JOBS = frozenset((
    "Backend (.NET 10 + PostgreSQL)",
    "React build + Playwright",
    "Terraform validate",
    "Dependency security (NuGet and npm)",
    "CodeQL (csharp)",
    "CodeQL (javascript-typescript)",
    "Combined container image",
))
API = "https://api.github.com/repos/" + REPOSITORY + "/actions"
TIMEOUT = 20
MAX_BODY = 1024 * 1024


class ReleaseRejected(Exception):
    """Error message is always a static literal without remote input."""


def require(ok, message):
    if not ok:
        raise ReleaseRejected(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def unique_json(data):
    def unique_pairs(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, "ambiguous GitHub Actions JSON")
            obj[key] = value
        return obj

    parsed = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)
    require(isinstance(parsed, dict), "malformed GitHub Actions response")
    return parsed


def github_get(opener, path, token):
    # All caller-supplied values are prevalidated; never accept arbitrary URLs.
    require(path.startswith(API + "/workflows/ci.yml/runs?") or
            bool(re.fullmatch(re.escape(API) + r"/runs/[1-9][0-9]*/jobs\?per_page=100", path)),
            "unexpected GitHub API endpoint")
    request = urllib.request.Request(
        path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    with opener.open(request, timeout=TIMEOUT) as response:
        require(response.status == 200, "GitHub Actions API unavailable")
        body = response.read(MAX_BODY + 1)
    require(len(body) <= MAX_BODY, "oversized GitHub Actions response")
    return unique_json(body)


def verify_release_ci():
    sha = os.environ.get("GITHUB_SHA", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and bool(COMMIT.fullmatch(sha)),
            "unapproved release source")
    require(bool(TOKEN.fullmatch(token)), "GitHub Actions read token unavailable")

    opener = urllib.request.build_opener(NoRedirect())
    query = urllib.parse.urlencode({
        "head_sha": sha, "branch": "main", "event": "push",
        "per_page": "100",
    })
    runs_data = github_get(opener, API + "/workflows/ci.yml/runs?" + query, token)
    runs = runs_data.get("workflow_runs")
    require(type(runs_data.get("total_count")) is int
            and runs_data["total_count"] == 1
            and isinstance(runs, list) and len(runs) == 1,
            "exactly one matching push CI run required")
    run = runs[0]
    require(isinstance(run, dict)
            and type(run.get("id")) is int and run["id"] > 0
            and run.get("name") == "CI"
            and run.get("path") == WORKFLOW_PATH
            and run.get("head_branch") == "main"
            and run.get("head_sha") == sha
            and run.get("event") == "push"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success",
            "unapproved or incomplete main CI run")

    run_id = run["id"]
    jobs_data = github_get(opener, API + "/runs/" + str(run_id)
                           + "/jobs?per_page=100", token)
    jobs = jobs_data.get("jobs")
    require(type(jobs_data.get("total_count")) is int
            and jobs_data["total_count"] == len(EXPECTED_JOBS)
            and isinstance(jobs, list) and len(jobs) == len(EXPECTED_JOBS),
            "incomplete CI job results")
    observed = set()
    for job in jobs:
        require(isinstance(job, dict)
                and isinstance(job.get("name"), str)
                and job["name"] in EXPECTED_JOBS
                and job["name"] not in observed
                and type(job.get("run_id")) is int and job["run_id"] == run_id
                and job.get("head_sha") == sha
                and job.get("status") == "completed"
                and job.get("conclusion") == "success",
                "unapproved, duplicated or unsuccessful CI job")
        observed.add(job["name"])
    require(observed == EXPECTED_JOBS, "missing required CI job")


def main():
    try:
        verify_release_ci()
    except (ReleaseRejected, OSError, ValueError, TypeError,
            UnicodeError, urllib.error.URLError, json.JSONDecodeError):
        # Suppress original error text, including HTTP body, URL, token or SHA.
        print("Release CI preflight rejected: green 7/7 main CI required",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
