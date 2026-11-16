"""RED-first GitHub Actions release gate: verify 7 successful jobs on exact main SHA.

No network or Azure credentials: the GitHub HTTPS opener is faked in every test.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import urllib.error
import urllib.parse
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/azure/check-release-ci.py"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
SHA = "a" * 40
OTHER_SHA = "b" * 40
TOKEN = "ghs_fake_private_release_token_only_for_testing"
RUN_ID = 43917329705
JOBS = (
    "Backend (.NET 10 + PostgreSQL)",
    "React build + Playwright",
    "Terraform validate",
    "Dependency security (NuGet and npm)",
    "CodeQL (csharp)",
    "CodeQL (javascript-typescript)",
    "Combined container image",
)


def workflow_run(**override):
    return {
        "id": RUN_ID, "name": "CI", "path": ".github/workflows/ci.yml",
        "head_sha": SHA, "head_branch": "main", "event": "push",
        "status": "completed", "conclusion": "success", **override,
    }


def job(name, **override):
    return {
        "name": name, "run_id": RUN_ID, "head_sha": SHA,
        "status": "completed", "conclusion": "success", **override,
    }


class Reply(io.BytesIO):
    def __init__(self, value, status=200):
        super().__init__(value)
        self.status = status


class FakeHttps:
    def __init__(self, first, second, *, status=200, error=None):
        self.payloads = [first, second]
        self.status, self.error = status, error
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return Reply(self.payloads.pop(0), status=self.status)


class ReleaseCiGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("release_ci_gate", GATE)
        cls.gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.gate)

    def invoke(self, *, runs=None, jobs=None, env=None, raw_runs=None,
               raw_jobs=None, status=200, error=None):
        runs = [workflow_run()] if runs is None else runs
        jobs = [job(name) for name in JOBS] if jobs is None else jobs
        first = (json.dumps({"total_count": len(runs),
                             "workflow_runs": runs}).encode()
                 if raw_runs is None else raw_runs)
        second = (json.dumps({"total_count": len(jobs),
                              "jobs": jobs}).encode()
                  if raw_jobs is None else raw_jobs)
        network = FakeHttps(first, second, status=status, error=error)
        fake_opener = SimpleNamespace(open=network.open)
        values = {
            "GITHUB_REPOSITORY": "KeyserDSoze/Comuni",
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": SHA, "GITHUB_TOKEN": TOKEN,
        }
        values.update(env or {})
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, values, clear=True), \
             mock.patch.object(self.gate.urllib.request, "build_opener",
                               return_value=fake_opener) as builder, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status_code = self.gate.main()
        return status_code, stdout.getvalue(), stderr.getvalue(), network, builder

    def deny(self, **kwargs):
        code, out, err, network, _ = self.invoke(**kwargs)
        self.assertNotEqual(0, code)
        self.assertEqual("", out)
        for secret in (TOKEN, SHA, OTHER_SHA, "ghs_", "Traceback"):
            self.assertNotIn(secret, err)
        return network

    def test_exact_successful_main_push_with_all_seven_jobs(self):
        code, out, err, network, builder = self.invoke()
        self.assertEqual(0, code, err)
        self.assertEqual("", out + err)
        self.assertEqual(2, len(network.requests))
        self.assertTrue(any(isinstance(h, self.gate.NoRedirect)
                            for h in builder.call_args.args))
        expected_path = (
            "/repos/KeyserDSoze/Comuni/actions/workflows/ci.yml/runs")
        first_request = network.requests[0][0]
        parsed = urllib.parse.urlsplit(first_request.full_url)
        self.assertEqual(("https", "api.github.com", expected_path),
                         (parsed.scheme, parsed.netloc, parsed.path))
        self.assertEqual({
            "head_sha": [SHA], "branch": ["main"], "event": ["push"],
            "status": ["completed"], "per_page": ["100"],
        }, urllib.parse.parse_qs(parsed.query))
        self.assertEqual(
            "https://api.github.com/repos/KeyserDSoze/Comuni/actions/runs/"
            + str(RUN_ID) + "/jobs?per_page=100",
            network.requests[1][0].full_url)
        for request, timeout in network.requests:
            self.assertEqual("GET", request.get_method())
            self.assertEqual("Bearer " + TOKEN,
                             request.get_header("Authorization"))
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 30)

    def test_ref_repo_event_sha_or_missing_token_denied_before_network(self):
        for env in (
            {"GITHUB_REF": "refs/heads/test"},
            {"GITHUB_REPOSITORY": "attacker/Comuni"},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_SHA": OTHER_SHA.upper()},
            {"GITHUB_SHA": "a" * 39},
            {"GITHUB_TOKEN": ""},
            {"GITHUB_TOKEN": TOKEN + " whitespace"},
            {"GITHUB_TOKEN": "ghs_too_short"},
        ):
            with self.subTest(env=list(env.keys())):
                self.assertEqual([], self.deny(env=env).requests)

    def test_no_green_run_or_wrong_workflow_identity_denied(self):
        for runs in (
            [],
            [workflow_run(head_sha=OTHER_SHA)],
            [workflow_run(head_branch="release")],
            [workflow_run(event="workflow_dispatch")],
            [workflow_run(status="in_progress")],
            [workflow_run(conclusion="failure")],
            [workflow_run(conclusion="skipped")],
            [workflow_run(path=".github/workflows/other.yml")],
            [workflow_run(name="Other")],
            [workflow_run(id=-1)],
            [workflow_run(), workflow_run(id=RUN_ID + 1)],
        ):
            with self.subTest(runs=runs):
                self.assertEqual(1, len(self.deny(runs=runs).requests))

    def test_incomplete_failed_skipped_duplicate_or_wrong_sha_jobs_denied(self):
        full = [job(name) for name in JOBS]
        for jobs in (
            full[:-1],
            [*full, job(JOBS[0])],
            [*full[:-1], job("Unapproved build")],
            [*full[:-1], job(JOBS[-1], status="queued")],
            [*full[:-1], job(JOBS[-1], conclusion="failure")],
            [*full[:-1], job(JOBS[-1], conclusion="skipped")],
            [*full[:-1], job(JOBS[-1], head_sha=OTHER_SHA)],
            [*full[:-1], job(JOBS[-1], run_id=RUN_ID + 1)],
            [*full[:-1], job(JOBS[-1], name=JOBS[0])],
        ):
            with self.subTest(job_count=len(jobs)):
                self.assertEqual(2, len(self.deny(jobs=jobs).requests))

    def test_http_redirect_malformed_json_duplicates_oversized_and_secret_safe(self):
        for args in (
            {"status": 302},
            {"status": 403},
            {"error": urllib.error.URLError("sensitive " + TOKEN)},
            {"raw_runs": b""},
            {"raw_runs": b"null"},
            {"raw_runs": b"{invalid"},
            {"raw_runs": b'{"workflow_runs":[],"workflow_runs":[],"total_count":0}'},
            {"raw_runs": b" " * 2500000},
            {"raw_jobs": b'{"jobs":[],"jobs":[],"total_count":7}'},
            {"raw_jobs": b'{"jobs":"not an array","total_count":7}'},
        ):
            with self.subTest(args=list(args.keys())):
                self.deny(**args)

    def test_deployment_checks_ci_before_first_azure_login(self):
        self.assertIn("actions: read", DEPLOY)
        self.assertIn("scripts/azure/check-release-ci.py", DEPLOY)
        self.assertLess(DEPLOY.index("check-release-ci.py"),
                        DEPLOY.index("uses: azure/login@"))
        self.assertLess(DEPLOY.index("check-release-ci.py"),
                        DEPLOY.index("docker build"))
        self.assertLess(DEPLOY.index("check-release-ci.py"),
                        DEPLOY.index("terraform -chdir=infra plan"))
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", DEPLOY)


if __name__ == "__main__":
    unittest.main()
