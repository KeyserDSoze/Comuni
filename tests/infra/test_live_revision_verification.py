"""TDD contract for read-only Azure Container Apps post-stage verification.

No Azure account, secrets or network are used; a fake az executable supplies
the exact metadata shapes returned by ARM/CLI.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts/azure/verify-staged-revisions.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
APP = "comuni-itn-001-app"
RG = "comuni-itn-001-rg"
STABLE = "stable001"
CANDIDATE = "r123456789abc"
IMAGE = "comuni.azurecr.io/comuni:" + ("a" * 40)
KEY_ID = "rotate2026"
VERSION = "b" * 32
RUNTIME_POSTGRES_VERSION = "d" * 32
POSTGRES_HOST = "comuni-itn-001-pg.postgres.database.azure.com"


def revision(suffix, *, image, key_id="legacy", secret="tenant-proof-key"):
    return {
        "name": APP + "-" + suffix,
        "properties": {
            "active": True, "healthState": "Healthy",
            "provisioningState": "Provisioned", "runningState": "Running",
            "replicas": 1,
            "template": {"containers": [{
                "image": image,
                "env": [
                    {"name": "Security__TenantProofKeyId", "value": key_id},
                    {"name": "Security__TenantProofKey", "secretRef": secret},
                ]
            }]},
        },
    }


def valid_revisions():
    stable = revision(STABLE, image="comuni.azurecr.io/comuni:" + ("0" * 40))
    candidate = revision(
        CANDIDATE, image=IMAGE, key_id=KEY_ID,
        secret="tp-" + VERSION[:16],
    )
    candidate["properties"]["template"]["containers"][0]["env"].append(
        {"name": "ConnectionStrings__Default",
         "secretRef": "pg-" + RUNTIME_POSTGRES_VERSION[:16]})
    candidate["properties"]["template"]["containers"][0]["env"].append(
        {"name": "RuntimePostgres__ExpectedHost", "value": POSTGRES_HOST})
    return [stable, candidate]


def valid_traffic():
    return [
        {"revisionName": APP + "-" + STABLE, "latestRevision": False, "weight": 100},
        {"latestRevision": True, "weight": 0, "label": CANDIDATE},
    ]


MOCK_AZ = r"""#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["AZ_CALL_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\n")
if os.environ.get("AZ_FAIL") == "1":
    sys.exit(1)
if args[:3] == ["containerapp", "revision", "list"] and os.environ.get("AZ_FAIL_ONCE") == "1":
    marker = os.environ["AZ_FAIL_MARKER"]
    if not os.path.exists(marker):
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("transient")
        sys.exit(1)
if args[:3] == ["containerapp", "revision", "list"]:
    print(os.environ["AZ_REVISIONS"])
elif args[:4] == ["containerapp", "ingress", "traffic", "show"]:
    print(os.environ["AZ_TRAFFIC"])
elif args[:2] == ["containerapp", "show"]:
    print(os.environ.get("AZ_MODE", "Multiple"))
elif args[:3] == ["postgres", "flexible-server", "show"]:
    if os.environ.get("AZ_POSTGRES_FAIL") == "1":
        sys.exit(3)
    if "--name" not in args or args[args.index("--name") + 1] != "comuni-itn-001-pg":
        sys.exit(4)
    if "--query" not in args or args[args.index("--query") + 1] != "fullyQualifiedDomainName":
        sys.exit(5)
    print(os.environ.get("AZ_POSTGRES_HOST", "comuni-itn-001-pg.postgres.database.azure.com"))
else:
    sys.exit(88)
"""


class LiveRevisionVerificationTests(unittest.TestCase):
    def call(self, revisions=None, traffic=None, mode="Multiple", *, az_fail=False,
             fail_once=False, candidate=CANDIDATE, image=IMAGE, attempts="1",
             postgres_host=POSTGRES_HOST, postgres_fail=False):
        with tempfile.TemporaryDirectory() as folder:
            fake_az = Path(folder) / "az"
            fake_az.write_text(MOCK_AZ, encoding="utf-8")
            fake_az.chmod(0o700)
            calls = Path(folder) / "calls.jsonl"
            env = {
                **os.environ,
                "PATH": folder + os.pathsep + os.environ.get("PATH", ""),
                "AZ_CALL_LOG": str(calls),
                "AZ_REVISIONS": json.dumps(valid_revisions() if revisions is None else revisions),
                "AZ_TRAFFIC": json.dumps(valid_traffic() if traffic is None else traffic),
                "AZ_MODE": mode, "AZ_FAIL": "1" if az_fail else "0",
                "AZ_POSTGRES_HOST": postgres_host,
                "AZ_POSTGRES_FAIL": "1" if postgres_fail else "0",
                "AZ_FAIL_ONCE": "1" if fail_once else "0",
                "AZ_FAIL_MARKER": str(Path(folder) / "first-failure"),
            }
            cmd = [
                "python3", str(VERIFY),
                "--app", APP,
                "--resource-group", RG,
                "--stable-revision", STABLE,
                "--candidate-revision", candidate,
                "--expected-image", image,
                "--candidate-key-id", KEY_ID,
                "--candidate-secret-version", VERSION,
                "--runtime-secret-version", RUNTIME_POSTGRES_VERSION,
                "--attempts", attempts,
                "--interval-seconds", "0",
            ]
            try:
                result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=12)
                invoked = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
                return result, invoked
            except FileNotFoundError:
                return subprocess.CompletedProcess(cmd, 127, "", "verifier script missing"), []

    def test_accepts_healthy_stable_and_candidate_with_explicit_100_0_traffic(self):
        result, calls = self.call()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(any(c[:3] == ["containerapp", "revision", "list"] for c in calls))
        self.assertTrue(any(c[:4] == ["containerapp", "ingress", "traffic", "show"] for c in calls))
        self.assertTrue(any(c[:2] == ["containerapp", "show"] for c in calls))
        self.assertFalse(any("set" in c or "update" in c for c in calls))
        self.assertNotIn(VERSION, result.stdout + result.stderr)
        self.assertNotIn(IMAGE, result.stdout + result.stderr)

    def test_rejects_missing_candidate_or_stable_and_duplicate_names(self):
        for revisions in [
            valid_revisions()[0:1],
            valid_revisions()[1:2],
            valid_revisions() + [valid_revisions()[1]],
        ]:
            result, _ = self.call(revisions=revisions)
            self.assertNotEqual(0, result.returncode)

    def test_rejects_unhealthy_unready_inactive_and_zero_replicas(self):
        for index in (0, 1):
            for field, bad in [
                ("healthState", "Unhealthy"), ("provisioningState", "Failed"),
                ("runningState", "Degraded"), ("active", False), ("replicas", 0),
            ]:
                revisions = valid_revisions()
                revisions[index]["properties"][field] = bad
                result, _ = self.call(revisions=revisions)
                self.assertNotEqual(0, result.returncode, (index, field, result.stdout))

    def test_rejects_wrong_image_key_id_and_candidate_secret_reference(self):
        cases = []
        r = valid_revisions()
        r[1]["properties"]["template"]["containers"][0]["image"] = "other.azurecr.io/comuni:wrong"
        cases.append(r)
        r = valid_revisions()
        r[1]["properties"]["template"]["containers"][0]["env"][0]["value"] = "forged"
        cases.append(r)
        r = valid_revisions()
        r[1]["properties"]["template"]["containers"][0]["env"][1]["secretRef"] = "tenant-proof-key"
        cases.append(r)
        r = valid_revisions()
        r[1]["properties"]["template"]["containers"][0]["env"].pop()
        cases.append(r)
        for revisions in cases:
            result, _ = self.call(revisions=revisions)
            self.assertNotEqual(0, result.returncode)

    def test_rejects_wrong_missing_or_inline_candidate_runtime_sql_credential(self):
        cases = []
        for change in ("stable", "inline", "missing", "duplicate"):
            revisions = valid_revisions()
            candidate = revisions[1]["properties"]["template"]["containers"][0]["env"]
            if change == "stable":
                candidate[-2]["secretRef"] = "postgres-connection"
            elif change == "inline":
                candidate[-2] = {"name": "ConnectionStrings__Default", "value": "Password=example-dont-echo"}
            elif change == "missing":
                candidate.pop(-2)
            else:
                candidate.append(dict(candidate[-2]))
            cases.append(revisions)
        for revisions in cases:
            result, _ = self.call(revisions=revisions)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("example-dont-echo", result.stdout + result.stderr)

    def test_post_stage_checks_exact_managed_postgres_identity_from_azure(self):
        result, calls = self.call()
        self.assertEqual(0, result.returncode, result.stderr)
        pg_calls = [x for x in calls if x[:3] == ["postgres", "flexible-server", "show"]]
        self.assertEqual(1, len(pg_calls))
        self.assertIn("fullyQualifiedDomainName", pg_calls[0])

        for postgres_host in (
            "other-pg.postgres.database.azure.com",
            "malformed.example.test", "",
        ):
            result, _ = self.call(postgres_host=postgres_host)
            self.assertNotEqual(0, result.returncode)
            if postgres_host:
                self.assertNotIn(postgres_host, result.stdout + result.stderr)
        result, _ = self.call(postgres_fail=True)
        self.assertNotEqual(0, result.returncode)

    def test_candidate_rejects_spoofed_missing_secret_ref_or_duplicate_expected_host(self):
        for kind in ("wrong", "missing", "duplicate", "secret"):
            revisions = valid_revisions()
            env = revisions[1]["properties"]["template"]["containers"][0]["env"]
            if kind == "wrong":
                env[-1]["value"] = "other-pg.postgres.database.azure.com"
            elif kind == "missing":
                env.pop()
            elif kind == "duplicate":
                env.append(dict(env[-1]))
            else:
                env[-1] = {
                    "name": "RuntimePostgres__ExpectedHost",
                    "secretRef": "postgres-connection",
                }
            result, _ = self.call(revisions=revisions)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("other-pg.postgres.database.azure.com",
                             result.stdout + result.stderr)

    def test_rejects_missing_or_misdirected_candidate_label(self):
        p = valid_traffic()
        p[1].pop("label")
        result, _ = self.call(traffic=p)
        self.assertNotEqual(0, result.returncode)

        p = valid_traffic()
        p[1]["label"] = "wrong-label"
        result, _ = self.call(traffic=p)
        self.assertNotEqual(0, result.returncode)

        p = valid_traffic()
        p[0]["label"] = CANDIDATE
        result, _ = self.call(traffic=p)
        self.assertNotEqual(0, result.returncode)

    def test_rejects_traffic_drift_or_automatic_promotion(self):
        cases = []
        traffic = valid_traffic()
        traffic[0]["weight"] = 99
        cases.append(traffic)
        traffic = valid_traffic()
        traffic[1]["weight"] = 100
        cases.append(traffic)
        traffic = valid_traffic()
        traffic[0]["revisionName"] = APP + "-wrong"
        cases.append(traffic)
        traffic = valid_traffic()
        traffic.append({"revisionName": APP + "-unknown", "weight": 0})
        cases.append(traffic)
        traffic = valid_traffic()
        traffic[1]["latestRevision"] = False
        cases.append(traffic)
        for traffic in cases:
            result, _ = self.call(traffic=traffic)
            self.assertNotEqual(0, result.returncode)

    def test_fails_closed_on_cli_errors_single_revision_mode_and_invalid_args(self):
        result, _ = self.call(az_fail=True)
        self.assertNotEqual(0, result.returncode)
        result, _ = self.call(mode="Single")
        self.assertNotEqual(0, result.returncode)
        result, _ = self.call(candidate="not;safe")
        self.assertNotEqual(0, result.returncode)
        result, _ = self.call(image="http://invalid/image")
        self.assertNotEqual(0, result.returncode)

    def test_bounded_retry_recovers_transient_azure_metadata_failure(self):
        result, calls = self.call(fail_once=True, attempts="2")
        self.assertEqual(0, result.returncode, result.stderr)
        revision_requests = [x for x in calls if x[:3] == ["containerapp", "revision", "list"]]
        self.assertEqual(2, len(revision_requests))

        # One attempt must fail closed; it must not silently skip the verification.
        rejected, _ = self.call(fail_once=True, attempts="1")
        self.assertNotEqual(0, rejected.returncode)

    def test_workflow_requires_read_only_verify_after_apply_and_no_promotion(self):
        self.assertTrue(VERIFY.is_file())
        self.assertIn("scripts/azure/verify-staged-revisions.py", WORKFLOW)
        self.assertLess(WORKFLOW.index("terraform -chdir=infra apply"),
                        WORKFLOW.index("scripts/azure/verify-staged-revisions.py"))
        self.assertIn("--expected-image", WORKFLOW)
        self.assertIn("--candidate-key-id", WORKFLOW)
        self.assertIn("--candidate-secret-version", WORKFLOW)
        self.assertIn("--runtime-secret-version", WORKFLOW)
        self.assertIn("postgres", VERIFY.read_text())
        self.assertIn("fullyQualifiedDomainName", VERIFY.read_text())
        self.assertNotIn("az containerapp ingress traffic set", WORKFLOW)
        self.assertNotIn("az containerapp revision deactivate", WORKFLOW)

    def test_does_not_expose_cli_payload_or_call_mutating_commands(self):
        result, calls = self.call()
        self.assertEqual(0, result.returncode, result.stderr)
        for call in calls:
            self.assertNotIn("set", call)
            self.assertNotIn("update", call)
            self.assertNotIn("deactivate", call)
            self.assertNotIn("activate", call)
        self.assertNotIn("tp-" + VERSION[:16], result.stdout + result.stderr)
        self.assertNotIn("AZ_REVISIONS", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
