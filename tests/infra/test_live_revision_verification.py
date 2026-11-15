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
    return [
        revision(STABLE, image="comuni.azurecr.io/comuni:" + ("0" * 40)),
        revision(
            CANDIDATE, image=IMAGE, key_id=KEY_ID,
            secret="tenant-proof-key-v" + VERSION,
        ),
    ]


def valid_traffic():
    return [
        {"revisionName": APP + "-" + STABLE, "latestRevision": False, "weight": 100},
        {"latestRevision": True, "weight": 0},
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
if args[:3] == ["containerapp", "revision", "list"]:
    print(os.environ["AZ_REVISIONS"])
elif args[:4] == ["containerapp", "ingress", "traffic", "show"]:
    print(os.environ["AZ_TRAFFIC"])
elif args[:2] == ["containerapp", "show"]:
    print(os.environ.get("AZ_MODE", "Multiple"))
else:
    sys.exit(88)
"""


class LiveRevisionVerificationTests(unittest.TestCase):
    def call(self, revisions=None, traffic=None, mode="Multiple", *, az_fail=False,
             candidate= CANDIDATE, image=IMAGE, attempts="1"):
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

    def test_workflow_requires_read_only_verify_after_apply_and_no_promotion(self):
        self.assertTrue(VERIFY.is_file())
        self.assertIn("scripts/azure/verify-staged-revisions.py", WORKFLOW)
        self.assertLess(WORKFLOW.index("terraform -chdir=infra apply"),
                        WORKFLOW.index("scripts/azure/verify-staged-revisions.py"))
        self.assertIn("--expected-image", WORKFLOW)
        self.assertIn("--candidate-key-id", WORKFLOW)
        self.assertIn("--candidate-secret-version", WORKFLOW)
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
        self.assertNotIn("tenant-proof-key-v" + VERSION, result.stdout + result.stderr)
        self.assertNotIn("AZ_REVISIONS", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
