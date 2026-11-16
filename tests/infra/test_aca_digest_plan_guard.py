"""RED-first: immutable OCI digest must replace mutable Docker tag in ACA plan.

The pre-apply gate receives the digest from a verified Docker push + ACR query,
not from a user-controlled Terraform field.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from test_staged_rollout import (
    fixture_plan, MANAGED_REGISTRY, SOURCE_COMMIT_SHA, STABLE_REVISION,
    CANDIDATE_REVISION, STABLE_VERSION, CANDIDATE_VERSION, CANDIDATE_KEY_ID,
    RUNTIME_POSTGRES_VERSION,
)
from test_aca_pushed_digest import DIGEST, OTHER, SENTINEL

GATE = Path(__file__).resolve().parents[2] / "scripts/azure/check-staged-rollout-plan.py"


def gate(plan, approved_digest=DIGEST):
    return subprocess.run(
        [sys.executable, str(GATE),
         "--stable-revision", STABLE_REVISION,
         "--candidate-revision", CANDIDATE_REVISION,
         "--source-commit-sha", SOURCE_COMMIT_SHA,
         "--candidate-image-digest", approved_digest,
         "--stable-secret-version", STABLE_VERSION,
         "--candidate-secret-version", CANDIDATE_VERSION,
         "--candidate-key-id", CANDIDATE_KEY_ID,
         "--runtime-secret-version", RUNTIME_POSTGRES_VERSION],
        input=json.dumps(plan), capture_output=True, text=True, check=False,
    )


def digest_plan():
    plan = fixture_plan()
    plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["image"] = (
        MANAGED_REGISTRY + "/comuni@" + DIGEST)
    return plan


def candidate(plan):
    return plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]


class DigestPinnedCandidateGateTests(unittest.TestCase):
    def assert_rejected(self, plan, *, approved_digest=DIGEST):
        result = gate(plan, approved_digest)
        self.assertNotEqual(0, result.returncode, "unapproved image/digest plan accepted")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("Password=", result.stdout + result.stderr)

    def test_matching_managed_acr_digest_is_accepted(self):
        result = gate(digest_plan())
        self.assertEqual(0, result.returncode, result.stderr)

    def test_mutable_tag_even_when_sha_matches_must_be_rejected(self):
        self.assert_rejected(fixture_plan())

    def test_different_digest_or_registry_is_rejected(self):
        for image in (
            MANAGED_REGISTRY + "/comuni@" + OTHER,
            MANAGED_REGISTRY + "/comuni:latest",
            MANAGED_REGISTRY + "/comuni:" + SOURCE_COMMIT_SHA + "@" + DIGEST,
            "evil.azurecr.io/comuni@" + DIGEST,
            MANAGED_REGISTRY + "/other@" + DIGEST,
            MANAGED_REGISTRY + "/comuni@SHA256:" + DIGEST.split(":")[1],
            MANAGED_REGISTRY + "/comuni@sha256:123",
            MANAGED_REGISTRY + "/comuni@sha256:" + "A" * 64,
            MANAGED_REGISTRY + "/comuni@sha256:" + "f" * 64 + "/extra",
            SENTINEL,
            "", None, {"unknown": True},
        ):
            with self.subTest(image_type=type(image).__name__):
                plan = digest_plan()
                candidate(plan)["image"] = image
                self.assert_rejected(plan)

    def test_digest_cannot_be_authorized_by_tampering_with_plan(self):
        plan = digest_plan()
        candidate(plan)["image"] = MANAGED_REGISTRY + "/comuni@" + OTHER
        self.assert_rejected(plan, approved_digest=DIGEST)

    def test_digest_arg_missing_invalid_or_different_is_rejected(self):
        plan = digest_plan()
        for approved in ("", "sha256:abcd", "sha256:" + "A" * 64,
                         OTHER, SENTINEL, DIGEST + " "):
            with self.subTest(approved_type=type(approved).__name__):
                self.assert_rejected(plan, approved_digest=approved)

    def test_unrelated_security_controls_still_reject_on_digest_plan(self):
        for mutation in ("oidc", "db", "init_container", "registry", "stable_weight"):
            with self.subTest(mutation=mutation):
                plan = digest_plan()
                change = plan["resource_changes"][0]["change"]
                after = change["after"]
                if mutation == "oidc":
                    next(e for e in candidate(plan)["env"] if
                         e.get("name") == "Authentication__Mode")["value"] = "DevelopmentJwt"
                elif mutation == "db":
                    next(e for e in candidate(plan)["env"] if
                         e.get("name") == "ConnectionStrings__Default")["secret_name"] = "postgres-connection"
                elif mutation == "init_container":
                    after["template"][0]["init_container"] = [{"image": "evil.azurecr.io/run:latest"}]
                elif mutation == "registry":
                    after["registry"][0]["server"] = "evil.azurecr.io"
                else:
                    after["ingress"][0]["traffic_weight"][0]["percentage"] = 1
                self.assert_rejected(plan)


if __name__ == "__main__":
    unittest.main()
