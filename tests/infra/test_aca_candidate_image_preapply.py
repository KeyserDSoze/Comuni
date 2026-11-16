"""RED-first: candidate image must be pinned before any Terraform apply.

Synthetic Terraform plans only. The same gate that authorizes an ACA 0% stage
must reject images that could run with tenant signing and database secrets.
"""
import copy
import unittest

from test_aca_stage_immutable_infrastructure import check
from test_staged_rollout import (
    fixture_plan, SOURCE_COMMIT_SHA, SOURCE_IMAGE_DIGEST, MANAGED_REGISTRY, DEPLOY, TERRAFORM,
)

SENTINEL = "synthetic-secret-that-must-never-appear-in-the-gate-output"


def candidate(plan):
    return plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]


def registry(plan):
    return plan["planned_values"]["root_module"]["resources"][1]


class CandidateImagePreapplyTests(unittest.TestCase):
    def reject_without_leaks(self, plan):
        result = check(plan)
        self.assertNotEqual(0, result.returncode, "untrusted candidate image accepted")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("Password=", result.stdout + result.stderr)

    def test_positive_existing_municipal_image_in_managed_acr(self):
        plan = fixture_plan()
        self.assertEqual(MANAGED_REGISTRY + "/comuni@" + SOURCE_IMAGE_DIGEST,
                         candidate(plan)["image"])
        self.assertEqual(0, check(plan).returncode)

    def test_different_registry_tag_digest_and_repository_fail_before_apply(self):
        valid = MANAGED_REGISTRY + "/comuni@" + SOURCE_IMAGE_DIGEST
        cases = [
            "attacker.azurecr.io/comuni@" + SOURCE_IMAGE_DIGEST,
            MANAGED_REGISTRY + "/comuni:latest",
            MANAGED_REGISTRY + "/comuni:" + "f" * 40,
            MANAGED_REGISTRY + "/comuni:" + SOURCE_COMMIT_SHA.upper(),
            MANAGED_REGISTRY + "/other@" + SOURCE_IMAGE_DIGEST,
            MANAGED_REGISTRY + "/team/comuni@" + SOURCE_IMAGE_DIGEST,
            MANAGED_REGISTRY + "/comuni@" + "sha256:" + "b" * 64,
            valid + "@sha256:" + "b" * 64,
            valid + ":extra",
            valid + "/extra",
            "https://" + valid,
            SENTINEL,
            None,
            "",
            {"unknown": True},
        ]
        for image in cases:
            with self.subTest(image=str(image)[:70]):
                plan = fixture_plan()
                candidate(plan)["image"] = image
                self.reject_without_leaks(plan)

    def test_init_container_cannot_bypass_the_approved_image(self):
        for init in (
            [{"name": "exfiltrate", "image": "attacker.azurecr.io/steal:latest",
              "env": [{"name": "SECRET", "value": SENTINEL}]}],
            [{"name": "extra", "image": MANAGED_REGISTRY + "/other:latest"}],
        ):
            with self.subTest(count=len(init)):
                plan = fixture_plan()
                plan["resource_changes"][0]["change"]["after"]["template"][0]["init_container"] = init
                self.reject_without_leaks(plan)

    def test_image_key_missing_fails_closed(self):
        plan = fixture_plan()
        candidate(plan).pop("image")
        self.reject_without_leaks(plan)

    def test_managed_registry_missing_duplicated_or_spoofed_fails(self):
        for mutation in ("missing", "duplicate", "wrong_type", "wrong_host",
                         "wrong_name", "unknown", "empty"):
            with self.subTest(mutation=mutation):
                plan = fixture_plan()
                resources = plan["planned_values"]["root_module"]["resources"]
                item = registry(plan)
                if mutation == "missing":
                    resources.pop()
                elif mutation == "duplicate":
                    resources.append(copy.deepcopy(item))
                elif mutation == "wrong_type":
                    item["type"] = "azurerm_container_app"
                elif mutation == "wrong_host":
                    item["values"]["login_server"] = "attacker.azurecr.io"
                elif mutation == "wrong_name":
                    item["values"]["name"] = "attacker"
                elif mutation == "unknown":
                    item["values"]["login_server"] = None
                elif mutation == "empty":
                    item["values"] = {}
                self.reject_without_leaks(plan)

    def test_app_scoped_registry_must_match_managed_registry(self):
        plan = fixture_plan()
        # A second, otherwise legitimate registry must never be selected
        # by trusting the app-scoped registry alone.
        app = plan["resource_changes"][0]["change"]
        app["before"]["registry"][0]["server"] = "attacker.azurecr.io"
        app["after"]["registry"][0]["server"] = "attacker.azurecr.io"
        self.reject_without_leaks(plan)

    def test_rejects_candidate_suffix_not_derived_from_approved_source(self):
        plan = fixture_plan()
        # The candidate revision suffix is an already-approved argument in
        # other gates. This test specifically requires its connection to
        # GITHUB_SHA, not just consistency with the template.
        plan["resource_changes"][0]["change"]["after"]["template"][0]["revision_suffix"] = (
            "r" + "f" * 12)
        # Existing check already rejects a suffix different from CLI argument;
        # subsequent TDD covers the CLI SHA binding itself.
        self.reject_without_leaks(plan)


    def test_rejects_wrong_malformed_or_ambiguous_source_sha(self):
        for source_sha in (
            "", "abc", SOURCE_COMMIT_SHA.upper(), SOURCE_COMMIT_SHA + "0",
            SOURCE_COMMIT_SHA + " ", "f" * 40,
            SOURCE_COMMIT_SHA[:12] + "f" * 28, SENTINEL,
        ):
            with self.subTest(sha_prefix=str(source_sha)[:12]):
                self.reject_without_leaks_source(fixture_plan(), source_sha)

    def reject_without_leaks_source(self, plan, source_sha):
        result = check(plan, source_sha=source_sha)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_release_workflow_uses_source_commit_not_plan_image_as_trust_anchor(self):
        self.assertIn('--source-commit-sha "$GITHUB_SHA"', DEPLOY)
        self.assertIn('TAG="${REGISTRY_HOST}/comuni:${GITHUB_SHA}"', DEPLOY)
        self.assertIn("scripts/azure/resolve-pushed-image-digest.py", DEPLOY)
        self.assertIn('--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"', DEPLOY)
        self.assertIn('image  = var.image', TERRAFORM)
        self.assertIn('azurerm_container_registry.main.login_server', TERRAFORM)
        self.assertLess(DEPLOY.index('--source-commit-sha "$GITHUB_SHA"'),
                        DEPLOY.index('terraform -chdir=infra apply'))


if __name__ == "__main__":
    unittest.main()
