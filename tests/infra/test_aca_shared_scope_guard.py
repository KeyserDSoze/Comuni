"""RED-first regression: 0%-traffic ACA stages must preserve application-scoped trust.

The plan examples are synthetic. Never load Azure credentials or terraform state.
"""
import copy
import unittest

from test_aca_stage_immutable_infrastructure import check, SENTINEL
from test_staged_rollout import fixture_plan


def after_and_before():
    plan = fixture_plan()
    change = plan["resource_changes"][0]["change"]
    # A credential in a plan must never appear in a gate error.
    change["after"]["registry"][0]["password"] = SENTINEL
    change["before"]["registry"][0]["password"] = SENTINEL
    return plan, change["before"], change["after"]


class AppScopedStageGuardTests(unittest.TestCase):
    def assert_rejected_without_leak(self, plan):
        response = check(plan)
        self.assertNotEqual(0, response.returncode, "unsafe ACA stage accepted")
        self.assertNotIn(SENTINEL, response.stdout + response.stderr)

    def test_valid_shared_settings_and_versioned_secret_identities_allowed(self):
        plan, before, after = after_and_before()
        self.assertEqual(before["identity"], after["identity"])
        self.assertEqual(before["registry"], after["registry"])
        self.assertEqual(before["container_app_environment_id"],
                         after["container_app_environment_id"])
        self.assertEqual(before["ingress"][0]["external_enabled"],
                         after["ingress"][0]["external_enabled"])
        response = check(plan)
        self.assertEqual(0, response.returncode, response.stderr)
        self.assertNotIn(SENTINEL, response.stdout + response.stderr)

    def test_rejects_app_identity_replacement_or_expansion(self):
        variants = [
            [{"type": "UserAssigned", "identity_ids": ["/attacker"]}],
            [{"type": "SystemAssigned", "identity_ids": []}],
            [{"type": "UserAssigned", "identity_ids": ["/uai", "/attacker"]}],
            [],
        ]
        for variant in variants:
            with self.subTest(identity=variant):
                plan, _, after = after_and_before()
                after["identity"] = variant
                self.assert_rejected_without_leak(plan)

    def test_rejects_registry_mutations_and_environment_switch(self):
        for key, new in (
            ("registry", [{"server": "attacker.azurecr.io", "identity": "/attacker"}]),
            ("registry", [{"server": "synthetic.azurecr.io", "identity": "/attacker",
                           "password": SENTINEL}]),
            ("registry", []),
            ("container_app_environment_id", "/subscriptions/other/environment"),
        ):
            with self.subTest(key=key, value=str(new)[:30]):
                plan, _, after = after_and_before()
                after[key] = new
                self.assert_rejected_without_leak(plan)

    def test_rejects_ingress_app_scope_mutations_beyond_approved_traffic_split(self):
        for key, value in (
            ("external_enabled", False),
            ("target_port", 4444),
            ("transport", "tcp"),
            ("ip_security_restriction", [{"name": "permit-all",
                                          "ip_address_range": "0.0.0.0/0",
                                          "action": "Allow"}]),
            ("custom_domain", [{"name": "attacker.example"}]),
        ):
            with self.subTest(key=key):
                plan, _, after = after_and_before()
                after["ingress"][0][key] = value
                self.assert_rejected_without_leak(plan)

    def test_rejects_existing_secret_identity_change_even_with_identical_uri(self):
        plan, before, after = after_and_before()
        self.assertEqual(before["secret"][0]["key_vault_secret_id"],
                         after["secret"][0]["key_vault_secret_id"])
        after["secret"][0]["identity"] = "/attacker"
        self.assert_rejected_without_leak(plan)

    def test_rejects_candidate_secret_identity_substitution(self):
        for name in ("tp-", "pg-"):
            with self.subTest(name=name):
                plan, _, after = after_and_before()
                next(secret for secret in after["secret"]
                     if secret["name"].startswith(name))["identity"] = "/attacker"
                self.assert_rejected_without_leak(plan)

    def test_rejects_missing_or_ambiguous_existing_uai(self):
        for identity in (None, [], [{"type": "SystemAssigned"}],
                         [{"type": "UserAssigned", "identity_ids": []}],
                         [{"type": "UserAssigned", "identity_ids": ["/uai", "/another"]}]):
            with self.subTest(identity=identity):
                plan, before, after = after_and_before()
                if identity is None:
                    before.pop("identity")
                    after.pop("identity")
                else:
                    before["identity"] = copy.deepcopy(identity)
                    after["identity"] = copy.deepcopy(identity)
                self.assert_rejected_without_leak(plan)


if __name__ == "__main__":
    unittest.main()
