"""RED-first: staging ACA must not downgrade OIDC or accept ambiguous .NET config.

Only synthetic plans/tokens. The gate consumes sensitive Terraform JSON via stdin;
test error responses must not expose fixture sentinel values.
"""
import unittest

from test_aca_stage_immutable_infrastructure import check
from test_staged_rollout import fixture_plan

SENTINEL = "synthetic-secret-must-never-be-logged"


def plan_and_env():
    plan = fixture_plan()
    env = plan["resource_changes"][0]["change"]["after"]["template"][0]["container"][0]["env"]
    return plan, env


def change(env, name, value=None, secret_name=None):
    target = next(e for e in env if e.get("name") == name)
    target.pop("value", None)
    target.pop("secret_name", None)
    if value is not None:
        target["value"] = value
    if secret_name is not None:
        target["secret_name"] = secret_name


class CandidateOidcEnvironmentTests(unittest.TestCase):
    def reject(self, plan):
        result = check(plan)
        self.assertNotEqual(result.returncode, 0, "unsafe candidate configuration accepted")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_current_production_oidc_plan_is_accepted(self):
        plan, _ = plan_and_env()
        result = check(plan)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_rejects_dev_or_nonproduction_environment(self):
        for value in ("Development", "Testing", "Staging", "", "production ", "Production;Testing"):
            with self.subTest(value=value):
                plan, env = plan_and_env()
                change(env, "ASPNETCORE_ENVIRONMENT", value=value)
                self.reject(plan)

    def test_rejects_missing_or_secret_backed_production_environment(self):
        for kind in ("missing", "secret"):
            with self.subTest(kind=kind):
                plan, env = plan_and_env()
                if kind == "missing":
                    env[:] = [e for e in env if e["name"] != "ASPNETCORE_ENVIRONMENT"]
                else:
                    change(env, "ASPNETCORE_ENVIRONMENT", secret_name="runtime-config")
                self.reject(plan)

    def test_rejects_oidc_mode_downgrade_or_absence(self):
        for value in ("DevelopmentJwt", "None", "oidc", "", " Oidc"):
            with self.subTest(mode=value):
                plan, env = plan_and_env()
                change(env, "Authentication__Mode", value=value)
                self.reject(plan)
        plan, env = plan_and_env()
        env[:] = [e for e in env if e["name"] != "Authentication__Mode"]
        self.reject(plan)

    def test_rejects_untrusted_missing_or_secret_backed_oidc_authority(self):
        for value in ("", "http://idp.example.test", "https://", "idp.example.test",
                      "https://user:pass@idp.example.test", "https://idp.example.test?token=x",
                      "https://idp.example.test/#x"):
            with self.subTest(authority=value):
                plan, env = plan_and_env()
                change(env, "Authentication__Authority", value=value)
                self.reject(plan)
        plan, env = plan_and_env()
        change(env, "Authentication__Authority", secret_name="evil-secret")
        self.reject(plan)
        plan, env = plan_and_env()
        env[:] = [e for e in env if e["name"] != "Authentication__Authority"]
        self.reject(plan)

    def test_rejects_invalid_or_missing_audience(self):
        for value in ("", " ", "\t", "token " + SENTINEL):
            with self.subTest(audience=value):
                plan, env = plan_and_env()
                change(env, "Authentication__Audience", value=value)
                self.reject(plan)
        plan, env = plan_and_env()
        change(env, "Authentication__Audience", secret_name="hidden")
        self.reject(plan)
        plan, env = plan_and_env()
        env[:] = [e for e in env if e["name"] != "Authentication__Audience"]
        self.reject(plan)

    def test_rejects_dotnet_environment_override(self):
        for value in ("Development", "Testing", "Production"):
            with self.subTest(value=value):
                plan, env = plan_and_env()
                env.append({"name": "DOTNET_ENVIRONMENT", "value": value})
                self.reject(plan)

    def test_rejects_duplicate_aliases_even_when_exact_security_entry_exists(self):
        cases = (
            ("authentication__mode", "value", "DevelopmentJwt"),
            ("Authentication:Mode", "value", "DevelopmentJwt"),
            ("AUTHENTICATION__AUTHORITY", "value", "http://evil.example.test"),
            ("authentication:audience", "value", SENTINEL),
            ("ASPNETCORE_environment", "value", "Development"),
            ("connectionstrings__default", "value", "Host=evil;Password=" + SENTINEL),
            ("ConnectionStrings:Default", "value", "Host=evil;Password=" + SENTINEL),
            ("security__tenantproofkey", "value", SENTINEL),
            ("Security:TenantProofKeyId", "value", "legacy"),
            ("RuntimePostgres:ExpectedHost", "value", "evil.postgres.database.azure.com"),
        )
        for name, source, value in cases:
            with self.subTest(name=name):
                plan, env = plan_and_env()
                env.append({"name": name, source: value})
                self.reject(plan)

    def test_rejects_non_sensitive_duplicate_and_malformed_entries(self):
        for entry in (
            {"name": "Storage__AccountName", "value": "a"},
            {"name": "storage__accountname", "value": "b"},
            {"name": "A:B", "value": SENTINEL},
            {"name": "EVIL NAME", "value": SENTINEL},
            {"name": "", "value": SENTINEL},
            {"value": SENTINEL},
            None,
            "not-an-env",
        ):
            with self.subTest(entry=type(entry).__name__):
                plan, env = plan_and_env()
                # Even the first extra Storage__AccountName should pass,
                # until it is duplicated; malformed entries must fail.
                if isinstance(entry, dict) and entry.get("name", "").lower() == "storage__accountname":
                    env.append({"name": "Storage__AccountName", "value": "existing"})
                env.append(entry)
                self.reject(plan)


if __name__ == "__main__":
    unittest.main()
