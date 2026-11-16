"""TDD RED: no legacy PostgreSQL ACA secret references in ANY stored revision.

Only a fake Azure CLI supplies synthetic metadata. The actual preflight must
make no secret read, state write, Terraform apply or revision mutation.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "scripts/azure/preflight-legacy-postgres-retirement.py"
TERRAFORM = (ROOT / "infra/main.tf").read_text()
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
APP = "comuni-itn-001-app"
GROUP = "comuni-itn-001-rg"
LEGACY = "postgres-connection"
NEW = "pg-" + "d" * 16
SENTINEL = "synthetic-private-connection-do-not-echo"


def revision(suffix, *, active=True, secret_ref=NEW, additional_env=None):
    env = [{"name": "ConnectionStrings__Default", "secretRef": secret_ref}]
    if additional_env:
        env.extend(additional_env)
    return {
        "name": APP + "-" + suffix,
        "properties": {
            "active": active,
            "template": {"containers": [{"name": "comuni", "env": env}]},
        },
    }


def healthy_revisions():
    return [revision("r123456789abc"), revision("r123456789abd", active=False)]


MOCK_AZ = r"""#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["AZ_CALL_LOG"], "a", encoding="utf-8") as f:
    f.write(json.dumps(args) + "\n")
if "--only-show-errors" not in args or "--output" not in args:
    sys.exit(7)
if args[:3] == ["containerapp", "revision", "list"]:
    if os.environ.get("FAIL_MODE") == "list":
        print("synthetic-private-connection-do-not-echo", file=sys.stderr)
        sys.exit(8)
    if "--all" not in args:
        # Without --all the old inactive revision would be silently hidden.
        print(json.dumps([r for r in json.loads(os.environ["AZ_REVISIONS"])
                          if r["properties"]["active"]]))
        sys.exit(0)
    if os.environ.get("FAIL_MODE") == "json":
        print("{not-json")
    else:
        print(os.environ["AZ_REVISIONS"])
elif args[:3] == ["containerapp", "revision", "show"]:
    if os.environ.get("FAIL_MODE") == "show":
        print("synthetic-private-connection-do-not-echo", file=sys.stderr)
        sys.exit(9)
    if "--revision" not in args:
        sys.exit(10)
    name = args[args.index("--revision") + 1]
    items = [r for r in json.loads(os.environ["AZ_REVISIONS"])
             if r.get("name") == name]
    if len(items) != 1:
        sys.exit(11)
    print(json.dumps(items[0]))
else:
    print("unexpected Azure command", file=sys.stderr)
    sys.exit(99)
"""


def execute(revisions=None, *, fail_mode="", app=APP, group=GROUP):
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        fake = folder / "az"
        fake.write_text(MOCK_AZ, encoding="utf-8")
        fake.chmod(0o700)
        log = folder / "calls.jsonl"
        env = {**os.environ,
               "PATH": str(folder) + os.pathsep + os.environ.get("PATH", ""),
               "AZ_CALL_LOG": str(log), "FAIL_MODE": fail_mode,
               "AZ_REVISIONS": json.dumps(healthy_revisions() if revisions is None
                                           else revisions)}
        if not PREFLIGHT.exists():
            return subprocess.CompletedProcess([], 127, "", "preflight missing"), []
        cmd = [sys.executable, str(PREFLIGHT),
               "--app", app, "--resource-group", group]
        result = subprocess.run(cmd, env=env, capture_output=True, text=True,
                                timeout=20, check=False)
        calls = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
        return result, calls


class LegacyPostgresRetirementPreflightTests(unittest.TestCase):
    def assert_rejected(self, revisions=None, **kwargs):
        result, calls = execute(revisions, **kwargs)
        self.assertNotEqual(0, result.returncode, result.stdout)
        for secret in (SENTINEL, LEGACY, NEW, APP + "-r123456789abc"):
            self.assertNotIn(secret, result.stdout + result.stderr)
        return calls

    def test_all_stored_revisions_including_inactive_are_checked_read_only(self):
        result, calls = execute()
        self.assertEqual(0, result.returncode, result.stderr)
        lists = [x for x in calls if x[:3] == ["containerapp", "revision", "list"]]
        shows = [x for x in calls if x[:3] == ["containerapp", "revision", "show"]]
        self.assertEqual(1, len(lists))
        self.assertIn("--all", lists[0])
        self.assertEqual(2, len(shows))
        self.assertEqual({APP+"-r123456789abc", APP+"-r123456789abd"},
                         {x[x.index("--revision") + 1] for x in shows})
        self.assertNotIn(NEW, result.stdout + result.stderr)
        self.assertNotIn(LEGACY, result.stdout + result.stderr)
        self.assertTrue(all(x[:3] in (["containerapp", "revision", "list"],
                                        ["containerapp", "revision", "show"]) for x in calls))
        self.assertTrue(all("--only-show-errors" in x for x in calls))
        self.assertTrue(all("--output" in x and x[x.index("--output") + 1] == "json"
                            for x in calls))

    def test_blocks_old_secret_in_active_inactive_and_other_environment_names(self):
        revisions = healthy_revisions()
        revisions[0]["properties"]["template"]["containers"][0]["env"][0]["secretRef"] = LEGACY
        self.assert_rejected(revisions)
        revisions = healthy_revisions()
        revisions[1]["properties"]["template"]["containers"][0]["env"][0]["secretRef"] = LEGACY
        self.assert_rejected(revisions)
        revisions = healthy_revisions()
        revisions[1]["properties"]["template"]["containers"][0]["env"].append(
            {"name": "SomeOtherConnection", "secretRef": LEGACY}
        )
        self.assert_rejected(revisions)

    def test_blocks_missing_malformed_inline_and_duplicated_db_connections(self):
        cases = []
        for ref in ("tenant-proof-key", "pg-notversioned", "", "postgres-connection",
                    "PG-" + "d" * 16, "pg-" + "d" * 16 + "e"):
            revisions = healthy_revisions()
            revisions[0]["properties"]["template"]["containers"][0]["env"][0]["secretRef"] = ref
            cases.append(revisions)
        revisions = healthy_revisions()
        revisions[0]["properties"]["template"]["containers"][0]["env"][0] = {
            "name": "ConnectionStrings__Default", "value": SENTINEL}
        cases.append(revisions)
        revisions = healthy_revisions()
        revisions[0]["properties"]["template"]["containers"][0]["env"].append(
            {"name": "ConnectionStrings__Default", "secretRef": NEW})
        cases.append(revisions)
        revisions = healthy_revisions()
        revisions[1]["properties"]["template"]["containers"][0]["env"].clear()
        cases.append(revisions)
        revisions = healthy_revisions()
        revisions[0]["properties"]["template"]["containers"].append({
            "name": "rogue-sidecar",
            "env": [{"name": "Other", "secretRef": LEGACY}]})
        cases.append(revisions)
        for data in cases:
            with self.subTest(index=cases.index(data)):
                self.assert_rejected(data)

    def test_blocks_incomplete_inconsistent_or_ambiguous_revision_inventory(self):
        cases = [
            [],
            [revision("r123456789abd", active=False)],
            [revision("r123456789abc"), revision("r123456789abc")],
            [revision("r123456789abc"), {"name": APP+"-r123456789abd"}],
            [revision("r123456789abc"), {"name": "other-app-r123456789abd",
                                         "properties": {"active": False}}],
            [revision("r123456789abc"), None],
            [revision("r123456789abc", active="yes")],
        ]
        for items in cases:
            with self.subTest(index=cases.index(items)):
                self.assert_rejected(items)

    def test_blocks_cli_failure_invalid_json_and_invalid_request_arguments(self):
        for mode in ("list", "show", "json"):
            self.assert_rejected(fail_mode=mode)
        for app, group in (
            ("bad;app", GROUP), ("", GROUP), (APP, "rg;rm"),
            ("other-app", GROUP), (APP, ""),
        ):
            self.assert_rejected(app=app, group=group)

    def test_no_mutating_azure_or_terraform_operations_are_in_the_tool(self):
        self.assertTrue(PREFLIGHT.is_file(), "RED: missing metadata-only preflight script")
        contents = PREFLIGHT.read_text()
        self.assertIn("containerapp", contents)
        self.assertIn("revision", contents)
        self.assertIn("--all", contents)
        self.assertNotIn("secret list", contents)
        self.assertNotIn("keyvault secret show", contents)
        self.assertNotIn("terraform apply", contents)
        self.assertNotIn("terraform state rm", contents)
        self.assertNotIn("revision deactivate", contents)
        self.assertNotIn("revision restart", contents)
        self.assertNotIn("secret delete", contents)
        self.assertNotIn("set -x", contents)
        self.assertIn('name                = "postgres-connection"', TERRAFORM)
        self.assertIn('key_vault_secret_id = azurerm_key_vault_secret.postgres_connection.versionless_id', TERRAFORM)
        self.assertIn("terraform -chdir=infra apply", WORKFLOW)
        self.assertNotIn("preflight-legacy-postgres-retirement.py", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
