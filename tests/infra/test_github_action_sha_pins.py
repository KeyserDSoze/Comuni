"""Security P0 #76: all CI/release GitHub Actions must use reviewed commit SHA.

Repointing a vetted action to a different commit requires an explicit
security review, contract update, ADR and a full 7/7 CI on main.
"""
from collections import Counter
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = {
    "ci.yml": (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"),
    "deploy.yml": (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8"),
}
# Tag refs verified via GitHub API, annotated tags dereferenced to commit.
REVIEWED = {
    "actions/checkout": "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/setup-dotnet": "26b0ec14cb23fa6904739307f278c14f94c95bf1",
    "actions/setup-node": "a0853c24544627f65ddf259abe73b1d18a591444",
    "hashicorp/setup-terraform": "dfe3c3f87815947d99a8997f908cb6525fc44e9e",
    "azure/login": "a641126d1b8aa4d1fa005f4f92df94a3a4c4c906",
    "github/codeql-action/init": "33d7b85da1a04171e211befe2c739303b9a4c066",
    "github/codeql-action/analyze": "33d7b85da1a04171e211befe2c739303b9a4c066",
    "aquasecurity/setup-trivy": "81e514348e19b6112ce2a7e3ecbafe19c1e1f567",
    "actions/attest": "1e69f48acb82d1966a394da916b4c1698aa569d6",
}
EXPECTED = {
    "ci.yml": {
        "actions/checkout": 6,
        "actions/setup-dotnet": 3,
        "actions/setup-node": 2,
        "hashicorp/setup-terraform": 1,
        "github/codeql-action/init": 1,
        "github/codeql-action/analyze": 1,
    },
    "deploy.yml": {
        "actions/checkout": 1,
        "azure/login": 3,
        "hashicorp/setup-terraform": 1,
        "aquasecurity/setup-trivy": 1,
        "actions/attest": 2,
    },
}
USES = re.compile(r"^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*(\S+)[^\n]*$",
                  flags=re.MULTILINE)
ACTION_REF = re.compile(r"([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)@([0-9a-f]{40})\Z")


def checked_uses(text):
    seen = Counter()
    for occurrence in USES.finditer(text):
        value = occurrence.group(1)
        result = ACTION_REF.fullmatch(value)
        if result is None:
            raise ValueError("unreviewed action reference: must be full SHA")
        action, sha = result.groups()
        if REVIEWED.get(action) != sha:
            raise ValueError("unreviewed GitHub Action source/commit")
        seen[action] += 1
    return dict(seen)


class ImmutableActionsContractTests(unittest.TestCase):
    def test_ci_and_release_use_only_reviewed_immutable_commits(self):
        for name, content in WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertEqual(EXPECTED[name], checked_uses(content),
                                 "removed or injected GitHub Action")

    def test_refuses_mutable_tags_short_hashes_unknown_actions_and_docker(self):
        for untrusted in (
            "actions/checkout@v4",
            "actions/checkout@main",
            "actions/checkout@11d5960",
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677263",
            "evil/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "docker://alpine:3.21",
            "./.github/actions/custom",
            "$" + "{{ vars.ACTION_REF }}",
            "Azure/login@7184910d9eb2b1c5e48f7073824a90609bb9b6d6",
            "github/codeql-action/init@5895b2c9be147bc7f1c75ce72c5cb577febb1907",
            "actions/checkout@11d5960a326750d5838078e36cf38b85af6772620",
        ):
            with self.subTest(ref=untrusted):
                with self.assertRaises(ValueError):
                    checked_uses("  - uses: " + untrusted + "\n")

    def test_valid_action_without_exact_reviewed_coverage_fails(self):
        work = "ci.yml"
        for action in ("actions/checkout", "actions/setup-node"):
            with self.subTest(action=action):
                original = WORKFLOWS[work]
                reference = action + "@" + REVIEWED[action]
                self.assertIn(reference, original)
                with self.assertRaises(ValueError):
                    checked_uses(original.replace(reference, action + "@v4", 1))
                removed = "".join(
                    line for line in original.splitlines(keepends=True)
                    if reference not in line
                )
                self.assertNotEqual(EXPECTED[work], checked_uses(removed))
        self.assertEqual(
            {"actions/checkout": 1},
            checked_uses(
                "steps:\n  - uses : actions/checkout@" +
                REVIEWED["actions/checkout"] + " # reviewed v5\n",
            ),
        )

    def test_node24_checkout_and_terraform_are_pinned_in_every_job(self):
        # Verified upstream Git tag commits, whose action.yml runtime is node24.
        checkout = "actions/checkout@" + REVIEWED["actions/checkout"]
        terraform = "hashicorp/setup-terraform@" + REVIEWED["hashicorp/setup-terraform"]
        self.assertEqual(7, sum(text.count("uses: " + checkout)
                                for text in WORKFLOWS.values()))
        self.assertEqual(2, sum(text.count("uses: " + terraform)
                                for text in WORKFLOWS.values()))
        for name, workflow in WORKFLOWS.items():
            with self.subTest(workflow=name):
                self.assertIn(checkout + " # v5", workflow)
                self.assertIn(terraform + " # v4", workflow)
                self.assertNotIn("actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                                 workflow)
                self.assertNotIn("hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd",
                                 workflow)

    def test_node24_setup_dotnet_node_and_azure_login_all_pinned(self):
        # SHA/tag verified using upstream Git refs and action.yml runtime node24.
        expected = {
            "actions/setup-dotnet": (3, 0, "v5"),
            "actions/setup-node": (2, 0, "v5"),
            "azure/login": (0, 3, "v3"),
        }
        for action, (ci_count, deploy_count, major) in expected.items():
            with self.subTest(action=action):
                value = action + "@" + REVIEWED[action] + " # " + major
                self.assertEqual(ci_count, WORKFLOWS["ci.yml"].count(value))
                self.assertEqual(deploy_count, WORKFLOWS["deploy.yml"].count(value))
        for workflow in WORKFLOWS.values():
            for old in (
                "actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9",
                "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
                "azure/login@7184910d9eb2b1c5e48f7073824a90609bb9b6d6",
            ):
                self.assertNotIn(old, workflow)

    def test_no_mixed_codeql_digests_or_unreviewed_release_login(self):
        self.assertEqual(REVIEWED["github/codeql-action/init"],
                         REVIEWED["github/codeql-action/analyze"])
        self.assertNotIn("azure/login", EXPECTED["ci.yml"])
        self.assertEqual(3, EXPECTED["deploy.yml"]["azure/login"])
        self.assertEqual(2, EXPECTED["deploy.yml"]["actions/attest"])


if __name__ == "__main__":
    unittest.main()
