"""TDD supply-chain contracts for deterministic workspace installs (#30).

CI executes this file as part of tests/infra. These tests intentionally fail
until the npm-generated lockfile and matching CI/Docker changes are committed.
"""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "package-lock.json"
ROOT_PACKAGE = ROOT / "package.json"
WORKSPACE_PACKAGE = ROOT / "src/frontend/package.json"
CI_FILE = ROOT / ".github/workflows/ci.yml"
DOCKER_FILE = ROOT / "Dockerfile"
ADR = ROOT / "adr/0024-reproducible-npm-workspace.md"


class ReproducibleNpmWorkspaceTests(unittest.TestCase):
    def test_root_lockfile_covers_exact_root_and_frontend_workspace(self):
        self.assertTrue(LOCK.is_file(), "Commit npm-generated root package-lock.json")
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        root = json.loads(ROOT_PACKAGE.read_text(encoding="utf-8"))
        frontend = json.loads(WORKSPACE_PACKAGE.read_text(encoding="utf-8"))
        self.assertEqual(root["name"], lock["name"])
        self.assertGreaterEqual(lock["lockfileVersion"], 3)
        self.assertEqual(["src/frontend"], root["workspaces"])
        self.assertEqual(root["workspaces"], lock["packages"][""]["workspaces"])
        self.assertEqual(frontend["name"], lock["packages"]["src/frontend"]["name"])
        self.assertEqual(frontend["dependencies"],
                         lock["packages"]["src/frontend"]["dependencies"])
        self.assertEqual(frontend["devDependencies"],
                         lock["packages"]["src/frontend"]["devDependencies"])
        self.assertEqual(
            {"resolved": "src/frontend", "link": True},
            lock["packages"]["node_modules/@comuni/frontend"],
        )
        self.assertGreater(
            len(lock["packages"]), 100,
            "Lockfile should contain the resolved dependency graph, not a stub",
        )

    def test_installers_fail_if_lockfile_and_manifests_disagree(self):
        ci = CI_FILE.read_text(encoding="utf-8")
        self.assertIn("npm ci --no-audit --no-fund", ci)
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", ci)
        self.assertIn("npm audit --omit=dev --audit-level=high", ci)
        self.assertNotRegex(ci, r"npm install(?:\\s|\\s*--)")
        self.assertNotIn("npm audit fix", ci)
        self.assertNotIn("continue-on-error: true", ci)
        self.assertIn("npm ci --no-audit --no-fund", DOCKER_FILE.read_text(encoding="utf-8"))

    def test_docker_uses_root_lockfile_and_preserves_workspace_build(self):
        docker = DOCKER_FILE.read_text(encoding="utf-8")
        self.assertIn("COPY package.json package-lock.json ./", docker)
        self.assertIn("COPY src/frontend/package.json ./src/frontend/package.json", docker)
        self.assertIn("COPY src/frontend/ ./src/frontend/", docker)
        self.assertIn("npm run build --workspace @comuni/frontend", docker)
        self.assertIn("/web/src/frontend/dist", docker)
        self.assertNotIn("RUN npm install", docker)
        self.assertTrue(ADR.is_file(), "Document lockfile ownership and update procedure")


if __name__ == "__main__":
    unittest.main()
