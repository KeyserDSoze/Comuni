"""RED/GREEN contract tests for dependency auditing and CodeQL (#29).

Run with: python3 -m unittest tests/infra/test_security_scanning.py -v
The workflow is part of the existing required CI, never a silent side task.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
ADR = ROOT / "adr/0023-continuous-security-scanning.md"


class SecurityScanningContracts(unittest.TestCase):
    def test_nuget_audit_fails_closed_for_high_critical_and_missing_feed(self):
        self.assertIn("dependency-audit:", CI)
        self.assertIn("dotnet restore tests/backend/Comuni.Api.Tests/Comuni.Api.Tests.csproj", CI)
        self.assertIn("dotnet restore tests/backend/Comuni.UnitTests/Comuni.UnitTests.csproj", CI)
        for option in (
            "-p:NuGetAudit=true",
            "-p:NuGetAuditMode=all",
            "-p:NuGetAuditLevel=high",
            "-warnaserror:NU1900,NU1903,NU1904",
        ):
            self.assertIn(option, CI)
        self.assertNotIn("NuGetAudit=false", CI)

    def test_npm_production_dependency_audit_is_a_failing_gate(self):
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", CI)
        self.assertIn("npm audit --omit=dev --audit-level=high", CI)
        self.assertNotIn("npm audit fix", CI)
        self.assertNotRegex(CI, r"npm audit[^\n]*\|\| true")

    def test_codeql_analyzes_csharp_and_typescript_with_scoped_permissions(self):
        self.assertIn("codeql:", CI)
        self.assertIn("language: csharp", CI)
        self.assertIn("language: javascript-typescript", CI)
        self.assertIn("github/codeql-action/init@v4", CI)
        self.assertIn("github/codeql-action/analyze@v4", CI)
        self.assertIn("security-events: write", CI)
        self.assertIn("build_mode: manual", CI)
        self.assertIn("build_mode: none", CI)
        self.assertIn("build-mode: ${{ matrix.build_mode }}", CI)
        self.assertIn("dotnet build src/backend/Applications/Api/Comuni.Api.csproj", CI)
        self.assertNotIn("continue-on-error: true", CI)

    def test_ci_runs_scheduled_scans_and_holds_container_on_security_checks(self):
        self.assertIn("schedule:", CI)
        self.assertRegex(CI, r"cron: ['\"][0-9* /,-]+['\"]")
        self.assertIn("branches: [main]", CI)
        self.assertIn("needs: [backend, frontend, dependency-audit, codeql]", CI)
        self.assertTrue(ADR.is_file(), "Architectural decision and limits must be documented")


if __name__ == "__main__":
    unittest.main()
