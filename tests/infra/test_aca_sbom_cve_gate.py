"""RED-first tests: signed SPDX SBOM + fail-closed container CVE gate (#67).

No Azure or GitHub access. Local scanner JSON, SPDX and fake gh output are
synthetic; gh attestation verify does the cryptographic work in real deployment.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_staged_rollout import SOURCE_COMMIT_SHA, SOURCE_IMAGE_DIGEST, MANAGED_REGISTRY

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts/azure/check-image-sbom-scan.py"
VERIFY = ROOT / "scripts/azure/verify-image-sbom-attestation.py"
WORKFLOW = (ROOT / ".github/workflows/deploy.yml").read_text()
IMAGE = MANAGED_REGISTRY + "/comuni@" + SOURCE_IMAGE_DIGEST
PREDICATE = "https://spdx.dev/Document/v2.3"
SENTINEL = "private-token-should-never-be-in-cli-output"
USE_DEFAULT = object()


def trivy_report():
    return {
        "SchemaVersion": 2, "ArtifactName": IMAGE,
        "ArtifactType": "container_image",
        "Results": [
            {"Target": "comuni (debian 13)", "Class": "os-pkgs",
             "Type": "debian", "Packages": [{"Name": "base-files"}],
             "Vulnerabilities": []},
            {"Target": "Comuni.Api.dll", "Class": "lang-pkgs",
             "Type": "dotnet-core", "Packages": [{"Name": "Npgsql"}],
             "Vulnerabilities": []},
        ],
    }


def spdx_document():
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "documentNamespace": "https://example.test/spdx/comuni-ci",
        "name": "Comuni OCI SBOM", "creationInfo": {
            "created": "2026-11-16T00:00:00Z", "creators": ["Tool: Trivy-test"],
        },
        "packages": [
            {"SPDXID": "SPDXRef-Package-1", "name": "base-files"},
            {"SPDXID": "SPDXRef-Package-2", "name": "Npgsql"},
        ],
    }


def scan(scan=USE_DEFAULT, sbom=USE_DEFAULT, image=IMAGE, digest=SOURCE_IMAGE_DIGEST,
         missing_scan=False, missing_sbom=False, malformed_scan=False):
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        scan_file, sbom_file = d / "scan.json", d / "sbom.spdx.json"
        if not missing_scan:
            scan_file.write_text(
                "{bad" if malformed_scan else json.dumps(trivy_report() if scan is USE_DEFAULT else scan),
                encoding="utf-8")
        if not missing_sbom:
            sbom_file.write_text(json.dumps(spdx_document() if sbom is USE_DEFAULT else sbom),
                                 encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(CHECK),
             "--image", image, "--candidate-image-digest", digest,
             "--scan-report", str(scan_file), "--sbom", str(sbom_file)],
            capture_output=True, text=True, timeout=12, check=False,
        )
        return result


def signed_sbom(*, name=MANAGED_REGISTRY + "/comuni",
                digest=SOURCE_IMAGE_DIGEST.split(":")[1],
                predicate_type=PREDICATE, packages=None):
    return [{"verificationResult": {"statement": {
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
        "predicate": spdx_document() if packages is None else packages,
    }}}]


FAKE_GH = String = '''#!/usr/bin/env python3
import json
import os
import sys

expected = [
    "attestation", "verify", "oci://" + os.environ["EXPECTED_IMAGE"],
    "--repo", "KeyserDSoze/Comuni",
    "--signer-workflow", "KeyserDSoze/Comuni/.github/workflows/deploy.yml",
    "--source-ref", "refs/heads/main",
    "--source-digest", os.environ["EXPECTED_SHA"],
    "--predicate-type", "https://spdx.dev/Document/v2.3",
    "--deny-self-hosted-runners", "--format", "json",
]
with open(os.environ["FAKE_GH_CALLS"], "a", encoding="utf-8") as file:
    file.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1:] != expected or not os.environ.get("GH_TOKEN"):
    sys.exit(41)
if os.environ["GH_EXIT"] != "0":
    sys.stderr.write(os.environ["GH_STDERR"])
    sys.exit(int(os.environ["GH_EXIT"]))
if os.environ["GH_OUTPUT"] == "__OVERSIZED__":
    print(" " * 180000)
else:
    print(os.environ["GH_OUTPUT"])
'''


def verify(raw=None, *, image=IMAGE, digest=SOURCE_IMAGE_DIGEST,
           sha=SOURCE_COMMIT_SHA, repo="KeyserDSoze/Comuni",
           source_ref="refs/heads/main", host=MANAGED_REGISTRY,
           gh_exit=0, token="fake-test-token"):
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        exe = d / "gh"
        exe.write_text(FAKE_GH, encoding="utf-8")
        exe.chmod(0o700)
        calls = d / "calls.jsonl"
        env = {**os.environ,
            "PATH": str(d) + os.pathsep + os.environ.get("PATH", ""),
            "EXPECTED_IMAGE": IMAGE, "EXPECTED_SHA": SOURCE_COMMIT_SHA,
            "FAKE_GH_CALLS": str(calls), "GH_EXIT": str(gh_exit),
            "GH_STDERR": SENTINEL, "GH_TOKEN": token,
            "GH_OUTPUT": json.dumps(signed_sbom()) if raw is None else raw,
        }
        result = subprocess.run(
            [sys.executable, str(VERIFY),
             "--image", image, "--candidate-image-digest", digest,
             "--source-commit-sha", sha, "--registry-host", host,
             "--repository", repo, "--source-ref", source_ref],
            env=env, capture_output=True, text=True, check=False, timeout=12)
        argv = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result, argv


class ImageSBOMGateTests(unittest.TestCase):
    def rejected(self, **kwargs):
        result = scan(**kwargs)
        self.assertNotEqual(0, result.returncode, "unscanned/untrusted image passed")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("CVE-", result.stdout + result.stderr)
        self.assertNotIn("sha256:", result.stdout + result.stderr)

    def test_clean_report_with_package_coverage_and_spdx_passes(self):
        result = scan()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def test_rejects_unavailable_or_malformed_scan_and_sbom(self):
        self.rejected(missing_scan=True)
        self.rejected(missing_sbom=True)
        self.rejected(malformed_scan=True)
        for report in ({}, [], None, "invalid",
                       {"Results": []},
                       {**trivy_report(), "Results": []},
                       {**trivy_report(), "ArtifactName": SENTINEL},
                       {**trivy_report(), "ArtifactType": "filesystem"},
                       {**trivy_report(), "SchemaVersion": 99}):
            with self.subTest(shape=str(type(report))):
                self.rejected(scan=report)

    def test_rejects_high_critical_or_unknown_vulnerabilities_even_when_unfixed(self):
        for sev in ("HIGH", "CRITICAL", "UNKNOWN", "unclassified"):
            with self.subTest(severity=sev):
                report = trivy_report()
                report["Results"][0]["Vulnerabilities"] = [
                    {"VulnerabilityID": "CVE-2026-99999",
                     "Severity": sev, "FixedVersion": ""}]
                self.rejected(scan=report)
        for vuln in (None, "not-an-object", {"VulnerabilityID": SENTINEL}):
            report = trivy_report()
            report["Results"][0]["Vulnerabilities"] = [vuln]
            self.rejected(scan=report)

    def test_low_and_medium_findings_are_allowed_under_explicit_policy(self):
        report = trivy_report()
        report["Results"][0]["Vulnerabilities"] = [
            {"VulnerabilityID": "CVE-2026-1234", "Severity": "LOW"},
            {"VulnerabilityID": "CVE-2026-5678", "Severity": "MEDIUM"},
        ]
        self.assertEqual(0, scan(scan=report).returncode)

    def test_rejects_missing_coverage_and_invalid_packages(self):
        for change in ("no_results", "empty_pkgs", "no_pkg_key", "empty_target",
                       "unknown_class", "non_dict", "vulns_not_list"):
            with self.subTest(change=change):
                report = trivy_report()
                entry = report["Results"][0]
                if change == "no_results":
                    report.pop("Results")
                elif change == "empty_pkgs":
                    entry["Packages"] = []
                elif change == "no_pkg_key":
                    entry.pop("Packages")
                elif change == "empty_target":
                    entry["Target"] = ""
                elif change == "unknown_class":
                    entry["Class"] = "secrets"
                elif change == "non_dict":
                    report["Results"][0] = SENTINEL
                else:
                    entry["Vulnerabilities"] = None
                self.rejected(scan=report)

    def test_sbom_must_be_nonempty_spdx_2_3_json(self):
        for kind in ("wrong_version", "empty_packages", "missing_packages",
                     "wrong_license", "missing_namespace", "bad_package",
                     "not_a_document"):
            with self.subTest(kind=kind):
                doc = spdx_document()
                if kind == "wrong_version":
                    doc["spdxVersion"] = "SPDX-2.2"
                elif kind == "empty_packages":
                    doc["packages"] = []
                elif kind == "missing_packages":
                    doc.pop("packages")
                elif kind == "wrong_license":
                    doc["dataLicense"] = SENTINEL
                elif kind == "missing_namespace":
                    doc["documentNamespace"] = ""
                elif kind == "bad_package":
                    doc["packages"][0] = {"name": ""}
                else:
                    doc = {"bomFormat": "CycloneDX", "components": [{"name": "base-files"}]}
                self.rejected(sbom=doc)

    def test_digest_and_image_must_match(self):
        self.rejected(image=MANAGED_REGISTRY + "/comuni:latest")
        self.rejected(image="attacker.azurecr.io/comuni@" + SOURCE_IMAGE_DIGEST)
        self.rejected(digest="sha256:" + "b" * 64)
        self.rejected(digest=SENTINEL)


class SignedSBOMTests(unittest.TestCase):
    def rejected(self, **kwargs):
        result, _ = verify(**kwargs)
        self.assertNotEqual(0, result.returncode, "unverified signed SBOM passed")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn("sha256:", result.stdout + result.stderr)

    def test_signed_spdx_for_correct_source_ref_and_subject_passes(self):
        result, calls = verify()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(calls))
        self.assertEqual("oci://" + IMAGE, calls[0][2])
        self.assertEqual("", result.stdout)

    def test_untrusted_github_attestations_fail_closed(self):
        self.rejected(token="")
        self.rejected(gh_exit=42)
        self.rejected(raw="")
        self.rejected(raw="[]")
        self.rejected(raw="{malformed")
        self.rejected(raw="__OVERSIZED__")
        self.rejected(raw=json.dumps([{}]))
        self.rejected(raw=json.dumps(signed_sbom(name="attacker.azurecr.io/comuni")))
        self.rejected(raw=json.dumps(signed_sbom(digest="b" * 64)))
        self.rejected(raw=json.dumps(signed_sbom(predicate_type="https://slsa.dev/provenance/v1")))
        self.rejected(raw=json.dumps(signed_sbom(packages={"spdxVersion": "SPDX-2.3", "packages": []})))
        self.rejected(raw=json.dumps(signed_sbom(packages={"spdxVersion": "SPDX-2.2", "packages": []})))

    def test_untrusted_repository_ref_image_and_sha_fail_closed(self):
        for delta in (
            {"repo": "other/Repo"}, {"source_ref": "refs/heads/dev"},
            {"sha": SOURCE_COMMIT_SHA[:12] + "f" * 28},
            {"sha": SOURCE_COMMIT_SHA.upper()},
            {"host": "evil.azurecr.io"},
            {"image": MANAGED_REGISTRY + "/comuni:" + SOURCE_COMMIT_SHA},
            {"image": MANAGED_REGISTRY + "/comuni@sha256:" + "b" * 64},
            {"digest": "sha256:" + "b" * 64},
        ):
            with self.subTest(change=next(iter(delta))):
                self.rejected(**delta)

    def test_workflow_has_scan_sbom_signed_attestation_and_gates_before_plan(self):
        self.assertIn("aquasecurity/setup-trivy@", WORKFLOW)
        self.assertIn("scripts/azure/check-image-sbom-scan.py", WORKFLOW)
        self.assertIn("trivy image", WORKFLOW)
        self.assertIn("--format spdx-json", WORKFLOW)
        self.assertIn('"$TF_VAR_image"', WORKFLOW)
        self.assertIn("sbom-path: ${{ env.CANDIDATE_SBOM_PATH }}", WORKFLOW)
        self.assertIn("subject-digest: ${{ env.CANDIDATE_IMAGE_DIGEST }}", WORKFLOW)
        self.assertIn("scripts/azure/verify-image-sbom-attestation.py", WORKFLOW)
        self.assertLess(WORKFLOW.index("scripts/azure/check-image-sbom-scan.py"),
                        WORKFLOW.index("sbom-path: ${{ env.CANDIDATE_SBOM_PATH }}"))
        self.assertLess(WORKFLOW.index("sbom-path: ${{ env.CANDIDATE_SBOM_PATH }}"),
                        WORKFLOW.index("scripts/azure/verify-image-sbom-attestation.py"))
        self.assertLess(WORKFLOW.index("scripts/azure/verify-image-sbom-attestation.py"),
                        WORKFLOW.index("terraform -chdir=infra plan"))
        self.assertNotIn("--ignore-unfixed", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
