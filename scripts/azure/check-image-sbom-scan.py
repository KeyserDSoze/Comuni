#!/usr/bin/env python3
"""Fail-closed package coverage, CVE policy and SPDX SBOM gate for ACA.

Consumes Trivy JSON and SPDX 2.3 generated from the SAME immutable OCI
image. No vulnerability IDs, image URI, dependency names or scanner output
are printed. The scanner must run successfully separately before this gate.
"""
import argparse
import json
import re
import sys
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[a-z0-9]{5,50}\.azurecr\.io/comuni@sha256:[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 15 * 1024 * 1024
BLOCKED = frozenset(("HIGH", "CRITICAL", "UNKNOWN"))
KNOWN = BLOCKED | {"LOW", "MEDIUM", "NONE"}


class ImageRejected(Exception):
    """Only constant messages, never strings from scanner artifacts."""


def require(value, message):
    if not value:
        raise ImageRejected(message)


def safe_json(path):
    p = Path(path)
    require(p.is_file() and not p.is_symlink() and
            p.stat().st_size <= MAX_JSON_BYTES,
            "missing, unsafe or oversized image security report")
    with p.open("rb") as stream:
        payload = stream.read(MAX_JSON_BYTES + 1)
    require(len(payload) <= MAX_JSON_BYTES,
            "oversized image security report")
    return json.loads(payload)


def check_scan(report, image):
    require(isinstance(report, dict) and
            report.get("SchemaVersion") == 2 and
            report.get("ArtifactType") == "container_image" and
            report.get("ArtifactName") == image,
            "image scanner report does not match the approved OCI manifest")
    results = report.get("Results")
    require(isinstance(results, list) and bool(results),
            "image vulnerability analysis lacks package coverage")
    package_count = 0
    for result in results:
        require(isinstance(result, dict) and
                isinstance(result.get("Target"), str) and result["Target"] and
                result.get("Class") in ("os-pkgs", "lang-pkgs"),
                "invalid package scanner result")
        packages = result.get("Packages")
        require(isinstance(packages, list) and bool(packages),
                "package scanner returned missing or empty package inventory")
        for package in packages:
            require(isinstance(package, dict) and
                    isinstance(package.get("Name"), str) and package["Name"],
                    "invalid discovered package record")
        package_count += len(packages)
        findings = result.get("Vulnerabilities", [])
        require(isinstance(findings, list), "malformed vulnerability findings")
        for finding in findings:
            require(isinstance(finding, dict) and
                    isinstance(finding.get("Severity"), str) and
                    finding["Severity"] in KNOWN and
                    isinstance(finding.get("VulnerabilityID"), str) and
                    bool(finding["VulnerabilityID"]),
                    "incomplete or unknown vulnerability classification")
            require(finding["Severity"] not in BLOCKED,
                    "blocked container vulnerability severity detected")
    require(package_count > 0,
            "image vulnerability analysis lacks discovered packages")


def check_spdx(sbom):
    require(isinstance(sbom, dict) and
            sbom.get("spdxVersion") == "SPDX-2.3" and
            sbom.get("SPDXID") == "SPDXRef-DOCUMENT" and
            sbom.get("dataLicense") == "CC0-1.0" and
            isinstance(sbom.get("name"), str) and bool(sbom["name"]) and
            isinstance(sbom.get("documentNamespace"), str)
            and bool(sbom["documentNamespace"]),
            "missing or invalid SPDX 2.3 SBOM document")
    packages = sbom.get("packages")
    require(isinstance(packages, list) and bool(packages),
            "signed SBOM must contain discovered packages")
    for package in packages:
        require(isinstance(package, dict) and
                isinstance(package.get("name"), str) and package["name"] and
                isinstance(package.get("SPDXID"), str)
                and package["SPDXID"].startswith("SPDXRef-"),
                "invalid SPDX package record")


def main():
    parser = argparse.ArgumentParser(
        description="Validate Trivy CVEs and SPDX SBOM before signed ACA stage")
    parser.add_argument("--image", required=True)
    parser.add_argument("--candidate-image-digest", required=True)
    parser.add_argument("--scan-report", required=True)
    parser.add_argument("--sbom", required=True)
    args = parser.parse_args()
    try:
        require(bool(DIGEST.fullmatch(args.candidate_image_digest)) and
                bool(IMAGE.fullmatch(args.image)) and
                args.image.endswith("/comuni@" + args.candidate_image_digest),
                "unapproved OCI digest image")
        check_scan(safe_json(args.scan_report), args.image)
        check_spdx(safe_json(args.sbom))
    except (ImageRejected, OSError, ValueError, TypeError, UnicodeError,
            json.JSONDecodeError) as error:
        reason = str(error) if isinstance(error, ImageRejected) else "invalid scanner or SBOM data"
        print("Image security gate rejected: " + reason, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
