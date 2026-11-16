"""P0 #77: only vetted OCI base-image indexes in the combined Dockerfile.

RED first: replace the empty reviewed-digest placeholders ONLY after reading
the complete manifest index digests from their authoritative registries.
The test also guards fixed linux/amd64 builds in CI and deploy.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
FROM = re.compile(r"^FROM\s+(\S+)(?:\s+AS\s+([a-z][a-z0-9]*))?\s*$", re.I)
APPROVED = (
    ("mcr.microsoft.com/dotnet/sdk:10.0", "", "backend"),
    ("node:22-alpine", "", "frontend"),
    ("mcr.microsoft.com/dotnet/aspnet:10.0", "", None),
)


def check_bases(content):
    stages = []
    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if re.match(r"^(?:ARG|ONBUILD)\s", trimmed, re.I):
            raise ValueError("Dockerfile may not inject or redefine base images")
        if re.match(r"^FROM\b", trimmed, re.I):
            match = FROM.fullmatch(trimmed)
            if not match:
                raise ValueError("invalid Docker FROM grammar")
            stages.append(match.groups())
    if len(stages) != 3:
        raise ValueError("unexpected number of Docker build stages")
    for (ref, alias), (repository_tag, digest, expected_alias) in zip(stages, APPROVED):
        if not SHA256.fullmatch(digest):
            raise ValueError("approved upstream OCI index digest is missing")
        if ref != repository_tag + "@" + digest or alias != expected_alias:
            raise ValueError("unreviewed base-image source, tag or digest")
    return stages


class ImmutableDockerBaseContract(unittest.TestCase):
    def test_reviewed_manifest_index_digests_are_complete_and_unique(self):
        self.assertEqual(3, len(APPROVED))
        self.assertEqual(3, len({name for name, _, _ in APPROVED}))
        for image, digest, stage in APPROVED:
            with self.subTest(base=image):
                self.assertRegex(digest, SHA256)
                self.assertNotEqual(digest, "sha256:" + "0" * 64)

    def test_dockerfile_uses_only_three_reviewed_immutable_base_images(self):
        bases = check_bases(DOCKERFILE)
        self.assertEqual(["backend", "frontend", None],
                         [alias for _, alias in bases])

    def test_refuses_unpinned_malformed_replaced_images_and_dockerfile_injection(self):
        examples = (
            "FROM mcr.microsoft.com/dotnet/sdk:10.0 AS backend",
            "FROM node:22-alpine AS frontend",
            "FROM mcr.microsoft.com/dotnet/aspnet:10.0",
            "FROM node:22-alpine@sha256:123 AS frontend",
            "FROM evil.example/dotnet/sdk:10.0@sha256:" + "a" * 64 + " AS backend",
            "FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:" + "A" * 64 + " AS backend",
            "FROM mcr.microsoft.com/dotnet/sdk:11.0@sha256:" + "a" * 64 + " AS backend",
            "FROM --platform=$TARGETPLATFORM node:22-alpine@sha256:" + "b" * 64 + " AS frontend",
            "ARG BASE_IMAGE=node:22-alpine",
            "ONBUILD FROM node:22-alpine",
        )
        for bad in examples:
            with self.subTest(mutation=bad[:48]):
                with self.assertRaises(ValueError):
                    check_bases(DOCKERFILE + "\n" + bad + "\n")
        self.assertRaises(ValueError, check_bases, DOCKERFILE.replace(
            "FROM node:22-alpine", "FROM malicious.example/node:22-alpine", 1))

    def test_both_docker_build_paths_use_fixed_amd64_and_no_base_override(self):
        self.assertIn("docker build --platform linux/amd64 -t comuni:ci .", CI)
        self.assertIn('docker build --platform linux/amd64 -t "$TAG" .', DEPLOY)
        for workflow in (CI, DEPLOY):
            self.assertNotIn("docker build --pull", workflow)
            self.assertNotIn("docker build --build-arg BASE_IMAGE", workflow)
            self.assertNotIn("docker build --platform $", workflow)


if __name__ == "__main__":
    unittest.main()
