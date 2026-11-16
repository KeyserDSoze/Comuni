"""RED-first tests for signed OCI provenance before ACA Terraform apply (#66).

No GitHub/Azure access or real credential: a strict fake gh validates the
command's identity policy. These tests verify our gate wiring and fail-closed
handling, NOT Sigstore cryptography (performed by genuine gh at deploy time).
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_staged_rollout import SOURCE_COMMIT_SHA, SOURCE_IMAGE_DIGEST, MANAGED_REGISTRY

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts/azure/verify-image-provenance.py"
DEPLOY = (ROOT / ".github/workflows/deploy.yml").read_text()
REPO = "KeyserDSoze/Comuni"
SIGNER = REPO + "/.github/workflows/deploy.yml"
IMAGE = MANAGED_REGISTRY + "/comuni@" + SOURCE_IMAGE_DIGEST
SENTINEL = "private-authentication-token-never-print"

FAKE_GH = """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
expected = [
    "attestation", "verify",
    "oci://" + os.environ["EXPECTED_IMAGE"],
    "--repo", "KeyserDSoze/Comuni",
    "--signer-workflow", "KeyserDSoze/Comuni/.github/workflows/deploy.yml",
    "--source-ref", "refs/heads/main",
    "--source-digest", os.environ["EXPECTED_SOURCE"],
    "--predicate-type", "https://slsa.dev/provenance/v1",
    "--deny-self-hosted-runners",
    "--format", "json",
]
with open(os.environ["GH_CALLS"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\\n")
if not os.environ.get("GH_TOKEN"):
    sys.stderr.write("missing auth")
    sys.exit(31)
if args != expected:
    sys.stderr.write("wrong signer, source or subject")
    sys.exit(32)
if os.environ.get("FAKE_GH_EXIT", "0") != "0":
    sys.stderr.write(os.environ["FAKE_GH_STDERR"])
    sys.exit(int(os.environ["FAKE_GH_EXIT"]))
if os.environ["FAKE_GH_JSON"] == "__OVERSIZED__":
    sys.stdout.write(" " * 200000)
else:
    sys.stdout.write(os.environ["FAKE_GH_JSON"])
"""


def verified_statement(*, name=MANAGED_REGISTRY + "/comuni",
                       digest=SOURCE_IMAGE_DIGEST.split(":")[1],
                       predicate="https://slsa.dev/provenance/v1"):
    return [{"verificationResult": {"statement": {
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": predicate, "predicate": {},
    }}}]


def invoke(*, image=IMAGE, source=SOURCE_COMMIT_SHA,
           digest=SOURCE_IMAGE_DIGEST, registry=MANAGED_REGISTRY,
           repository=REPO, source_ref="refs/heads/main",
           raw=None, gh_exit=0, gh_stderr=SENTINEL,
           auth="fake-test-token", empty_gh=False):
    with tempfile.TemporaryDirectory() as directory:
        folder = Path(directory)
        fake = folder / "gh"
        fake.write_text(FAKE_GH, encoding="utf-8")
        fake.chmod(0o700)
        calls = folder / "calls.jsonl"
        env = {**os.environ,
            "PATH": str(folder) + os.pathsep + os.environ.get("PATH", ""),
            "EXPECTED_IMAGE": IMAGE,
            "EXPECTED_SOURCE": SOURCE_COMMIT_SHA,
            "GH_CALLS": str(calls),
            "GH_TOKEN": auth,
            "FAKE_GH_EXIT": str(gh_exit),
            "FAKE_GH_STDERR": gh_stderr,
            "FAKE_GH_JSON": (json.dumps(verified_statement()) if raw is None else raw),
        }
        if empty_gh:
            fake.unlink()
        cmd = [
            sys.executable, str(VERIFY),
            "--image", image,
            "--candidate-image-digest", digest,
            "--source-commit-sha", source,
            "--registry-host", registry,
            "--repository", repository,
            "--source-ref", source_ref,
        ]
        result = subprocess.run(cmd, env=env, capture_output=True,
                                text=True, check=False, timeout=12)
        queried = ([json.loads(line) for line in calls.read_text().splitlines()]
                   if calls.exists() else [])
        return result, queried


class SignedProvenanceTests(unittest.TestCase):
    def rejects(self, **overrides):
        result, _ = invoke(**overrides)
        self.assertNotEqual(0, result.returncode, "unsafe/unverified provenance accepted")
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)
        self.assertNotIn(SOURCE_IMAGE_DIGEST, result.stdout + result.stderr)
        self.assertNotIn("fake-test-token", result.stdout + result.stderr)

    def test_matching_verified_source_and_subject_is_accepted(self):
        result, calls = invoke()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(1, len(calls))
        self.assertEqual("oci://" + IMAGE, calls[0][2])
        self.assertIn("--source-digest", calls[0])
        self.assertIn("--signer-workflow", calls[0])

    def test_rejects_gh_failure_without_disclosing_cli_output(self):
        for error in ("signature invalid", "certificate signer mismatch",
                      "missing attestation", "wrong GitHub OIDC issuer",
                      SENTINEL):
            with self.subTest(reason=error[:12]):
                self.rejects(gh_exit=17, gh_stderr=error)
        self.rejects(empty_gh=True)
        self.rejects(auth="")

    def test_rejects_unverified_empty_malformed_and_spoofed_attestations(self):
        candidates = [
            "[]", "null", "{}", "{bad-json}",
            json.dumps([{}]), json.dumps([{"verificationResult": {}}]),
            json.dumps(verified_statement(name="attacker.azurecr.io/comuni")),
            json.dumps(verified_statement(digest="b" * 64)),
            json.dumps(verified_statement(predicate="https://spdx.dev/Document/v2.3")),
            json.dumps([{"verificationResult": {"statement": {
                "subject": [], "predicateType": "https://slsa.dev/provenance/v1"}}}]),
            json.dumps(verified_statement()).replace('"sha256"', '"sha512"'),
            SENTINEL,
            "__OVERSIZED__",
        ]
        for raw in candidates:
            with self.subTest(length=len(raw)):
                self.rejects(raw=raw)

    def test_rejects_different_digest_or_untrusted_image(self):
        for change in (
            {"digest": "sha256:" + "b" * 64},
            {"digest": "sha256:" + "A" * 64},
            {"digest": ""},
            {"image": MANAGED_REGISTRY + "/comuni:" + SOURCE_COMMIT_SHA},
            {"image": "evil.azurecr.io/comuni@" + SOURCE_IMAGE_DIGEST},
            {"image": MANAGED_REGISTRY + "/other@" + SOURCE_IMAGE_DIGEST},
            {"image": MANAGED_REGISTRY + "/comuni@" + "sha256:" + "b" * 64},
            {"image": SENTINEL},
            {"registry": "evil.azurecr.io"},
            {"registry": "synthetic.azurecr.io:443"},
            {"repository": "attacker/Comuni"},
            {"repository": "KeyserDSoze/comuni"},
            {"source_ref": "refs/heads/dev"},
            {"source_ref": "refs/tags/v1"},
            {"source": "a" * 40},
            {"source": SOURCE_COMMIT_SHA[:12] + "f" * 28},
            {"source": SOURCE_COMMIT_SHA.upper()},
            {"source": SENTINEL},
        ):
            with self.subTest(field=next(iter(change))):
                self.rejects(**change)

    def test_workflow_must_sign_and_verify_before_terraform_plan(self):
        self.assertIn("attestations: write", DEPLOY)
        self.assertIn("id-token: write", DEPLOY)
        self.assertIn("uses: actions/attest@", DEPLOY)
        self.assertIn('subject-name: ${{ vars.ACR_LOGIN_SERVER }}/comuni', DEPLOY)
        self.assertIn('subject-digest: ${{ env.CANDIDATE_IMAGE_DIGEST }}', DEPLOY)
        self.assertIn("scripts/azure/verify-image-provenance.py", DEPLOY)
        self.assertIn('--source-commit-sha "$GITHUB_SHA"', DEPLOY)
        self.assertIn('--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"', DEPLOY)
        self.assertIn('--image "$TF_VAR_image"', DEPLOY)
        self.assertIn('GH_TOKEN: ${{ github.token }}', DEPLOY)
        self.assertLess(DEPLOY.index("uses: actions/attest@"),
                        DEPLOY.index("scripts/azure/verify-image-provenance.py"))
        self.assertLess(DEPLOY.index("scripts/azure/verify-image-provenance.py"),
                        DEPLOY.index("terraform -chdir=infra plan"))
        self.assertNotIn("push-to-registry: true", DEPLOY)


if __name__ == "__main__":
    unittest.main()
