#!/usr/bin/env python3
"""Real pgAudit ROLE/DDL privacy test on an isolated PostgreSQL 17 container.

The passwords and role identities here are disposable test-only values.
This never changes the existing main CI database or production resources.
The verifier is secret-equivalent: never print it or raw Docker server logs.

It exercises CREATE ROLE, ALTER ROLE, rejected input, runtime denial, and
transaction rollback with real app SQL scripts, actual pgAudit, and native
log_statement=all / log_parameter_max_length=-1. See ADR 0076 / #92.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
DB = "comuni_pgaudit_ci"
OWNER = "comuni"
OWNER_SECRET = "disposable-pgaudit-owner-ci-only"
PORT = "55432"
DOCKER_IMAGE = "comuni-pgaudit-roles:ci"

# No password, verifier or connection URI may appear in a command argument
# or in the printed diagnostics from this script.
def run(args: list[str], label: str, env: dict[str, str] | None = None,
        expected: int = 0, timeout: int = 110,
        include_stderr: bool = False) -> str:
    try:
        p = subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                           text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise AssertionError(f"pgAudit check unavailable at {label}") from None
    if expected == 0 and p.returncode != 0:
        raise AssertionError(
            f"pgAudit check failed at {label} (exit {p.returncode}); "
            "review CI setup separately without printing captured credentials")
    if expected != 0 and p.returncode == 0:
        raise AssertionError(f"pgAudit rejected operation unexpectedly succeeded: {label}")
    # Docker attaches PostgreSQL's server logs to stderr, not stdout.
    # Keep them in memory only; NEVER echo the full contents to CI.
    return p.stdout + p.stderr if include_stderr else p.stdout


def psql_env(**additional: str) -> dict[str, str]:
    values = os.environ.copy()
    values["PGPASSWORD"] = OWNER_SECRET
    values["PGOPTIONS"] = (
        "-c pgaudit.log=role,ddl,write,function "
        "-c pgaudit.log_parameter=on "
        "-c log_statement=all "
        "-c log_parameter_max_length=-1 "
        "-c log_parameter_max_length_on_error=-1"
    )
    values.pop("RUNTIME_DB_PASSWORD", None)
    values.pop("PLATFORM_READ_DB_PASSWORD", None)
    # Do not inherit a runner's tenant signing key by accident. Only an
    # explicit synthetic test input for a reviewed script may set these.
    values.pop("TENANT_PROOF_KEY", None)
    values.pop("TENANT_PROOF_KEY_ID", None)
    for retire_field in (
        "TENANT_PROOF_RETIRE_KEY_ID", "TENANT_PROOF_REPLACEMENT_KEY_ID",
        "TENANT_PROOF_GRACE_SECONDS",
    ):
        values.pop(retire_field, None)
    # Never inherit actual incident identity fields from a CI runner. Only
    # explicitly supplied, disposable synthetic inputs are permitted.
    for field in (
        "COMUNI_EMERGENCY_ORGANIZATION_ID",
        "COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER",
        "COMUNI_EMERGENCY_OLD_SUBJECT",
        "COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER",
        "COMUNI_EMERGENCY_NEW_SUBJECT",
        "COMUNI_EMERGENCY_INCIDENT_TICKET",
        "COMUNI_EMERGENCY_SECURITY_REVIEWER",
        "COMUNI_EMERGENCY_MUNICIPAL_REVIEWER",
        "COMUNI_EMERGENCY_REASON_CODE",
    ):
        values.pop(field, None)
    values.update(additional)
    return values


def sql(command: str, label: str, env: dict[str, str] | None = None,
        expect_failure: bool = False, role: str = OWNER) -> str:
    return run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
         "-p", PORT, "-U", role, "-d", DB, "-A", "-t", "-c", command],
        label, env or psql_env(), expected=1 if expect_failure else 0,
    ).strip()


def script(name: str, role_password: str | None,
           runtime: bool = False, expect_failure: bool = False,
           owner_password: str | None = None) -> str:
    env = psql_env()
    key = ("RUNTIME_DB_PASSWORD" if name == "provision-runtime-role.sql"
           else "PLATFORM_READ_DB_PASSWORD")
    if role_password is not None:
        env[key] = role_password
    if owner_password is not None:
        env["PGPASSWORD"] = owner_password
    if runtime:
        # Restricted SQL users must not set superuser-only pgAudit GUCs.
        # This negative path must actually reach the schema-owner SQL guard.
        env["PGOPTIONS"] = ""
    role = "comuni_app_runtime" if runtime else OWNER
    # Capture stdout AND stderr privately, including failed COPY/owner checks.
    # The caller audits them only after collecting all verifier canaries.
    return run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
         "-p", PORT, "-U", role, "-d", DB, "-f",
         str(ROOT / "scripts" / "postgres" / name)],
        f"offline role script {name}" + (" denied" if expect_failure else ""),
        env=env, expected=1 if expect_failure else 0, include_stderr=True,
    )


def verifier(role: str) -> str:
    # Role names here are constants, not untrusted operator input.
    result = sql(
        "SELECT rolpassword FROM pg_authid WHERE rolname='" + role + "'",
        "read private SCRAM verifier",
    )
    if not result.startswith("SCRAM-SHA-256$"):
        raise AssertionError("Role password is not a SCRAM-SHA-256 verifier")
    return result


def assert_auth(role: str, password: str) -> None:
    env = psql_env(PGPASSWORD=password, PGOPTIONS="")
    who = sql("SELECT current_user", "SCRAM password login", env=env, role=role)
    if who != role:
        raise AssertionError("Password did not authenticate the expected role")


def scram_components(verifier: str) -> tuple[str, str, str]:
    """Extract canonical SCRAM material without exposing its values in errors.

    pg_authid supplies a structured verifier: iteration count, salt, stored
    key and server key. Each base64 field is sensitive independently.
    See PostgreSQL 17 pg_authid and ADR 0098. Never print the raw verifier.
    """
    try:
        label, iteration_salt, keys = verifier.split("$")
        iteration, salt = iteration_salt.split(":")
        stored_key, server_key = keys.split(":")
        if label != "SCRAM-SHA-256" or int(iteration) < 1:
            raise ValueError()
        decoded = [base64.b64decode(value, validate=True)
                   for value in (salt, stored_key, server_key)]
        if (len(decoded[0]) < 16 or len(decoded[1]) != 32
                or len(decoded[2]) != 32):
            raise ValueError()
        if any(base64.b64encode(raw).decode("ascii") != value
               for raw, value in zip(decoded, (salt, stored_key, server_key))):
            raise ValueError()
        return salt, stored_key, server_key
    except (ValueError, binascii.Error):
        raise AssertionError("Invalid SCRAM verifier structure for audit check") from None


def assert_audits(log: str, verifiers: list[str],
                  passwords: list[str], client_output: str = "") -> None:
    # Base64 transport is reversible, not redaction. The exact single-record
    # CSV payload is base64(canonical JSON {"SCRAM_VERIFIER": verifier}).
    # Also reject bare base64(verifier/password), raw SCRAM components, and
    # raw plaintext in BOTH server logs and private psql stdout/stderr.
    sensitive = [item for item in passwords + verifiers if item]
    for item in verifiers:
        sensitive.extend(scram_components(item))
    for item in passwords + verifiers:
        if item:
            sensitive.append(base64.b64encode(item.encode("ascii")).decode("ascii"))
            # Defensively reject a synthetic password canary wrapped in the
            # same reversible envelope too, even though normal role transport
            # only ever wraps generated SCRAM verifiers.
            envelope = json.dumps(
                {"SCRAM_VERIFIER": item}, ensure_ascii=True,
                separators=(",", ":"), sort_keys=True,
            ).encode("ascii")
            sensitive.append(base64.b64encode(envelope).decode("ascii"))
    if any(value in output for output in (log, client_output)
           for value in sensitive):
        # Never print a candidate, envelope, client output or raw server log.
        raise AssertionError(
            "Sensitive SCRAM material in PostgreSQL/pgAudit or psql output")

    audit_lines = [
        line for line in log.splitlines()
        if "AUDIT: SESSION" in line and ",ROLE," in line
    ]
    if not audit_lines:
        raise AssertionError("No real pgAudit ROLE events; check shared preload")

    # Every CREATE/ALTER for the known login must carry its own redaction.
    # A single redacted audit line elsewhere cannot hide a missing redaction.
    for role in ("comuni_app_runtime", "comuni_platform_reader"):
        for command in ("CREATE ROLE", "ALTER ROLE"):
            expected = [
                line for line in audit_lines
                if "," + command + "," in line and role in line
            ]
            if not expected:
                raise AssertionError("Expected pgAudit operation metadata missing: "
                                     + command + " " + role)
            if any("<REDACTED>" not in line for line in expected):
                raise AssertionError("Per-operation pgAudit ROLE redaction missing")

    # Audited privilege operations and PostgreSQL statement logging remain on.
    if not any(",ROLE,GRANT," in line for line in audit_lines):
        raise AssertionError("Privilege-change audit events were suppressed")
    if "statement: COPY" not in log:
        raise AssertionError("No native COPY statement logged while pgAudit active")


def assert_identity_privacy(server_log: str, client_output: str,
                            canaries: tuple[str, ...]) -> None:
    """Require audited owner-only COPY and reject recognizable private values.

    The input here is only an isolated pgAudit log *slice* recorded while
    executing actual registration/bootstrap/activation/enrollment scripts, not role provisioning.
    Never echo the log, private inputs or a substring in diagnostic messages.
    """
    if not canaries or any(not canary for canary in canaries):
        raise AssertionError("No valid synthetic identity canaries to verify")
    # Only print the *category* and log channel, never any canary or raw line.
    # This helps diagnose a failing privacy gate without creating a second leak
    # in the CI job output. All canaries here are disposable synthetic inputs.
    categories = (
        "organization-id", "organization-name", "oidc-issuer",
        "oidc-subject", "registration-ticket", "bootstrap-ticket",
        "registration-reviewer", "bootstrap-reviewer", "invalid-subject",
        "activation-ticket", "activation-reviewer", "second-admin-subject",
        "second-admin-ticket", "second-admin-reviewer", "invalid-second-subject",
        "revocation-ticket", "revocation-reviewer", "revocation-reason",
        "last-admin-revocation-ticket", "suspension-ticket",
        "suspension-reviewer", "suspension-reason",
    )
    if len(canaries) != len(categories):
        raise AssertionError("Identity canary inventory mismatch")
    for category, canary in zip(categories, canaries, strict=True):
        if canary in client_output:
            raise AssertionError("Synthetic identity canary in client output: " + category)
        if canary in server_log:
            found_line = next((line for line in server_log.splitlines()
                               if canary in line), "")
            source = ("pgAudit" if "AUDIT: SESSION" in found_line else
                      "statement" if "statement:" in found_line else
                      "error/context")
            raise AssertionError(
                "Synthetic identity canary in server " + source +
                " logs: " + category)

    # Each real owner-only DO statement remains traceable in native logs.
    # pgAudit FUNCTION and WRITE prove full metadata auditing stays enabled.
    for marker in ("DO $register$", "DO $bootstrap$",
                   "DO $activation$", "DO $enrollment$",
                   "DO $revocation$", "DO $lifecycle$"):
        if marker not in server_log:
            raise AssertionError("Owner-only operation missing from PostgreSQL logs")
    audit_lines = [
        line for line in server_log.splitlines()
        if "AUDIT: SESSION" in line
    ]
    if sum(",FUNCTION,DO," in line for line in audit_lines) < 6:
        raise AssertionError("Owner-only operations missing pgAudit FUNCTION events")
    if not any(",WRITE,INSERT," in line for line in audit_lines):
        raise AssertionError("Owner-only operations missing pgAudit WRITE events")
    if not any(",WRITE,UPDATE," in line for line in audit_lines):
        raise AssertionError("Municipal activation missing pgAudit UPDATE event")
    if server_log.count("statement: COPY") < 6:
        raise AssertionError("Private client COPY statements not logged")


def private_owner_script(file: str, values: dict[str, str],
                         expect_failure: bool = False,
                         metadata_only: bool = True) -> str:
    """Use only static, reviewed script paths and private environment values."""
    if file not in (
        "register-organization.sql", "bootstrap-initial-admin.sql",
        "activate-organization.sql", "enroll-additional-admin.sql",
        "revoke-admin.sql", "set-organization-suspension.sql",
        "manage-platform-operator.sql", "provision-organization.sql",
        "provision-tenant-proof.sql", "stage-tenant-proof-key.sql",
        "stage-emergency-admin-replacement.sql",
        "retire-tenant-proof-key.sql",
    ):
        raise AssertionError("Unreviewed owner identity script")
    env = psql_env(**values)
    if metadata_only:
        # pgAudit FUNCTION/WRITE records remain enabled. The parameter field
        # alone must be suppressed for private owner input. Every script in
        # this allowlist REFUSES parameter=on before COPY transport begins.
        env["PGOPTIONS"] = env["PGOPTIONS"].replace(
            "-c pgaudit.log_parameter=on", "-c pgaudit.log_parameter=off")
    return run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
         "-p", PORT, "-U", OWNER, "-d", DB, "-f",
         str(ROOT / "scripts" / "postgres" / file)],
        "synthetic owner identity operation",
        env=env,
        expected=1 if expect_failure else 0,
        include_stderr=True,
    )


def verify_identity_under_pgaudit(container_name: str) -> tuple[str, str, str]:
    """Test owner-only onboarding, Admin revocation and tenant suspension.

    This disposable cluster is populated with synthetic records only. No
    canary is included in SQL literals, command arguments or diagnostic text.
    A previous Docker log snapshot isolates events from these operations.
    """
    prefix = run(["docker", "logs", container_name],
                 "pgAudit identity baseline", include_stderr=True)
    organization_id = str(uuid.uuid4())
    marker = uuid.uuid4().hex[:12]
    organization_name = "Comune Sintetico " + marker
    issuer = "https://oidc-ci.example.test/tenant-" + marker
    subject = "synthetic-oidc-sub-" + marker
    register_ticket = "REG-2026-" + marker
    bootstrap_ticket = "BOOT-2026-" + marker
    register_reviewer = "register-reviewer-" + marker
    bootstrap_reviewer = "bootstrap-reviewer-" + marker
    invalid_subject = " invalid-sub-" + marker
    activation_ticket = "ACT-2026-" + marker
    activation_reviewer = "activation-reviewer-" + marker
    additional_subject = "synthetic-second-admin-" + marker
    additional_ticket = "ADD-2026-" + marker
    additional_reviewer = "enrollment-reviewer-" + marker
    invalid_secondary_subject = " invalid-second-admin-" + marker
    revocation_ticket = "REVOKE-2026-" + marker
    revocation_reviewer = "revocation-reviewer-" + marker
    revocation_reason = "operator-departure-" + marker
    last_admin_ticket = "LAST-2026-" + marker
    suspension_ticket = "SUSP-2026-" + marker
    suspension_reviewer = "suspension-reviewer-" + marker
    suspension_reason = "security-incident-" + marker

    registration = {
        "COMUNI_REGISTER_ORGANIZATION_ID": organization_id,
        "COMUNI_REGISTER_ORGANIZATION_NAME": organization_name,
        "COMUNI_REGISTER_CHANGE_TICKET": register_ticket,
        "COMUNI_REGISTER_APPROVER": register_reviewer,
    }
    bootstrap = {
        "COMUNI_BOOTSTRAP_ORGANIZATION_ID": organization_id,
        "COMUNI_BOOTSTRAP_IDENTITY_ISSUER": issuer,
        "COMUNI_BOOTSTRAP_SUBJECT": subject,
        "COMUNI_BOOTSTRAP_CHANGE_TICKET": bootstrap_ticket,
        "COMUNI_BOOTSTRAP_APPROVER": bootstrap_reviewer,
    }
    activation = {
        "COMUNI_ACTIVATE_ORGANIZATION_ID": organization_id,
        "COMUNI_ACTIVATE_CHANGE_TICKET": activation_ticket,
        "COMUNI_ACTIVATE_APPROVER": activation_reviewer,
    }
    additional_admin = {
        "COMUNI_ADD_ADMIN_ORGANIZATION_ID": organization_id,
        "COMUNI_ADD_ADMIN_IDENTITY_ISSUER": issuer,
        "COMUNI_ADD_ADMIN_SUBJECT": additional_subject,
        "COMUNI_ADD_ADMIN_CHANGE_TICKET": additional_ticket,
        "COMUNI_ADD_ADMIN_APPROVER": additional_reviewer,
    }
    revocation = {
        "COMUNI_REVOKE_ADMIN_ORGANIZATION_ID": organization_id,
        "COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER": issuer,
        "COMUNI_REVOKE_ADMIN_SUBJECT": additional_subject,
        "COMUNI_REVOKE_ADMIN_CHANGE_TICKET": revocation_ticket,
        "COMUNI_REVOKE_ADMIN_APPROVER": revocation_reviewer,
        "COMUNI_REVOKE_ADMIN_REASON_CODE": revocation_reason,
    }
    suspension = {
        "COMUNI_LIFECYCLE_ORGANIZATION_ID": organization_id,
        "COMUNI_LIFECYCLE_ACTION": "suspend",
        "COMUNI_LIFECYCLE_CHANGE_TICKET": suspension_ticket,
        "COMUNI_LIFECYCLE_APPROVER": suspension_reviewer,
        "COMUNI_LIFECYCLE_REASON_CODE": suspension_reason,
    }
    client_output = ""
    client_output += private_owner_script("register-organization.sql", registration)
    client_output += private_owner_script("bootstrap-initial-admin.sql", bootstrap)

    # Preserve a negative safety check with pgAudit parameters ON. The
    # server-side guard rejects BEFORE sensitive COPY; this is not a test
    # of a successful unredacted operation and must remain fail-closed.
    unsafe_output = private_owner_script(
        "bootstrap-initial-admin.sql", bootstrap,
        expect_failure=True, metadata_only=False)
    if "Owner-only identity operation requires parameter-free audit metadata" not in unsafe_output:
        raise AssertionError("Unsafe pgAudit parameter profile was not denied")
    client_output += unsafe_output

    # Input validation must fail in the real DO, without creating membership
    # or changing audit. Keep this negative subject outside SQL and argv.
    invalid_bootstrap = dict(bootstrap)
    invalid_bootstrap["COMUNI_BOOTSTRAP_SUBJECT"] = invalid_subject
    client_output += private_owner_script(
        "bootstrap-initial-admin.sql", invalid_bootstrap, expect_failure=True)

    # Exact owner-only replay must be a no-op, including the audit count.
    client_output += private_owner_script("register-organization.sql", registration)
    client_output += private_owner_script("bootstrap-initial-admin.sql", bootstrap)

    client_output += private_owner_script("activate-organization.sql", activation)

    # A denied parameter-logging session cannot activate the organization
    # or grant another Admin; verify both negative paths before their success.
    for script_name, private_values in (
        ("activate-organization.sql", activation),
        ("enroll-additional-admin.sql", additional_admin),
    ):
        unsafe = private_owner_script(
            script_name, private_values,
            expect_failure=True, metadata_only=False)
        if "Owner-only identity operation requires parameter-free audit metadata" not in unsafe:
            raise AssertionError("Unsafe pgAudit parameter profile was not denied")
        client_output += unsafe

    client_output += private_owner_script("enroll-additional-admin.sql", additional_admin)

    invalid_extra_admin = dict(additional_admin)
    invalid_extra_admin["COMUNI_ADD_ADMIN_SUBJECT"] = invalid_secondary_subject
    client_output += private_owner_script(
        "enroll-additional-admin.sql", invalid_extra_admin, expect_failure=True)

    # Exact replays remain no-op, with no extra Admin or audit entry.
    client_output += private_owner_script("activate-organization.sql", activation)
    client_output += private_owner_script("enroll-additional-admin.sql", additional_admin)

    # Reject parameter logging BEFORE receiving either private COPY payload.
    # Then revoke only the second Admin; preserve the sole survivor.
    for script_name, private_values in (
        ("revoke-admin.sql", revocation),
        ("set-organization-suspension.sql", suspension),
    ):
        unsafe = private_owner_script(
            script_name, private_values,
            expect_failure=True, metadata_only=False)
        if "Owner-only identity operation requires parameter-free audit metadata" not in unsafe:
            raise AssertionError("Unsafe pgAudit parameter profile was not denied")
        client_output += unsafe

    client_output += private_owner_script("revoke-admin.sql", revocation)

    # Replay cannot add a second revocation event.
    client_output += private_owner_script("revoke-admin.sql", revocation)

    # A distinct change ticket must not allow revoking the last remaining
    # OIDC Admin. Use only the COPY environment, not SQL or command arguments.
    last_admin = dict(revocation)
    last_admin["COMUNI_REVOKE_ADMIN_SUBJECT"] = subject
    last_admin["COMUNI_REVOKE_ADMIN_CHANGE_TICKET"] = last_admin_ticket
    blocked = private_owner_script("revoke-admin.sql", last_admin,
                                   expect_failure=True)
    if "Last verified active Admin cannot be revoked" not in blocked:
        raise AssertionError("Last surviving OIDC Admin was not protected")
    client_output += blocked

    client_output += private_owner_script("set-organization-suspension.sql", suspension)
    # Replayed suspension must have no new audit entry.
    client_output += private_owner_script("set-organization-suspension.sql", suspension)

    # This query contains *only static SQL*, never organization ID, subject,
    # issuer, ticket, or reviewer. The isolated DB starts with zero tenants.
    verified = sql("""
        SELECT
           (SELECT count(*) FROM platform.organizations
            WHERE is_activated=TRUE AND is_suspended=TRUE) = 1
        AND (SELECT count(*) FROM platform.organization_modules
             WHERE module_key='protocol' AND enabled=FALSE) = 1
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin') = 2
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=TRUE
               AND identity_issuer IS NOT NULL) = 1
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=FALSE
               AND identity_issuer IS NOT NULL) = 1
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action IN ('platform.organization.registered',
                              'platform.membership.admin.initialized',
                              'platform.organization.activated',
                              'platform.membership.admin.added',
                              'platform.membership.admin.revoked',
                              'platform.organization.suspended')) = 6
        """, "synthetic owner full onboarding invariant")
    if verified != "t":
        raise AssertionError("Owner identity operations violated expected invariants")

    after = run(["docker", "logs", container_name],
                "collect isolated owner identity pgAudit logs",
                include_stderr=True)
    if not after.startswith(prefix):
        raise AssertionError("Cannot isolate owner identity pgAudit log window")
    canaries = (
        organization_id, organization_name, issuer, subject,
        register_ticket, bootstrap_ticket, register_reviewer,
        bootstrap_reviewer, invalid_subject,
        activation_ticket, activation_reviewer, additional_subject,
        additional_ticket, additional_reviewer, invalid_secondary_subject,
        revocation_ticket, revocation_reviewer, revocation_reason,
        last_admin_ticket, suspension_ticket, suspension_reviewer,
        suspension_reason,
    )
    assert_identity_privacy(after[len(prefix):], client_output, canaries)
    # Pass a synthetic identity reference privately to the final emergency
    # stage. Never emit it in CI diagnostics or argv/SQL query literals.
    return organization_id, issuer, subject


def assert_operator_provision_privacy(server_log: str, client_output: str,
                                      canaries: tuple[str, ...]) -> None:
    """Prove operator/provision metadata exists without leaking canary values.

    This handles only the log suffix after previous municipal onboarding.
    Neither secrets nor log lines are included in assertion messages.
    """
    categories = (
        "second-organization-id", "second-organization-name",
        "second-provision-ticket", "second-provision-reviewer",
        "platform-issuer", "platform-subject", "operator-enroll-ticket",
        "operator-revoke-ticket", "operator-reviewer",
        "invalid-platform-subject",
    )
    if len(canaries) != len(categories) or any(not item for item in canaries):
        raise AssertionError("Invalid synthetic operator canary inventory")
    for category, canary in zip(categories, canaries, strict=True):
        if canary in client_output:
            raise AssertionError("Synthetic operator canary in client output: " +
                                 category)
        if canary in server_log:
            # We never print the value or even the line where it appeared.
            raise AssertionError("Synthetic operator canary in PostgreSQL logs: " +
                                 category)

    for marker in ("DO $provision$", "DO $operator$"):
        if marker not in server_log:
            raise AssertionError("Owner-only operator/provision DO audit missing")
    audit_lines = [
        line for line in server_log.splitlines()
        if "AUDIT: SESSION" in line
    ]
    if sum(",FUNCTION,DO," in line for line in audit_lines) < 2:
        raise AssertionError("Operator/provision pgAudit FUNCTION events missing")
    if not any(",WRITE,INSERT," in line for line in audit_lines):
        raise AssertionError("Operator/provision pgAudit INSERT events missing")
    if not any(",WRITE,UPDATE," in line for line in audit_lines):
        raise AssertionError("Operator revoke pgAudit UPDATE event missing")
    if server_log.count("statement: COPY") < 2:
        raise AssertionError("Operator/provision native COPY audit missing")


def verify_platform_and_provision_under_pgaudit(container_name: str) -> None:
    """Real second-municipality provisioning and platform operator lifecycle.

    A new log window isolates this from the six owner-only operations already
    tested. The operators are a platform scope, not municipality memberships.
    All private values are synthetic and travel only through client COPY.
    """
    prefix = run(["docker", "logs", container_name],
                 "baseline platform operation audit", include_stderr=True)
    marker = uuid.uuid4().hex[:12]
    second_id = str(uuid.uuid4())
    second_name = "Comune Secondario Sintetico " + marker
    provision_ticket = "PROV-2026-" + marker
    provision_reviewer = "reviewer-provision-" + marker
    operator_issuer = "https://platform-ci.example.test/operator-" + marker
    operator_subject = "platform-sub-" + marker
    enroll_ticket = "OP-ENROLL-" + marker
    revoke_ticket = "OP-REVOKE-" + marker
    operator_reviewer = "platform-reviewer-" + marker
    invalid_subject = " invalid-platform-sub-" + marker

    second_provision = {
        "COMUNI_PROVISION_ORGANIZATION_ID": second_id,
        "COMUNI_PROVISION_ORGANIZATION_NAME": second_name,
        "COMUNI_PROVISION_CHANGE_TICKET": provision_ticket,
        "COMUNI_PROVISION_APPROVER": provision_reviewer,
    }
    operator_enroll = {
        "COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER": operator_issuer,
        "COMUNI_PLATFORM_OPERATOR_SUBJECT": operator_subject,
        "COMUNI_PLATFORM_OPERATOR_ACTION": "enroll",
        "COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET": enroll_ticket,
        "COMUNI_PLATFORM_OPERATOR_APPROVER": operator_reviewer,
    }
    operator_revoke = dict(operator_enroll)
    operator_revoke["COMUNI_PLATFORM_OPERATOR_ACTION"] = "revoke"
    operator_revoke["COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET"] = revoke_ticket

    output = ""
    # Both unsafe executions must abort before the COPY producer starts and
    # leave no additional municipality or platform operator in the database.
    for script_name, inputs in (
        ("provision-organization.sql", second_provision),
        ("manage-platform-operator.sql", operator_enroll),
    ):
        rejected = private_owner_script(
            script_name, inputs, expect_failure=True, metadata_only=False)
        if ("Owner-only identity operation requires parameter-free audit metadata"
                not in rejected):
            raise AssertionError("Unsafe platform owner pgAudit profile not rejected")
        output += rejected

    before = sql("""
        SELECT
            (SELECT count(*) FROM platform.organizations) = 1
        AND (SELECT count(*) FROM platform.platform_operators) = 0
        AND (SELECT count(*) FROM platform.platform_operator_audit_events) = 0
        """, "guarded platform owner operations are side effect free")
    if before != "t":
        raise AssertionError("Parameter-on guard changed platform state")

    output += private_owner_script("provision-organization.sql", second_provision)
    output += private_owner_script("manage-platform-operator.sql", operator_enroll)

    # Exact retries are no-op and cannot duplicate owner audits.
    output += private_owner_script("provision-organization.sql", second_provision)
    output += private_owner_script("manage-platform-operator.sql", operator_enroll)

    invalid = dict(operator_enroll)
    invalid["COMUNI_PLATFORM_OPERATOR_SUBJECT"] = invalid_subject
    output += private_owner_script("manage-platform-operator.sql", invalid,
                                   expect_failure=True)

    output += private_owner_script("manage-platform-operator.sql", operator_revoke)
    output += private_owner_script("manage-platform-operator.sql", operator_revoke)

    # No secret or canary in SQL: the static query checks tenant separation,
    # default-disabled services, correct operator lifecycle and audit counts.
    verified = sql("""
        SELECT
            (SELECT count(*) FROM platform.organizations) = 2
        AND (SELECT count(*) FROM platform.organizations
             WHERE is_activated=FALSE AND is_suspended=FALSE) = 1
        AND (SELECT count(*) FROM platform.organizations
             WHERE is_activated=TRUE AND is_suspended=TRUE) = 1
        AND (SELECT count(*) FROM platform.organization_modules
             WHERE module_key='protocol' AND enabled=FALSE) = 2
        AND (SELECT count(*) FROM platform.organization_memberships) = 2
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action='platform.organization.created') = 1
        AND (SELECT count(*) FROM platform.audit_events) = 7
        AND (SELECT count(*) FROM platform.platform_operators
             WHERE is_active=FALSE AND identity_issuer IS NOT NULL) = 1
        AND (SELECT count(*) FROM platform.platform_operator_audit_events
             WHERE action IN ('platform.operator.enrolled',
                              'platform.operator.revoked')) = 2
        AND (SELECT count(*) FROM platform.platform_operator_audit_events) = 2
        """, "isolated platform operator and second municipality invariants")
    if verified != "t":
        raise AssertionError("Platform owner operations violated expected invariants")

    after = run(["docker", "logs", container_name],
                "collect isolated platform pgAudit log suffix",
                include_stderr=True)
    if not after.startswith(prefix):
        raise AssertionError("Cannot isolate platform owner pgAudit log window")
    canaries = (
        second_id, second_name, provision_ticket, provision_reviewer,
        operator_issuer, operator_subject, enroll_ticket, revoke_ticket,
        operator_reviewer, invalid_subject,
    )
    assert_operator_provision_privacy(after[len(prefix):], output, canaries)



def assert_tenant_signing_key_privacy(server_log: str, client_output: str,
                                      canaries: tuple[str, ...]) -> None:
    """Fail closed for raw or obviously base64-encoded signing key canaries.

    This only checks the isolated log window of *real* tenant key provisioning.
    Do not print secret values, log lines or derived hashes in diagnostics.
    """
    categories = ("legacy-signing-key", "versioned-signing-key",
                  "versioned-key-id", "mismatched-legacy-signing-key",
                  "mismatched-versioned-signing-key")
    if len(canaries) != len(categories) or any(not key for key in canaries):
        raise AssertionError("Invalid synthetic signing-key audit inventory")
    for category, canary in zip(categories, canaries, strict=True):
        encoded = base64.b64encode(canary.encode("utf-8")).decode("ascii")
        for sensitive in (canary, encoded):
            if sensitive in client_output:
                raise AssertionError(
                    "Synthetic signing-key canary in client output: " + category)
            if sensitive in server_log:
                raise AssertionError(
                    "Synthetic signing-key canary in PostgreSQL logs: " + category)

    for marker in ("DO $tenant_legacy$", "DO $tenant_stage$"):
        if marker not in server_log:
            raise AssertionError("Owner signing-key DO metadata missing")
    audit_lines = [
        line for line in server_log.splitlines() if "AUDIT: SESSION" in line
    ]
    if sum(",FUNCTION,DO," in line for line in audit_lines) < 2:
        raise AssertionError("Owner signing-key pgAudit FUNCTION events missing")
    if not any(",WRITE,INSERT," in line for line in audit_lines):
        raise AssertionError("Owner signing-key pgAudit WRITE INSERT events missing")
    if server_log.count("statement: COPY") < 2:
        raise AssertionError("Owner signing-key native COPY statements missing")


def verify_tenant_signing_keys_under_pgaudit(container_name: str) -> str:
    """Execute true owner-only legacy and versioned RLS signing key scripts.

    This disposable cluster must have no signing keys yet. PostgreSQL pgAudit
    retains all ROLE/DDL/WRITE/FUNCTION categories; only bind parameter values
    are disabled for the private owner scripts. The CI runner never prints
    input keys, their digests, raw server logs or reversible COPY envelopes.
    """
    prefix = run(["docker", "logs", container_name],
                 "baseline owner signing key pgAudit", include_stderr=True)
    marker = uuid.uuid4().hex[:12]
    legacy_key = "synthetic-legacy-signing-key-2026-" + marker + "-never-real"
    staged_key = "synthetic-versioned-signing-key-2026-" + marker + "-never-real"
    staged_id = "synthetic_" + marker
    wrong_legacy = "different-legacy-signing-key-2026-" + marker + "-never-real"
    wrong_staged = "different-versioned-signing-key-2026-" + marker + "-never-real"

    legacy = {"TENANT_PROOF_KEY": legacy_key}
    staged = {"TENANT_PROOF_KEY_ID": staged_id, "TENANT_PROOF_KEY": staged_key}
    client_output = ""

    empty = sql("""
        SELECT
           (SELECT count(*) FROM platform.tenant_proof_secret) = 0
        AND (SELECT count(*) FROM platform.tenant_proof_keys) = 0
        """, "preflight synthetic tenant proof secret count")
    if empty != "t":
        raise AssertionError("Disposable pgAudit DB unexpectedly has signing keys")

    # Both scripts must refuse parameter-value auditing before COPY even for
    # otherwise valid synthetic input. No key row can be created.
    for filename, private_values in (
        ("provision-tenant-proof.sql", legacy),
        ("stage-tenant-proof-key.sql", staged),
    ):
        denied = private_owner_script(
            filename, private_values,
            expect_failure=True, metadata_only=False)
        if ("Owner-only signing key operation requires parameter-free audit metadata"
                not in denied):
            raise AssertionError("Unsafe signing key pgAudit profile not rejected")
        client_output += denied

    unsafe_after = run(["docker", "logs", container_name],
                       "check denied private COPY never started",
                       include_stderr=True)
    if not unsafe_after.startswith(prefix):
        raise AssertionError("Cannot isolate rejected signing-key audit window")
    if "statement: COPY" in unsafe_after[len(prefix):]:
        raise AssertionError("Parameter-on signing key execution reached COPY")
    no_keys = sql("""
        SELECT
           (SELECT count(*) FROM platform.tenant_proof_secret) = 0
        AND (SELECT count(*) FROM platform.tenant_proof_keys) = 0
        """, "rejected signing-key operations are side-effect-free")
    if no_keys != "t":
        raise AssertionError("Rejected signing-key operation changed database")

    client_output += private_owner_script("provision-tenant-proof.sql", legacy)
    client_output += private_owner_script("stage-tenant-proof-key.sql", staged)

    # Neither a retry with identical material nor an attempt to reuse a key
    # ID with different material may mutate the existing signing keys.
    client_output += private_owner_script("provision-tenant-proof.sql", legacy)
    client_output += private_owner_script("stage-tenant-proof-key.sql", staged)

    different_legacy = {"TENANT_PROOF_KEY": wrong_legacy}
    denied_legacy = private_owner_script(
        "provision-tenant-proof.sql", different_legacy, expect_failure=True)
    if "Legacy key mismatch or retirement" not in denied_legacy:
        raise AssertionError("Legacy signing-key collision not rejected")
    client_output += denied_legacy

    different_staged = dict(staged)
    different_staged["TENANT_PROOF_KEY"] = wrong_staged
    denied_staged = private_owner_script(
        "stage-tenant-proof-key.sql", different_staged, expect_failure=True)
    if "Key ID already has different material" not in denied_staged:
        raise AssertionError("Versioned signing-key collision not rejected")
    client_output += denied_staged

    # Static SQL only. No key, marker or key ID is in the query text or CLI.
    verified = sql("""
        SELECT
           (SELECT count(*) FROM platform.tenant_proof_secret WHERE id=1) = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id='legacy' AND revoked_at IS NULL
               AND valid_until > clock_timestamp()) = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id<>'legacy' AND revoked_at IS NULL
               AND valid_until > clock_timestamp()) = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys) = 2
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE octet_length(signing_key) >= 32) = 2
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id='legacy'
               AND signing_key=(SELECT signing_key
                                FROM platform.tenant_proof_secret
                                WHERE id=1)) = 1
        AND NOT has_table_privilege('comuni_app_runtime',
                                    'platform.tenant_proof_keys','SELECT')
        AND NOT has_table_privilege('comuni_app_runtime',
                                    'platform.tenant_proof_keys','INSERT')
        """, "tenant proof secrets and runtime isolation")
    if verified != "t":
        raise AssertionError("Signing-key database or runtime invariants failed")

    # SHA-256 is used ONLY as an in-memory test comparison. Never publish
    # fingerprints of live keys and never pass any material into SQL literals.
    def fingerprint(query: str) -> str:
        return sql(query, "inspect synthetic key material fingerprint")
    fingerprints = (
        fingerprint("SELECT encode(public.digest(signing_key,'sha256'),'hex') "
                    "FROM platform.tenant_proof_secret WHERE id=1"),
        fingerprint("SELECT encode(public.digest(signing_key,'sha256'),'hex') "
                    "FROM platform.tenant_proof_keys WHERE key_id='legacy'"),
        fingerprint("SELECT encode(public.digest(signing_key,'sha256'),'hex') "
                    "FROM platform.tenant_proof_keys WHERE key_id<>'legacy'"),
    )
    expected = (
        hashlib.sha256(legacy_key.encode("utf-8")).hexdigest(),
        hashlib.sha256(legacy_key.encode("utf-8")).hexdigest(),
        hashlib.sha256(staged_key.encode("utf-8")).hexdigest(),
    )
    if fingerprints != expected:
        raise AssertionError("Tenant signing material was changed by a retry")

    after = run(["docker", "logs", container_name],
                "collect isolated signing-key pgAudit logs", include_stderr=True)
    if not after.startswith(prefix):
        raise AssertionError("Cannot isolate signing-key pgAudit log window")
    canaries = (legacy_key, staged_key, staged_id, wrong_legacy, wrong_staged)
    assert_tenant_signing_key_privacy(after[len(prefix):], client_output, canaries)
    return staged_id


def assert_emergency_privacy(server_log: str, client_output: str,
                             canaries: tuple[str, ...]) -> None:
    """Require real pgAudit metadata but forbid emergency identity canaries.

    The isolated server log window covers only the true emergency script.
    Never print values, base64 payloads, raw log lines or derived fingerprints.
    """
    categories = (
        "organization-id", "old-issuer", "old-subject", "new-issuer",
        "new-subject", "incident-ticket", "security-reviewer",
        "municipal-reviewer", "reason-code", "alternate-incident-ticket",
    )
    if len(canaries) != len(categories) or any(not val for val in canaries):
        raise AssertionError("Invalid emergency pgAudit synthetic canary inventory")
    for category, canary in zip(categories, canaries, strict=True):
        for sensitive in (canary, base64.b64encode(canary.encode("utf-8")).decode("ascii")):
            if sensitive in client_output:
                raise AssertionError("Emergency canary in client output: " + category)
            if sensitive in server_log:
                raise AssertionError("Emergency canary in PostgreSQL log: " + category)

    if "DO $emergency$" not in server_log:
        raise AssertionError("Emergency owner-only DO statement missing")
    audit_lines = [
        line for line in server_log.splitlines() if "AUDIT: SESSION" in line
    ]
    if not any(",FUNCTION,DO," in line for line in audit_lines):
        raise AssertionError("Emergency pgAudit FUNCTION DO metadata missing")
    if not any(",WRITE,UPDATE," in line for line in audit_lines):
        raise AssertionError("Emergency pgAudit WRITE UPDATE metadata missing")
    if not any(",WRITE,INSERT," in line for line in audit_lines):
        raise AssertionError("Emergency pgAudit WRITE INSERT metadata missing")
    if "statement: COPY" not in server_log:
        raise AssertionError("Emergency COPY statement metadata missing")


def verify_emergency_under_pgaudit(
    container_name: str, identity_context: tuple[str, str, str]
) -> None:
    """Execute true break-glass staging only in disposable PostgreSQL17.

    An independently owner-audited suspension, one active verified Admin
    and one older revoked Admin already exist from the preceding CI fixture.
    This is NOT identity proof, MFA, two real approvals or live recovery.
    """
    prefix = run(["docker", "logs", container_name],
                 "baseline synthetic emergency pgAudit logs",
                 include_stderr=True)
    org_id, old_issuer, old_subject = identity_context
    marker = uuid.uuid4().hex[:12]
    new_issuer = "https://recovery-ci.example.test/tenant-" + marker
    new_subject = "verified-synthetic-replacement-" + marker
    incident = "INC-2026-" + marker
    security_review = "security-reviewer-" + marker
    municipality_review = "municipal-reviewer-" + marker
    reason = "verified-incident-" + marker
    other_incident = "INC-2026-OTHER-" + marker
    emergency = {
        "COMUNI_EMERGENCY_ORGANIZATION_ID": org_id,
        "COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER": old_issuer,
        "COMUNI_EMERGENCY_OLD_SUBJECT": old_subject,
        "COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER": new_issuer,
        "COMUNI_EMERGENCY_NEW_SUBJECT": new_subject,
        "COMUNI_EMERGENCY_INCIDENT_TICKET": incident,
        "COMUNI_EMERGENCY_SECURITY_REVIEWER": security_review,
        "COMUNI_EMERGENCY_MUNICIPAL_REVIEWER": municipality_review,
        "COMUNI_EMERGENCY_REASON_CODE": reason,
    }

    before = sql("""
        SELECT
            (SELECT count(*) FROM platform.organizations
             WHERE is_activated=TRUE AND is_suspended=TRUE) = 1
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=TRUE) = 1
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action='platform.membership.admin.emergency.revoked') = 0
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action='platform.membership.admin.emergency.staged') = 0
        AND (SELECT count(*) FROM platform.audit_events) = 7
        """, "preflight audited suspended sole Admin state")
    if before != "t":
        raise AssertionError("Synthetic emergency prerequisites not satisfied")

    # Attempt the identical operation with pgAudit parameter values ON. It
    # must refuse before even opening the private COPY producer.
    unsafe = private_owner_script(
        "stage-emergency-admin-replacement.sql", emergency,
        expect_failure=True, metadata_only=False)
    if ("Owner-only emergency operation requires parameter-free audit metadata"
            not in unsafe):
        raise AssertionError("Unsafe emergency pgAudit profile was not rejected")
    denied_logs = run(["docker", "logs", container_name],
                      "inspect denied emergency COPY boundary",
                      include_stderr=True)
    if not denied_logs.startswith(prefix):
        raise AssertionError("Cannot isolate refused emergency pgAudit log window")
    if "statement: COPY" in denied_logs[len(prefix):]:
        raise AssertionError("Rejected emergency operation reached private COPY")

    unaffected = sql("""
        SELECT
            (SELECT count(*) FROM platform.audit_events) = 7
        AND (SELECT count(*) FROM platform.organization_memberships) = 2
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=TRUE) = 1
        """, "denied emergency transition has no side effects")
    if unaffected != "t":
        raise AssertionError("Unsafe emergency audit profile modified state")

    client_output = unsafe
    client_output += private_owner_script(
        "stage-emergency-admin-replacement.sql", emergency)
    # Exact replay is allowed, but must not duplicate either of the two
    # owner-audit events or reactivate the suspended municipality.
    client_output += private_owner_script(
        "stage-emergency-admin-replacement.sql", emergency)

    duplicate_review = dict(emergency)
    duplicate_review["COMUNI_EMERGENCY_MUNICIPAL_REVIEWER"] = security_review
    rejected_review = private_owner_script(
        "stage-emergency-admin-replacement.sql", duplicate_review,
        expect_failure=True)
    if "Invalid incident or independent review references" not in rejected_review:
        raise AssertionError("Duplicate synthetic emergency reviewers accepted")
    client_output += rejected_review

    alternate = dict(emergency)
    alternate["COMUNI_EMERGENCY_INCIDENT_TICKET"] = other_incident
    rejected_ticket = private_owner_script(
        "stage-emergency-admin-replacement.sql", alternate,
        expect_failure=True)
    if "Inactive or ambiguously staged Admin cannot be recovered" not in rejected_ticket:
        raise AssertionError("Different incident unexpectedly replayed staging")
    client_output += rejected_ticket

    # No identity/incident values in SQL strings or command arguments. Check
    # the pending second municipality and inactive global operator as well.
    verified = sql("""
        SELECT
            (SELECT count(*) FROM platform.organizations) = 2
        AND (SELECT count(*) FROM platform.organizations
             WHERE is_activated=TRUE AND is_suspended=TRUE) = 1
        AND (SELECT count(*) FROM platform.organizations
             WHERE is_activated=FALSE AND is_suspended=FALSE) = 1
        AND (SELECT count(*) FROM platform.organization_modules
             WHERE module_key='protocol' AND enabled=FALSE) = 2
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin') = 3
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=TRUE
               AND identity_issuer IS NOT NULL) = 1
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=FALSE
               AND identity_issuer IS NOT NULL) = 2
        AND (SELECT count(*) FROM platform.organization_memberships m
             JOIN platform.organizations o ON m.organization_id=o.id
             WHERE o.is_activated=FALSE) = 0
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action='platform.membership.admin.emergency.revoked') = 1
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action='platform.membership.admin.emergency.staged') = 1
        AND (SELECT count(*) FROM platform.audit_events) = 9
        AND (SELECT count(*) FROM platform.platform_operators
             WHERE is_active=FALSE) = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys) = 2
        """, "synthetic suspended emergency staging invariants")
    if verified != "t":
        raise AssertionError("Emergency staging violated tenant or audit invariants")

    after = run(["docker", "logs", container_name],
                "collect private emergency pgAudit log suffix",
                include_stderr=True)
    if not after.startswith(prefix):
        raise AssertionError("Cannot isolate emergency pgAudit log window")
    canaries = (
        org_id, old_issuer, old_subject, new_issuer, new_subject,
        incident, security_review, municipality_review, reason, other_incident,
    )
    assert_emergency_privacy(after[len(prefix):], client_output, canaries)




def assert_retirement_privacy(server_log: str, client_output: str,
                              canaries: tuple[str, ...]) -> None:
    """Preserve audit evidence without exposing synthetic rotation key IDs.

    This observes only the isolated server log suffix from the real SQL
    retirement; it is not validation of Azure, SIEM or base64 JSON envelopes.
    """
    categories = ("staged-replacement-key-id", "invalid-replacement-key-id")
    if len(canaries) != len(categories) or any(not item for item in canaries):
        raise AssertionError("Invalid synthetic retirement canary inventory")
    for category, item in zip(categories, canaries, strict=True):
        for sensitive in (item, base64.b64encode(item.encode("utf-8")).decode("ascii")):
            if sensitive in server_log:
                raise AssertionError("Retirement key identifier in PostgreSQL log: " + category)
            if sensitive in client_output:
                raise AssertionError("Retirement key identifier in client output: " + category)

    if "DO $owner_audit_parameter_guard$" not in server_log:
        raise AssertionError("Retirement parameter-policy DO statement missing")
    audit_lines = [line for line in server_log.splitlines()
                   if "AUDIT: SESSION" in line]
    if not any(",FUNCTION,DO," in line for line in audit_lines):
        raise AssertionError("Retirement pgAudit FUNCTION metadata missing")
    if not any(",WRITE,UPDATE," in line for line in audit_lines):
        raise AssertionError("Retirement pgAudit WRITE UPDATE metadata missing")
    if "statement: COPY" not in server_log:
        raise AssertionError("Retirement native COPY statement missing")


def verify_tenant_retirement_under_pgaudit(
    container_name: str, staged_id: str
) -> None:
    """Execute actual owner-only retirement under a live PostgreSQL17 pgAudit.

    The previous test provisioned a synthetic legacy and an active versioned
    successor. This test does NOT perform a real multi-replica key rollout.
    """
    prefix = run(["docker", "logs", container_name],
                 "baseline retirement pgAudit window", include_stderr=True)
    marker = uuid.uuid4().hex[:12]
    bad_replacement = "synthetic_invalid_" + marker
    retirement = {
        "TENANT_PROOF_RETIRE_KEY_ID": "legacy",
        "TENANT_PROOF_REPLACEMENT_KEY_ID": staged_id,
        "TENANT_PROOF_GRACE_SECONDS": "0",
    }

    # All SQL below is static, with no key IDs from the producer, secret
    # values or canaries interpolated into SQL text or command arguments.
    initial = sql("""
        SELECT
            (SELECT count(*) FROM platform.tenant_proof_keys) = 2
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id='legacy' AND revoked_at IS NULL
               AND valid_until > clock_timestamp()) = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id<>'legacy' AND revoked_at IS NULL
               AND valid_until > clock_timestamp()) = 1
        """, "retirement predecessor and successor preflight")
    if initial != "t":
        raise AssertionError("Synthetic retirement prerequisite keys missing")

    # Check existing synthetic signing material without printing it.
    stage_fingerprint_before = sql(
        "SELECT encode(public.digest(signing_key,'sha256'),'hex') "
        "FROM platform.tenant_proof_keys WHERE key_id<>'legacy'",
        "synthetic successor digest before retirement")

    denied = private_owner_script(
        "retire-tenant-proof-key.sql", retirement,
        expect_failure=True, metadata_only=False)
    if ("Owner-only retirement operation requires parameter-free audit metadata"
            not in denied):
        raise AssertionError("Unsafe retirement pgAudit parameter profile not rejected")

    guarded_logs = run(["docker", "logs", container_name],
                       "inspect denied retirement COPY boundary",
                       include_stderr=True)
    if not guarded_logs.startswith(prefix):
        raise AssertionError("Cannot isolate refused retirement pgAudit window")
    if "statement: COPY" in guarded_logs[len(prefix):]:
        raise AssertionError("Retirement with parameter logging reached COPY")

    still_active = sql("""
        SELECT
            (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE revoked_at IS NOT NULL) = 0
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE valid_until > clock_timestamp()) = 2
        """, "unsafe retirement must not mutate active keys")
    if still_active != "t":
        raise AssertionError("Unsafe retirement changed active signing-key state")

    client_output = denied
    client_output += private_owner_script("retire-tenant-proof-key.sql", retirement)
    # An exact replay must never clear revoked_at or lengthen a valid_until
    # window. The existing script deliberately uses LEAST and COALESCE.
    client_output += private_owner_script("retire-tenant-proof-key.sql", retirement)

    # The last usable successor cannot be retired by claiming that the
    # already-revoked legacy key is a replacement.
    unsafe_last = {
        "TENANT_PROOF_RETIRE_KEY_ID": staged_id,
        "TENANT_PROOF_REPLACEMENT_KEY_ID": "legacy",
        "TENANT_PROOF_GRACE_SECONDS": "0",
    }
    blocked = private_owner_script(
        "retire-tenant-proof-key.sql", unsafe_last, expect_failure=True)
    if "Retirement refused by safety guard" not in blocked:
        raise AssertionError("Unsafe last active key retirement not blocked")
    client_output += blocked

    # Unknown successor is also denied, without a new key or replacement.
    invalid_successor = dict(retirement)
    invalid_successor["TENANT_PROOF_REPLACEMENT_KEY_ID"] = bad_replacement
    blocked_missing = private_owner_script(
        "retire-tenant-proof-key.sql", invalid_successor,
        expect_failure=True)
    if "Retirement refused by safety guard" not in blocked_missing:
        raise AssertionError("Unprovisioned key replacement not blocked")
    client_output += blocked_missing

    verified = sql("""
        SELECT
            (SELECT count(*) FROM platform.tenant_proof_keys) = 2
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id='legacy' AND revoked_at IS NOT NULL
               AND valid_until <= clock_timestamp()) = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE key_id<>'legacy' AND revoked_at IS NULL
               AND not_before <= clock_timestamp()
               AND valid_until > clock_timestamp() + interval '300 seconds') = 1
        AND (SELECT count(*) FROM platform.tenant_proof_keys
             WHERE revoked_at IS NULL AND valid_until > clock_timestamp()) = 1
        AND NOT has_table_privilege('comuni_app_runtime',
                                    'platform.tenant_proof_keys', 'UPDATE')
        """, "retirement monotonicity and usable successor invariant")
    if verified != "t":
        raise AssertionError("Retirement altered successor or revived a key")

    stage_fingerprint_after = sql(
        "SELECT encode(public.digest(signing_key,'sha256'),'hex') "
        "FROM platform.tenant_proof_keys WHERE key_id<>'legacy'",
        "synthetic successor digest after retirement")
    if stage_fingerprint_before != stage_fingerprint_after:
        raise AssertionError("Retirement changed synthetic successor material")

    after = run(["docker", "logs", container_name],
                "collect isolated retirement pgAudit logs",
                include_stderr=True)
    if not after.startswith(prefix):
        raise AssertionError("Cannot isolate retirement pgAudit log suffix")
    assert_retirement_privacy(
        after[len(prefix):], client_output, (staged_id, bad_replacement))



def main() -> None:
    name = "comuni-pgaudit-ci-" + uuid.uuid4().hex[:8]
    container_started = False
    test_passwords: list[str] = []
    observed_verifiers: list[str] = []
    client_outputs: list[str] = []
    try:
        # The image is built from postgres:17-bookworm with the matching
        # postgresql-17-pgaudit package. No Azure or external database.
        env = os.environ.copy()
        env["POSTGRES_PASSWORD"] = OWNER_SECRET
        run(
            ["docker", "run", "-d", "--rm", "--name", name,
             "--publish", "127.0.0.1:" + PORT + ":5432",
             "--env", "POSTGRES_PASSWORD",
             "--env", "POSTGRES_DB=" + DB,
             "--env", "POSTGRES_USER=" + OWNER,
             DOCKER_IMAGE,
             "-c", "shared_preload_libraries=pgaudit",
             "-c", "log_statement=all",
             "-c", "log_parameter_max_length=-1",
             "-c", "log_parameter_max_length_on_error=-1"],
            "create isolated pgAudit PostgreSQL 17", env=env,
        )
        container_started = True
        ready = False
        for _ in range(50):
            # Docker's internal pg_isready may pass before the published host
            # port is available. Probe the actual TCP+SCRAM path that every
            # subsequent test uses to avoid flaky CI startup races.
            probe = subprocess.run(
                ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                 "-h", "127.0.0.1", "-p", PORT, "-U", OWNER,
                 "-d", DB, "-A", "-t", "-c", "SELECT 1"],
                cwd=ROOT, env=psql_env(PGOPTIONS=""),
                capture_output=True, text=True, check=False, timeout=5,
            )
            if probe.returncode == 0 and probe.stdout.strip() == "1":
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise AssertionError("pgAudit test PostgreSQL 17 TCP/auth was not ready")

        # CREATE EXTENSION before enabling ROLE and DDL pgAudit session logging.
        sql("CREATE EXTENSION IF NOT EXISTS pgaudit", "enable real pgAudit",
            env=psql_env(PGOPTIONS=""))
        installed = sql(
            "SELECT extversion FROM pg_extension WHERE extname='pgaudit'",
            "inspect pgAudit version",
        )
        if not installed:
            raise AssertionError("pgAudit extension not installed")

        migration_env = os.environ.copy()
        migration_env["ConnectionStrings__Default"] = (
            "Host=127.0.0.1;Port=" + PORT + ";Database=" + DB +
            ";Username=" + OWNER + ";Password=" + OWNER_SECRET
        )
        run(["bash", "scripts/migrate.sh"],
            "EF migrations in isolated pgAudit PostgreSQL",
            env=migration_env, timeout=210)

        # pgAudit SESSION role/ddl with max parameter logging. Both first
        # CREATE ROLE and subsequent ALTER ROLE are executed by real scripts.
        for role, file in (
            ("comuni_app_runtime", "provision-runtime-role.sql"),
            ("comuni_platform_reader", "provision-platform-read-role.sql"),
        ):
            initial = "ci-private-audit-" + role + "-" + uuid.uuid4().hex
            rotated = "ci-private-audit-rotation-" + role + "-" + uuid.uuid4().hex
            test_passwords.extend([initial, rotated])
            client_outputs.append(script(file, initial))
            old_verifier = verifier(role)
            observed_verifiers.append(old_verifier)
            assert_auth(role, initial)
            client_outputs.append(script(file, rotated))
            current_verifier = verifier(role)
            observed_verifiers.append(current_verifier)
            if current_verifier == old_verifier:
                raise AssertionError("SCRAM role rotation did not generate a new salt")
            assert_auth(role, rotated)

            # A failed COPY/input validation must rollback and preserve the
            # existing verifier and role permissions.
            client_outputs.append(script(file, None, expect_failure=True))
            if verifier(role) != current_verifier:
                raise AssertionError("Invalid role input did not rollback")
            assert_auth(role, rotated)

            # The restricted app account cannot grant or rotate SQL roles.
            if role == "comuni_platform_reader":
                denied_password = ("synthetic-runtime-denied-credential-" +
                                   uuid.uuid4().hex)
                test_passwords.append(denied_password)
                client_outputs.append(script(
                    file, denied_password, runtime=True,
                    owner_password=test_passwords[1], expect_failure=True,
                ))
                if verifier(role) != current_verifier:
                    raise AssertionError("Restricted runtime changed reader password")

        # Real pgAudit and native logs; never print their raw contents.
        logs = run(["docker", "logs", name], "collect private pgAudit logs",
                   include_stderr=True)
        assert_audits(
            logs, observed_verifiers, test_passwords,
            client_output="".join(client_outputs),
        )
        identity_context = verify_identity_under_pgaudit(name)
        verify_platform_and_provision_under_pgaudit(name)
        staged_id = verify_tenant_signing_keys_under_pgaudit(name)
        verify_emergency_under_pgaudit(name, identity_context)
        verify_tenant_retirement_under_pgaudit(name, staged_id)
        print("PASS: PostgreSQL17 pgAudit ROLE/DDL, SCRAM transport/client output " 
              "and twelve owner-only COPY "
              "operations verified; synthetic SCRAM/OIDC/signing-key/emergency/"
              "retirement canaries absent from captured logs.")
    finally:
        if container_started:
            # Always delete the synthetic roles and entire ephemeral cluster.
            subprocess.run(["docker", "rm", "-f", name],
                           capture_output=True, check=False, timeout=45)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        # Internal assertion messages contain only fixed stage labels, safe
        # role names and generic checks, NEVER query text or secrets.
        print("FAIL: pgAudit ROLE/DDL verifier-redaction gate: " + str(error),
              file=sys.stderr)
        sys.exit(1)
    except (OSError, subprocess.TimeoutExpired):
        print("FAIL: pgAudit ROLE/DDL verifier-redaction gate unavailable",
              file=sys.stderr)
        sys.exit(1)
