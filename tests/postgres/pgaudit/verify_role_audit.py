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
           owner_password: str | None = None) -> None:
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
    run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
         "-p", PORT, "-U", role, "-d", DB, "-f",
         str(ROOT / "scripts" / "postgres" / name)],
        f"offline role script {name}" + (" denied" if expect_failure else ""),
        env=env, expected=1 if expect_failure else 0,
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
                  passwords: list[str]) -> None:
    # The complete verifier is not the only secret-equivalent representation:
    # fail if any salt, StoredKey or ServerKey is present anywhere in native,
    # extension or error-context logs, even without the full verifier.
    sensitive = [item for item in passwords + verifiers if item]
    for item in verifiers:
        sensitive.extend(scram_components(item))
    if any(value in log for value in sensitive):
        # Never print the candidate or raw server log.
        raise AssertionError(
            "Sensitive SCRAM material leaked into PostgreSQL/pgAudit server logs")

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
                   "DO $activation$", "DO $enrollment$"):
        if marker not in server_log:
            raise AssertionError("Owner-only operation missing from PostgreSQL logs")
    audit_lines = [
        line for line in server_log.splitlines()
        if "AUDIT: SESSION" in line
    ]
    if sum(",FUNCTION,DO," in line for line in audit_lines) < 4:
        raise AssertionError("Owner-only operations missing pgAudit FUNCTION events")
    if not any(",WRITE,INSERT," in line for line in audit_lines):
        raise AssertionError("Owner-only operations missing pgAudit WRITE events")
    if not any(",WRITE,UPDATE," in line for line in audit_lines):
        raise AssertionError("Municipal activation missing pgAudit UPDATE event")
    if server_log.count("statement: COPY") < 4:
        raise AssertionError("Private client COPY statements not logged")


def private_owner_script(file: str, values: dict[str, str],
                         expect_failure: bool = False,
                         metadata_only: bool = True) -> str:
    """Use only static, reviewed script paths and private environment values."""
    if file not in (
        "register-organization.sql", "bootstrap-initial-admin.sql",
        "activate-organization.sql", "enroll-additional-admin.sql",
    ):
        raise AssertionError("Unreviewed owner identity script")
    env = psql_env(**values)
    if metadata_only:
        # pgAudit FUNCTION/WRITE records remain enabled. The parameter field
        # alone must be suppressed for private owner input. All four scripts
        # independently REFUSE parameter=on before COPY transport begins.
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


def verify_identity_under_pgaudit(container_name: str) -> None:
    """Test real full municipal/Admin onboarding under full pgAudit.

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

    # This query contains *only static SQL*, never organization ID, subject,
    # issuer, ticket, or reviewer. The isolated DB starts with zero tenants.
    verified = sql("""
        SELECT
           (SELECT count(*) FROM platform.organizations
            WHERE is_activated=TRUE AND is_suspended=FALSE) = 1
        AND (SELECT count(*) FROM platform.organization_modules
             WHERE module_key='protocol' AND enabled=FALSE) = 1
        AND (SELECT count(*) FROM platform.organization_memberships
             WHERE role='Admin' AND is_active=TRUE
               AND identity_issuer IS NOT NULL) = 2
        AND (SELECT count(*) FROM platform.audit_events
             WHERE action IN ('platform.organization.registered',
                              'platform.membership.admin.initialized',
                              'platform.organization.activated',
                              'platform.membership.admin.added')) = 4
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
    )
    assert_identity_privacy(after[len(prefix):], client_output, canaries)

def main() -> None:
    name = "comuni-pgaudit-ci-" + uuid.uuid4().hex[:8]
    container_started = False
    test_passwords: list[str] = []
    observed_verifiers: list[str] = []
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
            script(file, initial)
            old_verifier = verifier(role)
            observed_verifiers.append(old_verifier)
            assert_auth(role, initial)
            script(file, rotated)
            current_verifier = verifier(role)
            observed_verifiers.append(current_verifier)
            if current_verifier == old_verifier:
                raise AssertionError("SCRAM role rotation did not generate a new salt")
            assert_auth(role, rotated)

            # A failed COPY/input validation must rollback and preserve the
            # existing verifier and role permissions.
            script(file, None, expect_failure=True)
            if verifier(role) != current_verifier:
                raise AssertionError("Invalid role input did not rollback")
            assert_auth(role, rotated)

            # The restricted app account cannot grant or rotate SQL roles.
            if role == "comuni_platform_reader":
                script(file, "synthetic-runtime-denied-credential-" +
                       uuid.uuid4().hex, runtime=True,
                       owner_password=test_passwords[1], expect_failure=True)
                if verifier(role) != current_verifier:
                    raise AssertionError("Restricted runtime changed reader password")

        # Real pgAudit and native logs; never print their raw contents.
        logs = run(["docker", "logs", name], "collect private pgAudit logs",
                   include_stderr=True)
        assert_audits(logs, observed_verifiers, test_passwords)
        verify_identity_under_pgaudit(name)
        print("PASS: PostgreSQL17 pgAudit ROLE/DDL and owner identity COPY verified; "
              "synthetic SCRAM and OIDC canaries absent from captured logs.")
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
