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
        expected: int = 0, timeout: int = 110) -> str:
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
    return p.stdout


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


def assert_audits(log: str, verifiers: list[str],
                  passwords: list[str]) -> None:
    # Expect real pgAudit session entries, including nested CREATE/ALTER ROLE
    # (not just DO or COPY from PostgreSQL's native statement logging).
    audit_lines = [
        line for line in log.splitlines()
        if "AUDIT: SESSION" in line and ",ROLE," in line
    ]
    if not audit_lines:
        raise AssertionError("No real pgAudit ROLE events; check shared preload")
    for role in ("comuni_app_runtime", "comuni_platform_reader"):
        for command in ("CREATE ROLE", "ALTER ROLE"):
            if not any(
                "," + command + "," in line and role in line
                for line in audit_lines
            ):
                raise AssertionError("Expected pgAudit operation metadata missing: "
                                     + command + " " + role)
    if not any("<REDACTED>" in line for line in audit_lines):
        raise AssertionError("pgAudit password redaction was not observed")

    for candidate in passwords + verifiers:
        if candidate and candidate in log:
            # Do not echo the matching secret or the server log.
            raise AssertionError(
                "Sensitive role material leaked into PostgreSQL/pgAudit server logs")
    if "statement: COPY" not in log:
        raise AssertionError("No native COPY statement logged while pgAudit active")

    # Audited operations remain traceable, including GRANT/REVOKE and roles.
    if not any(",ROLE,GRANT," in line for line in audit_lines):
        raise AssertionError("Privilege-change audit events were suppressed")
    # This gate does not SET pgaudit.log = 'none' or SET log_statement = 'none'.


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
            probe = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-U", OWNER, "-d", DB],
                capture_output=True, text=True, check=False, timeout=5,
            )
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise AssertionError("pgAudit test PostgreSQL 17 did not become ready")

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
        logs = run(["docker", "logs", name], "collect private pgAudit logs")
        assert_audits(logs, observed_verifiers, test_passwords)
        print("PASS: real PostgreSQL17 pgAudit ROLE/DDL audit retained; "
              "CREATE/ALTER redacted, login and rollback proven; "
              "no canary plaintext/verifier in server logs.")
    finally:
        if container_started:
            # Always delete the synthetic roles and entire ephemeral cluster.
            subprocess.run(["docker", "rm", "-f", name],
                           capture_output=True, check=False, timeout=45)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.TimeoutExpired):
        # Security test failures must not print captured SQL, env or logs.
        print("FAIL: pgAudit ROLE/DDL verifier-redaction gate (see ADR 0076)",
              file=sys.stderr)
        sys.exit(1)
