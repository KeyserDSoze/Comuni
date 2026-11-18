#!/usr/bin/env python3
"""One fixed-allowlist, single-record psql client-side COPY source.

The output contains *sensitive* data (base64 is NOT encryption), intended
EXCLUSIVELY for a private psql COPY FROM PROGRAM pipe into a temporary table.
Never execute this helper directly in a terminal or capture its stdout/logs.

See ADR 0073 and #88; not yet approved for production identities.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys

# Restrict operation names and their input sets to known, reviewed scripts.
# Extending this dictionary requires matching SQL, tests, and an ADR.
INPUTS: dict[str, tuple[str, ...]] = {
    "runtime-role": ("RUNTIME_DB_PASSWORD",),
    "platform-role": ("PLATFORM_READ_DB_PASSWORD",),
    # Signing keys are only read from the runner's protected environment;
    # NEVER forward the caller's complete environment to PostgreSQL.
    "tenant-legacy": ("TENANT_PROOF_KEY",),
    "tenant-stage": ("TENANT_PROOF_KEY_ID", "TENANT_PROOF_KEY"),
    "platform-operator": (
        "COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER",
        "COMUNI_PLATFORM_OPERATOR_SUBJECT",
        "COMUNI_PLATFORM_OPERATOR_ACTION",
        "COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET",
        "COMUNI_PLATFORM_OPERATOR_APPROVER",
    ),
    "revoke-admin": (
        "COMUNI_REVOKE_ADMIN_ORGANIZATION_ID",
        "COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER",
        "COMUNI_REVOKE_ADMIN_SUBJECT",
        "COMUNI_REVOKE_ADMIN_CHANGE_TICKET",
        "COMUNI_REVOKE_ADMIN_APPROVER",
        "COMUNI_REVOKE_ADMIN_REASON_CODE",
    ),
    "bootstrap-admin": (
        "COMUNI_BOOTSTRAP_ORGANIZATION_ID",
        "COMUNI_BOOTSTRAP_IDENTITY_ISSUER",
        "COMUNI_BOOTSTRAP_SUBJECT",
        "COMUNI_BOOTSTRAP_CHANGE_TICKET",
        "COMUNI_BOOTSTRAP_APPROVER",
    ),
    "add-admin": (
        "COMUNI_ADD_ADMIN_ORGANIZATION_ID",
        "COMUNI_ADD_ADMIN_IDENTITY_ISSUER",
        "COMUNI_ADD_ADMIN_SUBJECT",
        "COMUNI_ADD_ADMIN_CHANGE_TICKET",
        "COMUNI_ADD_ADMIN_APPROVER",
    ),
    "emergency": (
        "COMUNI_EMERGENCY_ORGANIZATION_ID",
        "COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER",
        "COMUNI_EMERGENCY_OLD_SUBJECT",
        "COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER",
        "COMUNI_EMERGENCY_NEW_SUBJECT",
        "COMUNI_EMERGENCY_INCIDENT_TICKET",
        "COMUNI_EMERGENCY_SECURITY_REVIEWER",
        "COMUNI_EMERGENCY_MUNICIPAL_REVIEWER",
        "COMUNI_EMERGENCY_REASON_CODE",
    ),
}
MAX_VALUE_BYTES = 1024
MAX_ENVELOPE_BYTES = 8192


def stream_one_record() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in INPUTS:
        raise ValueError("unsupported operation")

    values: dict[str, str] = {}
    for key in INPUTS[sys.argv[1]]:
        value = os.environ.get(key)
        if value is None or not value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ValueError("missing or oversized input")
        values[key] = value

    if sys.argv[1] in ("runtime-role", "platform-role"):
        # PostgreSQL 17 SCRAM-SHA-256 verifier structure. Client-side
        # derivation prevents the SQL/role password statement from ever
        # containing the plaintext password, even when DDL is logged.
        #
        # PostgreSQL normally applies SASLprep to Unicode passwords. Restrict
        # this offline operation to printable ASCII to avoid client/server
        # SASLprep mismatches. This deliberately rejects Unicode passwords.
        name = INPUTS[sys.argv[1]][0]
        raw = values[name]
        required = 32 if sys.argv[1] == "platform-role" else 24
        if (len(raw) < required or len(raw) > MAX_VALUE_BYTES
                or any(ord(char) < 0x20 or ord(char) > 0x7E for char in raw)):
            raise ValueError("invalid role password")
        salt = secrets.token_bytes(16)
        iterations = 4096
        salted = hashlib.pbkdf2_hmac("sha256", raw.encode("ascii"), salt, iterations)
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        def b64(item: bytes) -> str:
            return base64.b64encode(item).decode("ascii")
        # Never transmit the plaintext or the PBKDF2 intermediate.
        verifier = (f"SCRAM-SHA-256${iterations}:{b64(salt)}$"
                    f"{b64(stored_key)}:{b64(server_key)}")
        values = {"SCRAM_VERIFIER": verifier}

    payload = json.dumps(
        values, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise ValueError("oversized payload")

    # Base64 is purely a COPY transport encoding, NOT cryptography/redaction.
    # An ASCII line has no COPY delimiter, backslash, quote, or newline and
    # therefore cannot provoke a CSV parse error that exposes source columns.
    encoded = base64.b64encode(payload).decode("ascii")
    sys.stdout.write(encoded + "\n")


if __name__ == "__main__":
    try:
        stream_one_record()
    except (ValueError, UnicodeError, OSError):
        # A constant error, never an exception trace, secret, key or payload.
        print("Private input transport rejected", file=sys.stderr)
        sys.exit(2)
