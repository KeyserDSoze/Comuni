#!/usr/bin/env python3
"""One fixed-allowlist, single-record psql client-side COPY source.

The output contains *sensitive* data (base64 is NOT encryption), intended
EXCLUSIVELY for a private psql COPY FROM PROGRAM pipe into a temporary table.
Never execute this helper directly in a terminal or capture its stdout/logs.

See ADR 0073 and #88; not yet approved for production identities.
"""

import base64
import json
import os
import sys

# Restrict operation names and their input sets to known, reviewed scripts.
# Extending this dictionary requires matching SQL, tests, and an ADR.
INPUTS: dict[str, tuple[str, ...]] = {
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
