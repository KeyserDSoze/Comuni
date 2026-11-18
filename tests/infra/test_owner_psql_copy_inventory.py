"""Global owner-only private psql COPY inventory contract (#105).

An offline, deterministic Python stdlib guard for every reviewed private
transport operation. Does not inspect live PostgreSQL, pgAudit, Azure or PII.
"""
import ast
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts" / "postgres"
HELPER = SCRIPTS / "stream-private-input.py"
MANIFEST = ROOT / "docs" / "security" / "owner-only-psql-private-input-inventory.json"

# Explicit review boundary: adding a new owner script also requires changing
# this test, the inventory, ADR and applicable xUnit/PostgreSQL regressions.
EXPECTED_OPERATIONS = {
    "revoke-admin.sql": "revoke-admin",
    "register-organization.sql": "register-organization",
    "activate-organization.sql": "activate-organization",
    "provision-organization.sql": "provision-organization",
    "retire-tenant-proof-key.sql": "retire-tenant-proof",
    "bootstrap-initial-admin.sql": "bootstrap-admin",
    "manage-platform-operator.sql": "platform-operator",
    "set-organization-suspension.sql": "organization-lifecycle",
    "stage-emergency-admin-replacement.sql": "emergency",
    "enroll-additional-admin.sql": "add-admin",
    "provision-runtime-role.sql": "runtime-role",
    "provision-platform-read-role.sql": "platform-role",
    "provision-tenant-proof.sql": "tenant-legacy",
    "stage-tenant-proof-key.sql": "tenant-stage",
}
VALID_CLASSES = {
    "municipality-metadata",
    "identity-and-approval",
    "key-and-password",
    "key-retirement-metadata",
}
LITERAL = re.compile(r":'[a-zA-Z_][a-zA-Z0-9_]*'")
GETENV = re.compile(r"(?m)^\s*\\getenv\s+\S+\s+([A-Z][A-Z0-9_]+)\s*$")
COPY = re.compile(r"(?m)^\\copy[^\n]*$")
COPY_PREFIX = (
    r"\copy pg_temp.comuni_private_input(payload) "
    r"FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py "
)
COPY_SUFFIX = r"' WITH (FORMAT csv)"


def active_lines(sql):
    """Remove whole-line comments, never suppress actual psql or SQL lines."""
    return "\n".join(
        line for line in sql.splitlines()
        if not line.lstrip().startswith("--")
    )


def helper_allowlists():
    # Parse without executing the helper or accessing environment secrets.
    source = ast.parse(HELPER.read_text(encoding="utf-8"))
    definitions = [
        node for node in source.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "INPUTS"
    ]
    assert len(definitions) == 1, "Expected one literal INPUTS declaration"
    result = ast.literal_eval(definitions[0].value)
    assert isinstance(result, dict)
    return result


def validate_private_sql(sql, operation):
    code = active_lines(sql)
    if LITERAL.search(code):
        raise AssertionError("Unreviewed psql quoted-literal input")
    if re.search(r"(?m)^\s*\\echo\s+:", code):
        raise AssertionError("Unreviewed psql variable echo")
    if not re.search(r"(?m)^\\set ON_ERROR_STOP on$", code):
        raise AssertionError("Missing fail-closed psql ON_ERROR_STOP")
    if not re.search(r"(?m)^BEGIN;$", code):
        raise AssertionError("Missing owner-only transaction")
    if "CREATE TEMP TABLE pg_temp.comuni_private_input" not in code:
        raise AssertionError("Private temporary table is missing")
    if "ON COMMIT DROP" not in code:
        raise AssertionError("Private payload must be dropped")
    if "FROM pg_temp.comuni_private_input" not in code:
        raise AssertionError("Private payload must be consumed by SQL")
    copies = COPY.findall(code)
    expected = COPY_PREFIX + operation + COPY_SUFFIX
    if copies != [expected]:
        raise AssertionError("Missing or dynamic/duplicated client-side COPY")
    if not (code.index("BEGIN;") <
            code.index("CREATE TEMP TABLE pg_temp.comuni_private_input") <
            code.index(expected)):
        raise AssertionError("Private COPY must stay within the transaction")
    return GETENV.findall(code)


class OwnerPsqlCopyInventoryTests(unittest.TestCase):
    def test_manifest_is_complete_and_matches_literal_helper_allowlists(self):
        self.assertTrue(MANIFEST.is_file(), "RED: reviewed owner input inventory missing")
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(1, document["schema_version"])
        rows = document["operations"]
        self.assertEqual(14, len(rows))
        self.assertEqual(set(EXPECTED_OPERATIONS), {r["script"] for r in rows})
        self.assertEqual(set(EXPECTED_OPERATIONS.values()), {r["operation"] for r in rows})
        self.assertEqual(14, len({r["script"] for r in rows}))
        self.assertEqual(14, len({r["operation"] for r in rows}))

        allowlists = helper_allowlists()
        self.assertEqual(set(EXPECTED_OPERATIONS.values()), set(allowlists))
        for row in rows:
            with self.subTest(script=row["script"]):
                self.assertEqual(EXPECTED_OPERATIONS[row["script"]], row["operation"])
                self.assertIn(row["classification"], VALID_CLASSES)
                self.assertEqual(
                    tuple(row["environment_variables"]),
                    allowlists[row["operation"]],
                )
                self.assertEqual(
                    len(row["environment_variables"]),
                    len(set(row["environment_variables"])),
                )
                self.assertTrue(all(key.isupper() for key in row["environment_variables"]))

    def test_every_manifest_script_has_a_static_private_client_copy(self):
        rows = json.loads(MANIFEST.read_text(encoding="utf-8"))["operations"]
        for row in rows:
            with self.subTest(script=row["script"]):
                sql = (SCRIPTS / row["script"]).read_text(encoding="utf-8")
                env = validate_private_sql(sql, row["operation"])
                if env:
                    self.assertEqual(
                        set(env), set(row["environment_variables"]),
                        "psql preflight and client helper must use the same env",
                    )

    def test_any_new_owner_sensitive_script_must_be_registered(self):
        # Detect new scripts even when the author forgets the fixed helper.
        identified = set()
        for script in SCRIPTS.glob("*.sql"):
            code = active_lines(script.read_text(encoding="utf-8"))
            if GETENV.search(code) or LITERAL.search(code) or (
                "stream-private-input.py" in code
            ):
                identified.add(script.name)
        self.assertEqual(set(EXPECTED_OPERATIONS), identified)

    def test_mutation_gate_rejects_inline_input_and_dynamic_copy(self):
        reference = (SCRIPTS / "register-organization.sql").read_text(encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "quoted-literal"):
            validate_private_sql(
                reference + "\nSELECT set_config('comuni.x', :'register_name', true);\n",
                "register-organization",
            )
        with self.assertRaisesRegex(AssertionError, "dynamic/duplicated"):
            validate_private_sql(
                reference.replace(
                    COPY_PREFIX + "register-organization" + COPY_SUFFIX,
                    r"\copy pg_temp.comuni_private_input(payload) FROM PROGRAM :'program'",
                ),
                "register-organization",
            )

    def test_shared_client_helper_limits_are_fail_closed(self):
        code = HELPER.read_text(encoding="utf-8")
        self.assertIn("MAX_VALUE_BYTES = 1024", code)
        self.assertIn("MAX_ENVELOPE_BYTES = 8192", code)
        self.assertIn("Private input transport rejected", code)
        self.assertIn("except (ValueError, UnicodeError, OSError)", code)
        self.assertIn("base64.b64encode(payload)", code)


if __name__ == "__main__":
    unittest.main()
