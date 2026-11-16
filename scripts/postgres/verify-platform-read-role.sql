\set ON_ERROR_STOP on

-- Run as migration/schema owner from a PRIVATE PostgreSQL runner, only after
-- migration 0012 and provision-platform-read-role.sql. READ-ONLY; no secret
-- values or platform operator identities are queried or printed.
BEGIN READ ONLY;

DO $verify$
DECLARE
    v_platform_role oid;
BEGIN
    SELECT oid INTO v_platform_role
    FROM pg_roles WHERE rolname = 'comuni_platform_reader';
    IF v_platform_role IS NULL THEN
        RAISE EXCEPTION 'Restricted platform inventory SQL role is missing';
    END IF;

    -- No owner/admin powers, RLS bypass, inherited roles or ownership.
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE oid = v_platform_role
          AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
               OR rolbypassrls OR rolinherit)
    ) OR EXISTS (
        SELECT 1 FROM pg_auth_members WHERE member = v_platform_role
    ) OR EXISTS (
        SELECT 1 FROM pg_class WHERE relowner = v_platform_role
    ) THEN
        RAISE EXCEPTION 'Platform inventory SQL role is overprivileged';
    END IF;

    IF NOT has_schema_privilege('comuni_platform_reader', 'platform', 'USAGE')
       OR has_schema_privilege('comuni_platform_reader', 'platform', 'CREATE')
       OR has_schema_privilege('comuni_platform_reader', 'protocol', 'USAGE')
       OR has_schema_privilege('comuni_platform_reader', 'protocol', 'CREATE')
    THEN
        RAISE EXCEPTION 'Platform inventory SQL schema privileges are invalid';
    END IF;

    IF NOT has_table_privilege('comuni_platform_reader',
                              'platform.platform_organization_inventory', 'SELECT')
       OR NOT has_function_privilege('comuni_platform_reader',
                              'platform.active_platform_operator_id(text,text)', 'EXECUTE')
       OR NOT has_any_column_privilege('comuni_platform_reader',
                              'platform.platform_operator_audit_events', 'INSERT')
       OR has_table_privilege('comuni_platform_reader',
                              'platform.platform_operator_audit_events', 'SELECT')
       OR has_table_privilege('comuni_platform_reader',
                              'platform.platform_operator_audit_events', 'UPDATE')
       OR has_table_privilege('comuni_platform_reader',
                              'platform.platform_operator_audit_events', 'DELETE')
       OR has_table_privilege('comuni_platform_reader',
                              'platform.platform_organization_inventory', 'INSERT')
       OR has_table_privilege('comuni_platform_reader',
                              'platform.platform_organization_inventory', 'UPDATE')
       OR has_table_privilege('comuni_platform_reader',
                              'platform.platform_organization_inventory', 'DELETE')
    THEN
        RAISE EXCEPTION 'Platform inventory allowlist is invalid';
    END IF;

    -- The view is an owner-context RLS bypass. Treat addition of even one
    -- extra column as a security-sensitive schema migration.
    IF (
        SELECT array_agg(attname::text ORDER BY attnum)
        FROM pg_attribute
        WHERE attrelid = 'platform.platform_organization_inventory'::regclass
          AND attnum > 0 AND NOT attisdropped
    ) IS DISTINCT FROM ARRAY['id', 'name', 'is_suspended', 'protocol_enabled', 'lifecycle_status']
    THEN
        RAISE EXCEPTION 'Platform inventory view has unexpected columns';
    END IF;

    -- Deny direct reads/updates of ALL present and future relations in the
    -- platform/protocol namespaces, except the explicitly approved view and
    -- COLUMN-RESTRICTED INSERT on the global audit table.
    IF EXISTS (
        SELECT 1 FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('platform', 'protocol')
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND c.oid <> 'platform.platform_organization_inventory'::regclass
          AND (
              has_any_column_privilege('comuni_platform_reader', c.oid, 'SELECT')
              OR has_any_column_privilege('comuni_platform_reader', c.oid, 'UPDATE')
              OR has_table_privilege('comuni_platform_reader', c.oid, 'DELETE')
              OR has_table_privilege('comuni_platform_reader', c.oid, 'TRUNCATE')
              OR has_table_privilege('comuni_platform_reader', c.oid, 'TRIGGER')
              OR (
                  c.oid <> 'platform.platform_operator_audit_events'::regclass
                  AND has_any_column_privilege('comuni_platform_reader', c.oid, 'INSERT')
              )
          )
    ) OR EXISTS (
        SELECT 1 FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('platform', 'protocol') AND c.relkind = 'S'
          AND (
              has_sequence_privilege('comuni_platform_reader', c.oid, 'USAGE')
              OR has_sequence_privilege('comuni_platform_reader', c.oid, 'SELECT')
              OR has_sequence_privilege('comuni_platform_reader', c.oid, 'UPDATE')
          )
    ) THEN
        RAISE EXCEPTION 'Platform inventory SQL role can access unrelated data';
    END IF;

    -- SQL injection under the municipal runtime login MUST NOT cross into
    -- the owner-context inventory view or global platform audit resolver.
    IF has_table_privilege('comuni_app_runtime',
                           'platform.platform_organization_inventory', 'SELECT')
       OR has_function_privilege('comuni_app_runtime',
                           'platform.active_platform_operator_id(text,text)', 'EXECUTE')
    THEN
        RAISE EXCEPTION 'Municipal runtime acquired forbidden global privileges';
    END IF;
END
$verify$;

COMMIT;
\echo 'Platform inventory SQL privileges verified (read-only, no secret values).'
