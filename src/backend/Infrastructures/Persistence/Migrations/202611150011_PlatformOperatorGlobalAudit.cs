using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

/// <summary>
/// Platform-wide audit is intentionally separate from tenant audit; no fake
/// organization id is used to record platform operator lifecycle events.
/// </summary>
[DbContext(typeof(ComuniDbContext))]
[Migration("202611150011_PlatformOperatorGlobalAudit")]
public sealed class PlatformOperatorGlobalAudit : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            -- Stable random ID avoids storing issuer or subject in audit data.
            -- Existing synthetic rows get their own random ID, no activation
            -- or backfill of identity-issuer mappings occurs.
            ALTER TABLE platform.platform_operators
                ADD COLUMN operator_id uuid NOT NULL DEFAULT gen_random_uuid();
            ALTER TABLE platform.platform_operators
                ADD CONSTRAINT uq_platform_operator_id UNIQUE (operator_id);

            CREATE TABLE platform.platform_operator_audit_events (
                id uuid PRIMARY KEY,
                actor_subject character varying(160) NOT NULL,
                action character varying(120) NOT NULL,
                resource_type character varying(100) NOT NULL,
                resource_id uuid NOT NULL,
                correlation_id character varying(128) NOT NULL,
                occurred_at timestamp with time zone NOT NULL
            );

            CREATE INDEX ix_platform_operator_audit_events_resource_time
                ON platform.platform_operator_audit_events(resource_id, occurred_at);

            -- Reuse DB-level audit history rejection defined in migration 0003.
            CREATE TRIGGER trg_platform_operator_audit_prevent_change
                BEFORE UPDATE OR DELETE ON platform.platform_operator_audit_events
                FOR EACH ROW EXECUTE FUNCTION platform.reject_audit_change();
            CREATE TRIGGER trg_platform_operator_audit_prevent_truncate
                BEFORE TRUNCATE ON platform.platform_operator_audit_events
                FOR EACH STATEMENT EXECUTE FUNCTION platform.reject_audit_change();

            REVOKE ALL ON TABLE platform.platform_operator_audit_events FROM PUBLIC;
            REVOKE ALL ON TABLE platform.platform_operators FROM PUBLIC;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Platform operator audit is append-only and cannot be silently dropped.");
}
