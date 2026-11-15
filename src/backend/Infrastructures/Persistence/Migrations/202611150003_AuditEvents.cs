using System;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150003_AuditEvents")]
public sealed class AuditEvents : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "audit_events", schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                actor_subject = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                action = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                resource_type = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                resource_id = table.Column<Guid>(type: "uuid", nullable: false),
                correlation_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_audit_events", x => x.id);
                table.ForeignKey(
                    name: "fk_audit_events_organizations", column: x => x.organization_id,
                    principalSchema: "platform", principalTable: "organizations", principalColumn: "id",
                    onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateIndex(
            name: "ix_audit_events_organization_id_occurred_at",
            schema: "platform", table: "audit_events",
            columns: new[] { "organization_id", "occurred_at" });
        migrationBuilder.CreateIndex(
            name: "ix_audit_events_organization_id_resource_id",
            schema: "platform", table: "audit_events",
            columns: new[] { "organization_id", "resource_id" });

        // Database-level guard for ordinary DML; privileged DB superusers can alter database objects.
        migrationBuilder.Sql("""
            CREATE FUNCTION platform.reject_audit_change() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'Audit history is append-only' USING ERRCODE = '55000';
            END;
            $$;
            CREATE TRIGGER trg_audit_events_prevent_change
                BEFORE UPDATE OR DELETE ON platform.audit_events
                FOR EACH ROW EXECUTE FUNCTION platform.reject_audit_change();
            CREATE TRIGGER trg_audit_events_prevent_truncate
                BEFORE TRUNCATE ON platform.audit_events
                FOR EACH STATEMENT EXECUTE FUNCTION platform.reject_audit_change();
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "audit_events", schema: "platform");
        migrationBuilder.Sql("DROP FUNCTION platform.reject_audit_change();");
    }
}
