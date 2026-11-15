using System;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150001_InitialCreate")]
public sealed class InitialCreate : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.EnsureSchema(name: "platform");
        migrationBuilder.EnsureSchema(name: "protocol");

        migrationBuilder.CreateTable(
            name: "organizations", schema: "platform",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false)
            },
            constraints: table => table.PrimaryKey("pk_organizations", x => x.id));

        migrationBuilder.CreateTable(
            name: "organization_modules", schema: "platform",
            columns: table => new
            {
                organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                module_key = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                enabled = table.Column<bool>(type: "boolean", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_organization_modules", x => new { x.organization_id, x.module_key });
                table.ForeignKey("fk_modules_organizations", x => x.organization_id, "platform", "organizations", "id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "records", schema: "protocol",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                subject = table.Column<string>(type: "character varying(250)", maxLength: 250, nullable: false),
                registered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_records", x => x.id);
                table.ForeignKey("fk_records_organizations", x => x.organization_id, "platform", "organizations", "id", onDelete: ReferentialAction.Restrict);
            });

        migrationBuilder.CreateIndex(
            name: "ix_records_organization_id_registered_at",
            schema: "protocol", table: "records",
            columns: new[] { "organization_id", "registered_at" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "records", schema: "protocol");
        migrationBuilder.DropTable(name: "organization_modules", schema: "platform");
        migrationBuilder.DropTable(name: "organizations", schema: "platform");
    }
}
