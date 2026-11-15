using System;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150002_OrganizationMemberships")]
public sealed class OrganizationMemberships : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "organization_memberships", schema: "platform",
            columns: table => new
            {
                organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                subject = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                role = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                is_active = table.Column<bool>(type: "boolean", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_organization_memberships",
                    x => new { x.organization_id, x.subject, x.role });
                table.ForeignKey(
                    name: "fk_memberships_organizations", column: x => x.organization_id,
                    principalSchema: "platform", principalTable: "organizations", principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
                table.CheckConstraint("ck_organization_memberships_role",
                    "role IN ('Admin','Officer','Reader')");
            });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "organization_memberships", schema: "platform");
    }
}
