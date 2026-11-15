using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150004_OrganizationSuspension")]
public sealed class OrganizationSuspension : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<bool>(
            name: "is_suspended", schema: "platform", table: "organizations",
            type: "boolean", nullable: false, defaultValue: false);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "is_suspended", schema: "platform", table: "organizations");
    }
}
