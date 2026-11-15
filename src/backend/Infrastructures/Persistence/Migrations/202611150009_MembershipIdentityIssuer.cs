using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
[Migration("202611150009_MembershipIdentityIssuer")]
public sealed class MembershipIdentityIssuer : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Intentionally no default and NO automatic backfill. Identity issuer
        // cannot be inferred safely from a previous subject-only membership.
        migrationBuilder.AddColumn<string>(
            name: "identity_issuer", schema: "platform",
            table: "organization_memberships",
            type: "character varying(512)", maxLength: 512, nullable: true);
        migrationBuilder.Sql("""
            ALTER TABLE platform.organization_memberships
            ADD CONSTRAINT ck_membership_identity_issuer_https
            CHECK (identity_issuer IS NULL OR
                  (identity_issuer LIKE 'https://%' AND
                   identity_issuer !~ '[?#]'));
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            ALTER TABLE platform.organization_memberships
            DROP CONSTRAINT IF EXISTS ck_membership_identity_issuer_https;
            """);
        migrationBuilder.DropColumn(name: "identity_issuer",
            schema: "platform", table: "organization_memberships");
    }
}
