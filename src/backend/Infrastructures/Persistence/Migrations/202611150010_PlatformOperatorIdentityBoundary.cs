using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

/// <summary>
/// Additive, unseeded platform identity boundary. No tenant membership migration.
/// This table is NOT mapped to the DbContext: runtime receives only a boolean
/// SECURITY DEFINER function, never direct table grants or roster endpoints.
/// </summary>
[DbContext(typeof(ComuniDbContext))]
[Migration("202611150010_PlatformOperatorIdentityBoundary")]
public sealed class PlatformOperatorIdentityBoundary : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            CREATE TABLE platform.platform_operators (
                identity_issuer character varying(512) NOT NULL,
                subject character varying(160) NOT NULL,
                is_active boolean NOT NULL DEFAULT FALSE,
                CONSTRAINT pk_platform_operators PRIMARY KEY (identity_issuer, subject),
                CONSTRAINT ck_platform_operator_issuer_https CHECK (
                    identity_issuer LIKE 'https://%' AND identity_issuer !~ '[?#]'
                ),
                CONSTRAINT ck_platform_operator_subject_exact CHECK (
                    length(subject) BETWEEN 1 AND 160 AND
                    subject = btrim(subject) AND
                    subject !~ '[[:cntrl:]]'
                )
            );
            -- Explicitly no public table privilege, including for the SQL runtime.
            REVOKE ALL ON TABLE platform.platform_operators FROM PUBLIC;

            -- Only an exact (issuer, subject) active-state check, not an operator
            -- listing; callers never receive roster data or operator attributes.
            CREATE FUNCTION platform.is_active_platform_operator(
                candidate_issuer text, candidate_subject text
            ) RETURNS boolean
            LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path = pg_catalog, platform
            AS $operator_check$
                SELECT EXISTS (
                    SELECT 1 FROM platform.platform_operators
                    WHERE identity_issuer = candidate_issuer
                      AND subject = candidate_subject
                      AND is_active = TRUE
                );
            $operator_check$;
            REVOKE ALL ON FUNCTION platform.is_active_platform_operator(text, text)
                FROM PUBLIC;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            DROP FUNCTION IF EXISTS platform.is_active_platform_operator(text, text);
            DROP TABLE IF EXISTS platform.platform_operators;
            """);
    }
}
