using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>Real PostgreSQL 17 row security tests against the non-owner runtime role.</summary>
public sealed class TenantRlsTests
{
    private static string Runtime =>
        Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_RUNTIME_DATABASE_CONNECTION is required.");
    private static string Owner =>
        Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION is required.");

    [Fact]
    public async Task SQL_injection_cannot_switch_tenants_by_setting_unsigned_GUC_or_forging_proof()
    {
        var first = await SeedAsync();
        var second = await SeedAsync();
        await using var connection = new NpgsqlConnection(Runtime);
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();

        // Reproduces the existing vulnerability: no cryptographic proof of the tenant.
        await using (var spoof = new NpgsqlCommand(
            "SELECT set_config('comuni.organization_id', @org, true)", connection, transaction))
        {
            spoof.Parameters.AddWithValue("org", second.ToString("D"));
            await spoof.ExecuteScalarAsync();
        }
        Assert.Equal(0L, await CountAsync(connection, transaction, "protocol.records"));

        var fake = $"{second:N}|{DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds()}|{Guid.NewGuid():N}|{new string('0', 64)}";
        await using (var spoof = new NpgsqlCommand(
            "SELECT set_config('comuni.tenant_assertion', @token, true)", connection, transaction))
        {
            spoof.Parameters.AddWithValue("token", fake);
            await spoof.ExecuteScalarAsync();
        }
        Assert.Equal(0L, await CountAsync(connection, transaction, "platform.organizations"));

        await SelectTenantAsync(connection, transaction, first);
        // The old unsigned organization-id setting cannot override a valid signed proof.
        await using (var spoof = new NpgsqlCommand(
            "SELECT set_config('comuni.organization_id', @org, true)", connection, transaction))
        {
            spoof.Parameters.AddWithValue("org", second.ToString("D"));
            await spoof.ExecuteScalarAsync();
        }
        Assert.Equal(1L, await CountAsync(connection, transaction, "platform.organizations"));

        // Untrusted runtime SQL cannot read the DB-side HMAC signing material.
        await using (var secret = new NpgsqlCommand(
            "SELECT signing_key FROM platform.tenant_proof_secret", connection, transaction))
        {
            var exception = await Assert.ThrowsAsync<PostgresException>(
                () => secret.ExecuteScalarAsync());
            Assert.Equal("42501", exception.SqlState);
        }
    }

    [Fact]
    public async Task Prepared_statement_rechecks_HMAC_on_every_execution_and_rejects_tenant_substitution()
    {
        var authorized = await SeedAsync();
        var other = await SeedAsync();
        var signer = new TenantProofSigner(
            Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Missing test signer key."));
        var valid = signer.Create(authorized);
        var forged = valid.Replace(authorized.ToString("N"), other.ToString("N"), StringComparison.Ordinal);
        Assert.NotEqual(valid, forged);

        await using var connection = new NpgsqlConnection(Runtime);
        await connection.OpenAsync();
        await using (var tx = await connection.BeginTransactionAsync())
        {
            await using (var prepared = new NpgsqlCommand(
                "PREPARE tenant_count AS SELECT count(*) FROM protocol.records", connection, tx))
                await prepared.ExecuteNonQueryAsync();

            async Task<long> ExecutePreparedAsync()
            {
                await using var cmd = new NpgsqlCommand("EXECUTE tenant_count", connection, tx);
                return (long)(await cmd.ExecuteScalarAsync())!;
            }

            async Task SetProofAsync(string assertion)
            {
                await using var set = new NpgsqlCommand(
                    "SELECT set_config('comuni.tenant_assertion', @assertion, true)", connection, tx);
                set.Parameters.AddWithValue("assertion", assertion);
                await set.ExecuteScalarAsync();
            }

            await SetProofAsync(valid);
            Assert.Equal(1L, await ExecutePreparedAsync());

            // A proof for A is never valid for B just because an injected query edits its tenant.
            await SetProofAsync(forged);
            Assert.Equal(0L, await ExecutePreparedAsync());

            // The old unsigned GUC must have no effect on a forged assertion.
            await using (var unsigned = new NpgsqlCommand(
                "SELECT set_config('comuni.organization_id', @tenant, true)", connection, tx))
            {
                unsigned.Parameters.AddWithValue("tenant", other.ToString("D"));
                await unsigned.ExecuteScalarAsync();
            }
            Assert.Equal(0L, await ExecutePreparedAsync());

            await SetProofAsync(valid);
            Assert.Equal(1L, await ExecutePreparedAsync());
            await tx.CommitAsync();
        }

        await using (var withoutTenant = new NpgsqlCommand(
            "EXECUTE tenant_count", connection))
            Assert.Equal(0L, (long)(await withoutTenant.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task All_five_tenant_owned_tables_have_RLS_enabled()
    {
        await using var connection = new NpgsqlConnection(Owner);
        await connection.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT count(*)
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE (n.nspname, c.relname) IN
              (('platform', 'organizations'),
               ('platform', 'organization_modules'),
               ('platform', 'organization_memberships'),
               ('platform', 'audit_events'),
               ('protocol', 'records'))
              AND c.relrowsecurity
            """, connection);
        Assert.Equal(5L, (long)(await cmd.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task SQL_runtime_without_transaction_tenant_context_sees_zero_rows()
    {
        var org = await SeedAsync();
        await using var connection = new NpgsqlConnection(Runtime);
        await connection.OpenAsync();

        Assert.Equal(0L, await CountAsync(connection, null, "platform.organizations"));
        Assert.Equal(0L, await CountAsync(connection, null, "platform.organization_modules"));
        Assert.Equal(0L, await CountAsync(connection, null, "platform.organization_memberships"));
        Assert.Equal(0L, await CountAsync(connection, null, "protocol.records"));
        // Audit is intentionally INSERT-only, never SELECT for the runtime login.
        Assert.NotEqual(Guid.Empty, org);
    }

    [Fact]
    public async Task SET_LOCAL_filters_raw_SQL_to_tenant_and_does_not_leak_after_commit_or_pool_reuse()
    {
        var first = await SeedAsync();
        var second = await SeedAsync();
        await using (var connection = new NpgsqlConnection(Runtime))
        {
            await connection.OpenAsync();
            await using (var tx = await connection.BeginTransactionAsync())
            {
                await SelectTenantAsync(connection, tx, first);
                Assert.Equal(1L, await CountAsync(connection, tx, "protocol.records"));
                Assert.Equal(1L, await CountAsync(connection, tx, "platform.organizations"));
                Assert.Equal(1L, await CountAsync(connection, tx, "platform.organization_modules"));
                Assert.Equal(1L, await CountAsync(connection, tx, "platform.organization_memberships"));
                await tx.CommitAsync();
            }

            Assert.Equal(0L, await CountAsync(connection, null, "protocol.records"));
            await using (var tx = await connection.BeginTransactionAsync())
            {
                await SelectTenantAsync(connection, tx, second);
                Assert.Equal(1L, await CountAsync(connection, tx, "protocol.records"));
                await tx.CommitAsync();
            }
            Assert.Equal(0L, await CountAsync(connection, null, "platform.organizations"));
        }
        // Reopening can reuse the pooled physical connection, but must not retain the tenant.
        await using var reopened = new NpgsqlConnection(Runtime);
        await reopened.OpenAsync();
        Assert.Equal(0L, await CountAsync(reopened, null, "protocol.records"));
    }

    [Fact]
    public async Task SQL_runtime_cannot_insert_cross_tenant_record_or_update_cross_tenant_module()
    {
        var first = await SeedAsync();
        var second = await SeedAsync();
        await using var connection = new NpgsqlConnection(Runtime);
        await connection.OpenAsync();
        await using (var tx = await connection.BeginTransactionAsync())
        {
            await SelectTenantAsync(connection, tx, first);
            await using var update = new NpgsqlCommand(
                "UPDATE platform.organization_modules SET enabled = FALSE WHERE organization_id = @org",
                connection, tx);
            update.Parameters.AddWithValue("org", second);
            Assert.Equal(0, await update.ExecuteNonQueryAsync());
            await tx.CommitAsync();
        }

        await using (var tx = await connection.BeginTransactionAsync())
        {
            await SelectTenantAsync(connection, tx, first);
            await using var insert = new NpgsqlCommand("""
                INSERT INTO protocol.records (id, organization_id, subject, registered_at)
                VALUES (@id, @org, 'Untrusted cross tenant', NOW())
                """, connection, tx);
            insert.Parameters.AddWithValue("id", Guid.NewGuid());
            insert.Parameters.AddWithValue("org", second);
            var violation = await Assert.ThrowsAsync<PostgresException>(
                () => insert.ExecuteNonQueryAsync());
            Assert.Equal("42501", violation.SqlState);
            await tx.RollbackAsync();
        }

        await using var admin = new NpgsqlConnection(Owner);
        await admin.OpenAsync();
        await using var verify = new NpgsqlCommand(
            "SELECT enabled FROM platform.organization_modules WHERE organization_id = @org AND module_key = 'protocol'",
            admin);
        verify.Parameters.AddWithValue("org", second);
        Assert.True((bool)(await verify.ExecuteScalarAsync())!);
    }

    private static async Task<Guid> SeedAsync()
    {
        var organization = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(Owner);
        await connection.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name) VALUES (@org, 'RLS municipality');
            INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
              VALUES (@org, 'protocol', TRUE);
            INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active)
              VALUES (@org, 'rls-officer', 'Officer', TRUE);
            INSERT INTO protocol.records (id, organization_id, subject, registered_at)
              VALUES (@id, @org, 'RLS sample', NOW());
            """, connection);
        cmd.Parameters.AddWithValue("org", organization);
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        await cmd.ExecuteNonQueryAsync();
        return organization;
    }

    private static async Task SelectTenantAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, Guid organization)
    {
        var signer = new TenantProofSigner(
            Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Security__TenantProofKey is required."));
        await using var cmd = new NpgsqlCommand(
            "SELECT set_config('comuni.tenant_assertion', @token, true)", conn, tx);
        cmd.Parameters.AddWithValue("token", signer.Create(organization));
        await cmd.ExecuteScalarAsync();
    }

    private static async Task<long> CountAsync(
        NpgsqlConnection conn, NpgsqlTransaction? tx, string table)
    {
        // Fixed internal constant table names, never supplied from an HTTP request.
        await using var cmd = new NpgsqlCommand("SELECT count(*) FROM " + table, conn, tx);
        return (long)(await cmd.ExecuteScalarAsync())!;
    }
}

/// <summary>End-to-end application request uses the restricted database login.</summary>
public sealed class TenantRlsApiTests
{
    [Fact]
    public async Task Authorized_API_reads_and_writes_under_the_restricted_PostgreSQL_role()
    {
        var org = Guid.NewGuid();
        var owner = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")!;
        await using (var db = new NpgsqlConnection(owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organizations (id, name) VALUES (@org, 'Comune RLS API');
                INSERT INTO platform.organization_modules (organization_id, module_key, enabled)
                  VALUES (@org, 'protocol', TRUE);
                INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active)
                  VALUES (@org, 'rls-officer', 'Officer', TRUE);
                """, db);
            cmd.Parameters.AddWithValue("org", org);
            await cmd.ExecuteNonQueryAsync();
        }

        using var factory = new RestrictedRlsFactory();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", factory.Token(org));

        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync("/api/v1/context")).StatusCode);
        var created = await client.PostAsJsonAsync(
            "/api/v1/protocol/records", new { subject = "RLS endpoint" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync("/api/v1/protocol/records")).StatusCode);
    }

    private sealed class RestrictedRlsFactory : WebApplicationFactory<Program>
    {
        public RestrictedRlsFactory()
        {
            Environment.SetEnvironmentVariable("ConnectionStrings__Default",
                Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION"));
            Environment.SetEnvironmentVariable("Authentication__Mode", "DevelopmentJwt");
            Environment.SetEnvironmentVariable("Jwt__SigningKey", ApiFactory.SigningKey);
            Environment.SetEnvironmentVariable("Jwt__Issuer", "Comuni.Tests");
            Environment.SetEnvironmentVariable("Jwt__Audience", "Comuni.Api");
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder) =>
            builder.UseEnvironment("Testing");

        public string Token(Guid organization)
        {
            var signingKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                System.Text.Encoding.UTF8.GetBytes(ApiFactory.SigningKey));
            var now = DateTime.UtcNow;
            var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: "Comuni.Tests", audience: "Comuni.Api",
                claims:
                [
                    new System.Security.Claims.Claim("sub", "rls-officer"),
                    new System.Security.Claims.Claim("organization_id", organization.ToString("D"))
                ],
                notBefore: now.AddMinutes(-1), expires: now.AddMinutes(10),
                signingCredentials: new Microsoft.IdentityModel.Tokens.SigningCredentials(
                    signingKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256));
            return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }
}
