using System.Net;
using Comuni.Infrastructures.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// TDD RED (#126): readiness must prove the *configured* HMAC verifier against
/// the real PostgreSQL runtime login, not merely test TCP connectivity.
/// Disposable credentials, unallocated organization IDs and a versioned key.
/// </summary>
public sealed class TenantRlsReadinessApiTests
{
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_DATABASE_CONNECTION required.");
    private static string Runtime => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("TEST_RUNTIME_DATABASE_CONNECTION required.");

    [Fact]
    public async Task Ready_tracks_active_wrong_and_revoked_versioned_signing_key_without_exposing_tenant_data()
    {
        var keyId = "ready" + Guid.NewGuid().ToString("N")[..20];
        var secret = "synthetic-readiness-signing-key-2026-" + Guid.NewGuid().ToString("N");
        await using var owner = new NpgsqlConnection(Owner);
        await owner.OpenAsync();
        await using (var stage = new NpgsqlCommand("""
            INSERT INTO platform.tenant_proof_keys
                (key_id, signing_key, not_before, valid_until)
            VALUES (@id, @secret, clock_timestamp() - interval '1 minute',
                    clock_timestamp() + interval '30 minutes')
            """, owner))
        {
            stage.Parameters.AddWithValue("id", keyId);
            stage.Parameters.AddWithValue("secret", secret);
            await stage.ExecuteNonQueryAsync();
        }

        try
        {
            // The readiness API must run with the non-owner restricted runtime
            // login: never sign using the schema owner, never read key material.
            await using (var runtime = new NpgsqlConnection(Runtime))
            {
                await runtime.OpenAsync();
                await using var role = new NpgsqlCommand("SELECT current_user", runtime);
                Assert.Equal("comuni_app_runtime", await role.ExecuteScalarAsync());
            }

            using var valid = new ReadinessFactory(Runtime, secret, keyId);
            using var validClient = valid.CreateClient();
            using var live = await validClient.GetAsync("/health/live");
            Assert.Equal(HttpStatusCode.OK, live.StatusCode);
            using var healthy = await validClient.GetAsync("/health/ready");
            Assert.Equal(HttpStatusCode.OK, healthy.StatusCode);
            Assert.Equal(true, healthy.Headers.CacheControl?.NoStore);
            Assert.DoesNotContain(secret, await healthy.Content.ReadAsStringAsync());

            // Any valid TCP connection with a *wrong* signer must be marked
            // unready. A service that only uses CanConnectAsync returns 200.
            using var invalid = new ReadinessFactory(Runtime, secret + "-wrong", keyId);
            using var invalidClient = invalid.CreateClient();
            using var wrong = await invalidClient.GetAsync("/health/ready");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, wrong.StatusCode);
            Assert.Equal(true, wrong.Headers.CacheControl?.NoStore);
            Assert.DoesNotContain(secret, await wrong.Content.ReadAsStringAsync());
            Assert.Equal(HttpStatusCode.OK,
                (await invalidClient.GetAsync("/health/live")).StatusCode);

            // Database-side key retirement must immediately withdraw readiness
            // even if an existing application instance still holds the key.
            await using (var revoke = new NpgsqlCommand("""
                UPDATE platform.tenant_proof_keys
                SET revoked_at = clock_timestamp()
                WHERE key_id = @id
                """, owner))
            {
                revoke.Parameters.AddWithValue("id", keyId);
                Assert.Equal(1, await revoke.ExecuteNonQueryAsync());
            }
            using var revoked = await validClient.GetAsync("/health/ready");
            Assert.Equal(HttpStatusCode.ServiceUnavailable, revoked.StatusCode);
            Assert.DoesNotContain(secret, await revoked.Content.ReadAsStringAsync());
            Assert.Equal(HttpStatusCode.OK,
                (await validClient.GetAsync("/health/live")).StatusCode);

            // A transaction-local HMAC proof must never survive a pooled
            // connection release/rollback into another request.
            await using (var runtime = new NpgsqlConnection(Runtime))
            {
                await runtime.OpenAsync();
                await using var inspect = new NpgsqlCommand("""
                    SELECT platform.verified_tenant_id() IS NULL
                       AND NULLIF(current_setting('comuni.tenant_assertion', true), '') IS NULL
                    """, runtime);
                Assert.True((bool)(await inspect.ExecuteScalarAsync())!);
            }
        }
        finally
        {
            // Cleanup is owner-only and affects this synthetic key alone.
            await using var cleanup = new NpgsqlCommand(
                "DELETE FROM platform.tenant_proof_keys WHERE key_id = @id", owner);
            cleanup.Parameters.AddWithValue("id", keyId);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task Database_unavailable_means_503_not_exception_or_cached_success()
    {
        var connection = new NpgsqlConnectionStringBuilder(Runtime)
        {
            Host = "127.0.0.1",
            Port = 1,
            Timeout = 1,
            Pooling = false
        }.ConnectionString;
        using var failed = new ReadinessFactory(
            connection, "synthetic-readiness-only-key-2026-very-long", "ready_offline");
        using var client = failed.CreateClient();
        using var response = await client.GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(true, response.Headers.CacheControl?.NoStore);
        Assert.DoesNotContain("Password", await response.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
    }

    private sealed class ReadinessFactory(string connection, string signerKey, string keyId)
        : WebApplicationFactory<Program>
    {
        private static readonly object EnvironmentGate = new();

        // WebApplicationFactory's minimal hosting Program reads configuration
        // before the ConfigureWebHost callback; use a scoped environment
        // override on startup, immediately restoring its previous values.
        public new HttpClient CreateClient()
        {
            var required = new Dictionary<string, string?>
            {
                ["ConnectionStrings__Default"] = connection,
                ["Security__TenantProofKey"] = signerKey,
                ["Security__TenantProofKeyId"] = keyId,
                ["Authentication__Mode"] = "DevelopmentJwt",
                ["Jwt__SigningKey"] = ApiFactory.SigningKey,
                ["Jwt__Issuer"] = "Comuni.Tests",
                ["Jwt__Audience"] = "Comuni.Api",
                ["PlatformInventory__Enabled"] = "false"
            };
            lock (EnvironmentGate)
            {
                var prior = required.Keys.ToDictionary(
                    name => name, Environment.GetEnvironmentVariable);
                try
                {
                    foreach (var (name, value) in required)
                        Environment.SetEnvironmentVariable(name, value);
                    return base.CreateClient();
                }
                finally
                {
                    foreach (var (name, value) in prior)
                        Environment.SetEnvironmentVariable(name, value);
                }
            }
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Default"] = connection,
                    ["Security:TenantProofKey"] = signerKey,
                    ["Security:TenantProofKeyId"] = keyId,
                    ["Authentication:Mode"] = "DevelopmentJwt",
                    ["Jwt:SigningKey"] = ApiFactory.SigningKey,
                    ["Jwt:Issuer"] = "Comuni.Tests",
                    ["Jwt:Audience"] = "Comuni.Api",
                    ["PlatformInventory:Enabled"] = "false"
                }));
        }
    }
}
