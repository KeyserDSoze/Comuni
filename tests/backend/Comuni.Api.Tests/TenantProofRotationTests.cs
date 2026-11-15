using Comuni.Infrastructures.Persistence;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class TenantProofRotationTests
{
    private static readonly string Owner = Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Missing owner test database.");
    private static readonly string Runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Missing restricted test database.");

    [Fact]
    public async Task Two_versioned_keys_can_overlap_then_revocation_immediately_denies_old_proof()
    {
        var oldId = "o" + Guid.NewGuid().ToString("N")[..31];
        var newId = "n" + Guid.NewGuid().ToString("N")[..31];
        const string oldSecret = "test-only-old-key-for-rls-rotation-2026-11";
        const string newSecret = "test-only-new-key-for-rls-rotation-2026-11";
        var tenantA = Guid.NewGuid();
        var tenantB = Guid.NewGuid();
        await using var admin = new NpgsqlConnection(Owner);
        await admin.OpenAsync();

        async Task ExecuteAdminAsync(string sql, params (string name, object value)[] args)
        {
            await using var cmd = new NpgsqlCommand(sql, admin);
            foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value);
            await cmd.ExecuteNonQueryAsync();
        }

        await ExecuteAdminAsync("""
            INSERT INTO platform.organizations (id, name) VALUES (@a, 'Rotation A'), (@b, 'Rotation B');
            INSERT INTO platform.tenant_proof_keys (key_id, signing_key, not_before, valid_until)
              VALUES (@old_id, @old_key, clock_timestamp() - interval '1 minute', clock_timestamp() + interval '1 hour'),
                     (@new_id, @new_key, clock_timestamp() - interval '1 minute', clock_timestamp() + interval '1 hour');
            """,
            ("a", tenantA), ("b", tenantB),
            ("old_id", oldId), ("old_key", oldSecret),
            ("new_id", newId), ("new_key", newSecret));

        var oldProof = new TenantProofSigner(oldSecret, oldId).Create(tenantA);
        var newProof = new TenantProofSigner(newSecret, newId).Create(tenantB);

        await using var runtime = new NpgsqlConnection(Runtime);
        await runtime.OpenAsync();

        await using var tx = await runtime.BeginTransactionAsync();
        async Task<long> CountAsync(string proof)
        {
            await using (var set = new NpgsqlCommand(
                "SELECT set_config('comuni.tenant_assertion', @proof, true)", runtime, tx))
            {
                set.Parameters.AddWithValue("proof", proof);
                await set.ExecuteScalarAsync();
            }
            await using var read = new NpgsqlCommand("SELECT count(*) FROM platform.organizations", runtime, tx);
            return (long)(await read.ExecuteScalarAsync())!;
        }

        Assert.Equal(1L, await CountAsync(oldProof));
        Assert.Equal(1L, await CountAsync(newProof));
        Assert.Equal(0L, await CountAsync(oldProof.Replace(oldId, newId, StringComparison.Ordinal)));

        await ExecuteAdminAsync(
            "UPDATE platform.tenant_proof_keys SET revoked_at = clock_timestamp() WHERE key_id = @id",
            ("id", oldId));
        Assert.Equal(0L, await CountAsync(oldProof));
        Assert.Equal(1L, await CountAsync(newProof));

        await ExecuteAdminAsync(
            "UPDATE platform.tenant_proof_keys SET valid_until = clock_timestamp() - interval '1 second' WHERE key_id = @id",
            ("id", newId));
        Assert.Equal(0L, await CountAsync(newProof));
        await tx.CommitAsync();
        await using var post = new NpgsqlCommand("SELECT count(*) FROM platform.organizations", runtime);
        Assert.Equal(0L, (long)(await post.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Runtime_cannot_read_or_modify_versioned_key_material()
    {
        await using var conn = new NpgsqlConnection(Runtime);
        await conn.OpenAsync();

        await using (var read = new NpgsqlCommand("SELECT signing_key FROM platform.tenant_proof_keys", conn))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => read.ExecuteScalarAsync());
            Assert.Equal("42501", error.SqlState);
        }
        await using (var write = new NpgsqlCommand(
            "UPDATE platform.tenant_proof_keys SET revoked_at = NULL", conn))
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => write.ExecuteNonQueryAsync());
            Assert.Equal("42501", error.SqlState);
        }
    }
}
