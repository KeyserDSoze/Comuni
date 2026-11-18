using System.Diagnostics;
using Comuni.Infrastructures.Persistence;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first tests of an owner-only retirement safety guard with PostgreSQL 17.
/// All IDs, keys and organizations are synthetic; no Azure or live key material.
/// </summary>
public sealed class TenantProofRetirementGuardTests
{
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner connection required.");
    private static string Runtime => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted PostgreSQL login required.");

    private const string OldKey = "synthetic-retire-old-key-2026-guard-46-aaaaaaaa";
    private const string NewKey = "synthetic-retire-new-key-2026-guard-46-bbbbbbbb";

    private static string FreshId() => "k" + Guid.NewGuid().ToString("N")[..31];

    private static string Script()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory);
             dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return Path.Combine(dir.FullName, "scripts", "postgres", "retire-tenant-proof-key.sql");
        throw new InvalidOperationException("Cannot resolve repository root.");
    }

    private static async Task<(int ExitCode, string Output)> RetireAsync(
        string? target, string? successor, string? grace = "300", string? connection = null,
        bool logStatements = false)
    {
        var database = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            // Static client-side COPY resolves only from a trusted checkout root.
            WorkingDirectory = Path.GetFullPath(Path.Combine(
                Path.GetDirectoryName(Script())!, "..", "..")),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var part in new[]
        {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", database.Host,
            "-p", database.Port.ToString(), "-U", database.Username,
            "-d", database.Database, "-f", Script()
        }) start.ArgumentList.Add(part);
        start.Environment["PGPASSWORD"] = database.Password;
        if (logStatements)
            start.Environment["PGOPTIONS"] =
                "-c log_statement=all -c log_parameter_max_length=-1 -c log_parameter_max_length_on_error=-1";
        void Set(string name, string? value)
        {
            if (value is null) start.Environment.Remove(name);
            else start.Environment[name] = value;
        }
        Set("TENANT_PROOF_RETIRE_KEY_ID", target);
        Set("TENANT_PROOF_REPLACEMENT_KEY_ID", successor);
        Set("TENANT_PROOF_GRACE_SECONDS", grace);

        using var process = Process.Start(start) ?? throw new InvalidOperationException("psql unavailable.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task SeedAsync(string id, string secret, int startsInSeconds = -60,
        int expiresInSeconds = 3600, bool revoked = false)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO platform.tenant_proof_keys
                (key_id, signing_key, not_before, valid_until, revoked_at)
            VALUES (@id, @key, @starts, @expires, @revoked)
            """, db);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("key", secret);
        command.Parameters.AddWithValue("starts", DateTime.UtcNow.AddSeconds(startsInSeconds));
        command.Parameters.AddWithValue("expires", DateTime.UtcNow.AddSeconds(expiresInSeconds));
        command.Parameters.AddWithValue("revoked",
            revoked ? (object)DateTime.UtcNow : DBNull.Value);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<(DateTime Until, DateTime? Revoked)> ReadAsync(string id)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT valid_until, revoked_at FROM platform.tenant_proof_keys WHERE key_id=@id", db);
        command.Parameters.AddWithValue("id", id);
        await using var row = await command.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetDateTime(0), row.IsDBNull(1) ? null : row.GetDateTime(1));
    }

    [Fact]
    public async Task Missing_same_unknown_revoked_future_or_short_lived_successor_is_rejected_without_writes()
    {
        var target = FreshId();
        var healthy = FreshId();
        var revoked = FreshId();
        var future = FreshId();
        var expiring = FreshId();
        await SeedAsync(target, OldKey);
        await SeedAsync(healthy, NewKey);
        await SeedAsync(revoked, NewKey, revoked: true);
        await SeedAsync(future, NewKey, startsInSeconds: 600);
        await SeedAsync(expiring, NewKey, expiresInSeconds: 100);
        var before = await ReadAsync(target);

        foreach (var replacement in new string?[]
        {
            null, target, FreshId(), revoked, future, expiring, "INVALID"
        })
        {
            var result = await RetireAsync(target, replacement);
            Assert.NotEqual(0, result.ExitCode);
            Assert.Equal(before, await ReadAsync(target));
            Assert.DoesNotContain(OldKey, result.Output);
            Assert.DoesNotContain(NewKey, result.Output);
        }
        foreach (var grace in new[] { "-1", "3601", "bad" })
        {
            Assert.NotEqual(0, (await RetireAsync(target, healthy, grace)).ExitCode);
            Assert.Equal(before, await ReadAsync(target));
        }
        Assert.NotEqual(0, (await RetireAsync(FreshId(), healthy)).ExitCode);
        Assert.NotEqual(0, (await RetireAsync(target, healthy, null)).ExitCode);
        Assert.Equal(before, await ReadAsync(target));
    }

    [Fact]
    public async Task Valid_successor_allows_irreversible_retirement_and_preserves_tenant_RLS()
    {
        var target = FreshId();
        var successor = FreshId();
        var municipality = Guid.NewGuid();
        await SeedAsync(target, OldKey);
        await SeedAsync(successor, NewKey);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var create = new NpgsqlCommand(
                "INSERT INTO platform.organizations (id,name) VALUES (@id,'Retirement safety synthetic')", db);
            create.Parameters.AddWithValue("id", municipality);
            await create.ExecuteNonQueryAsync();
        }

        var oldProof = new TenantProofSigner(OldKey, target).Create(municipality);
        var newProof = new TenantProofSigner(NewKey, successor).Create(municipality);
        await using var runtime = new NpgsqlConnection(Runtime);
        await runtime.OpenAsync();
        await using var tx = await runtime.BeginTransactionAsync();

        async Task<long> VisibleAsync(string proof)
        {
            await using (var set = new NpgsqlCommand(
                "SELECT set_config('comuni.tenant_assertion', @proof, true)", runtime, tx))
            {
                set.Parameters.AddWithValue("proof", proof);
                await set.ExecuteScalarAsync();
            }
            await using var query = new NpgsqlCommand(
                "SELECT count(*) FROM platform.organizations WHERE id = @org", runtime, tx);
            query.Parameters.AddWithValue("org", municipality);
            return (long)(await query.ExecuteScalarAsync())!;
        }
        Assert.Equal(1, await VisibleAsync(oldProof));
        Assert.Equal(1, await VisibleAsync(newProof));

        var retired = await RetireAsync(target, successor, "0");
        Assert.Equal(0, retired.ExitCode);
        Assert.DoesNotContain(OldKey, retired.Output);
        Assert.Equal(0, await VisibleAsync(oldProof));
        Assert.Equal(1, await VisibleAsync(newProof));
        var after = await ReadAsync(target);
        Assert.NotNull(after.Revoked);

        Assert.Equal(0, (await RetireAsync(target, successor, "60")).ExitCode);
        Assert.Equal(after, await ReadAsync(target));
        await tx.CommitAsync();
    }

    [Fact]
    public async Task Concurrent_reciprocal_retirements_cannot_revoke_both_candidates()
    {
        var a = FreshId();
        var b = FreshId();
        await SeedAsync(a, OldKey);
        await SeedAsync(b, NewKey);
        var outcomes = await Task.WhenAll(RetireAsync(a, b, "0"), RetireAsync(b, a, "0"));
        Assert.Single(outcomes.Where(x => x.ExitCode == 0));
        Assert.Single(outcomes.Where(x => x.ExitCode != 0));
        var first = await ReadAsync(a);
        var second = await ReadAsync(b);
        Assert.NotEqual(first.Revoked is null, second.Revoked is null);
    }

    [Fact]
    public async Task Municipal_runtime_cannot_retire_keys_even_with_a_valid_successor()
    {
        var from = FreshId();
        var to = FreshId();
        await SeedAsync(from, OldKey);
        await SeedAsync(to, NewKey);
        var result = await RetireAsync(from, to, "0", Runtime);
        Assert.NotEqual(0, result.ExitCode);
        Assert.Null((await ReadAsync(from)).Revoked);
        Assert.DoesNotContain(OldKey, result.Output);
        Assert.DoesNotContain(NewKey, result.Output);
    }

    [Fact]
    public async Task Invalid_grace_input_never_surfaces_in_PostgreSQL_integer_cast_error()
    {
        var target = FreshId();
        var successor = FreshId();
        await SeedAsync(target, OldKey);
        await SeedAsync(successor, NewKey);
        var invalid = "private-grace-canary-" + Guid.NewGuid().ToString("N");
        var result = await RetireAsync(target, successor, invalid, logStatements: true);
        Assert.NotEqual(0, result.ExitCode);
        Assert.DoesNotContain(invalid, result.Output);
        Assert.Null((await ReadAsync(target)).Revoked);
    }

    [Fact]
    public async Task Retirement_private_copy_transport_does_not_interpolate_metadata()
    {
        var sql = await File.ReadAllTextAsync(Script());
        foreach (var name in new[] { "retire_id", "replacement_id", "grace_secs" })
            Assert.DoesNotContain(":'" + name + "'", sql);
        Assert.Contains(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py retire-tenant-proof'",
            sql);
    }

    [Fact]
    public async Task Retirement_key_metadata_canaries_do_not_appear_in_real_PostgreSQL_17_statement_logs()
    {
        // Only synthetic metadata (never HMAC secrets); no raw server logs
        // or input markers are printed in failure messages.
        var target = FreshId();
        var successor = FreshId();
        await SeedAsync(target, OldKey);
        await SeedAsync(successor, NewKey);
        var since = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");
        var result = await RetireAsync(target, successor, "0", logStatements: true);
        Assert.Equal(0, result.ExitCode);
        Assert.False(result.Output.Contains(target, StringComparison.Ordinal)
                     || result.Output.Contains(successor, StringComparison.Ordinal),
            "psql emitted synthetic retirement metadata.");
        Assert.NotNull((await ReadAsync(target)).Revoked);

        using var dockerPs = new Process();
        dockerPs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] {
            "ps", "--filter", "ancestor=postgres:17-alpine", "--format", "{{.ID}}"
        }) dockerPs.StartInfo.ArgumentList.Add(arg);
        try
        {
            dockerPs.Start();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "PostgreSQL 17 server logs are mandatory in CI.");
            return;
        }
        var ids = (await dockerPs.StandardOutput.ReadToEndAsync()).Trim();
        _ = await dockerPs.StandardError.ReadToEndAsync();
        await dockerPs.WaitForExitAsync();
        if (dockerPs.ExitCode != 0 || string.IsNullOrWhiteSpace(ids))
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "PostgreSQL 17 server logs must be inspectable in CI.");
            return;
        }
        Assert.DoesNotContain('\n', ids);

        using var logs = new Process();
        logs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] { "logs", "--since", since, ids })
            logs.StartInfo.ArgumentList.Add(arg);
        logs.Start();
        var stdout = logs.StandardOutput.ReadToEndAsync();
        var stderr = logs.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await logs.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, logs.ExitCode);
        var text = await stdout + await stderr;
        Assert.Contains("statement: COPY", text);
        Assert.False(text.Contains(target, StringComparison.Ordinal)
                     || text.Contains(successor, StringComparison.Ordinal),
            "PostgreSQL statement logging exposed synthetic retirement metadata; raw logs withheld.");
    }
}
