using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Synthetic PostgreSQL 17/psql security checks for tenant proof material
/// transported through client-side COPY (ADR 0074, issue #90).
/// </summary>
public sealed class TenantProofPrivateCopyTests
{
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Owner disposable PostgreSQL required.");
    private static string Runtime => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Restricted disposable PostgreSQL required.");
    private static string ExistingLegacyKey =>
        Environment.GetEnvironmentVariable("Security__TenantProofKey")
        ?? throw new InvalidOperationException("Synthetic existing tenant signing key required.");

    private static string Root()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory);
             dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return dir.FullName;
        }
        throw new InvalidOperationException("Cannot find repository root.");
    }

    private static string FreshId() => "p" + Guid.NewGuid().ToString("N")[..31];

    private static async Task<(int Exit, string Output)> Psql(
        string script, string? key, string? keyId = null,
        string? connection = null, bool verboseServerLogging = false)
    {
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var psi = new ProcessStartInfo("psql")
        {
            WorkingDirectory = Root(), RedirectStandardOutput = true,
            RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var arg in new[] {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", db.Host,
            "-p", db.Port.ToString(), "-U", db.Username, "-d", db.Database,
            "-f", Path.Combine(Root(), "scripts/postgres", script)
        }) psi.ArgumentList.Add(arg);
        psi.Environment["PGPASSWORD"] = db.Password;
        if (key is null) psi.Environment.Remove("TENANT_PROOF_KEY");
        else psi.Environment["TENANT_PROOF_KEY"] = key;
        if (keyId is null) psi.Environment.Remove("TENANT_PROOF_KEY_ID");
        else psi.Environment["TENANT_PROOF_KEY_ID"] = keyId;
        if (verboseServerLogging)
            psi.Environment["PGOPTIONS"] = "-c log_statement=all " +
                "-c log_parameter_max_length=-1 -c log_parameter_max_length_on_error=-1";
        using var process = Process.Start(psi) ??
            throw new InvalidOperationException("psql not available.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(string Secret, bool Revoked)> ReadVersioned(string id)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT signing_key, revoked_at IS NOT NULL
            FROM platform.tenant_proof_keys WHERE key_id=@id
            """, db);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (reader.GetString(0), reader.GetBoolean(1));
    }

    [Fact]
    public async Task Versioned_key_staging_must_be_owner_only_idempotent_and_never_resurrect_revoked_id()
    {
        var id = FreshId();
        var secret = "synthetic-key-copy-" + Guid.NewGuid().ToString("N") + "-never-log";
        Assert.Equal(0, (await Psql("stage-tenant-proof-key.sql", secret, id)).Exit);
        Assert.Equal((secret, false), await ReadVersioned(id));
        Assert.Equal(0, (await Psql("stage-tenant-proof-key.sql", secret, id)).Exit);
        Assert.Equal((secret, false), await ReadVersioned(id));
        var mismatch = await Psql("stage-tenant-proof-key.sql", secret + "-different", id);
        Assert.NotEqual(0, mismatch.Exit);
        Assert.DoesNotContain(secret, mismatch.Output);
        Assert.Equal((secret, false), await ReadVersioned(id));
        await using (var owner = new NpgsqlConnection(Owner))
        {
            await owner.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                UPDATE platform.tenant_proof_keys SET revoked_at=clock_timestamp()
                WHERE key_id=@id
                """, owner);
            cmd.Parameters.AddWithValue("id", id);
            Assert.Equal(1, await cmd.ExecuteNonQueryAsync());
        }
        Assert.NotEqual(0, (await Psql("stage-tenant-proof-key.sql", secret, id)).Exit);
        Assert.Equal((secret, true), await ReadVersioned(id));
        Assert.NotEqual(0, (await Psql("stage-tenant-proof-key.sql",
            "synthetic-runtime-key-2026-11-17-verified-aaaa", FreshId(),
            connection: Runtime)).Exit);
    }

    [Fact]
    public async Task Legacy_secret_provision_is_idempotent_but_never_rotates_or_restores_other_secret()
    {
        Assert.Equal(0, (await Psql("provision-tenant-proof.sql", ExistingLegacyKey)).Exit);
        Assert.Equal(0, (await Psql("provision-tenant-proof.sql", ExistingLegacyKey)).Exit);
        var mismatch = await Psql("provision-tenant-proof.sql",
            "synthetic-other-legacy-secret-2026-11-17-guard");
        Assert.NotEqual(0, mismatch.Exit);
        Assert.DoesNotContain("synthetic-other-legacy-secret", mismatch.Output);

        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT (SELECT signing_key FROM platform.tenant_proof_secret WHERE id=1),
                   (SELECT signing_key FROM platform.tenant_proof_keys WHERE key_id='legacy'),
                   (SELECT revoked_at IS NULL FROM platform.tenant_proof_keys WHERE key_id='legacy')
            """, db);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(ExistingLegacyKey, reader.GetString(0));
        Assert.Equal(ExistingLegacyKey, reader.GetString(1));
        Assert.True(reader.GetBoolean(2));
    }

    [Fact]
    public async Task Invalid_missing_small_or_conflicting_key_inputs_are_denied_without_writes()
    {
        var invalidIds = new string?[] { null, "legacy", "UPPERCASE",
            "../escape", "id with spaces", new string('a', 33) };
        foreach (var id in invalidIds)
        {
            var result = await Psql("stage-tenant-proof-key.sql",
                "synthetic-long-enough-private-key-2026-11-17", id);
            Assert.NotEqual(0, result.Exit);
        }
        var missing = await Psql("stage-tenant-proof-key.sql", null, FreshId());
        Assert.NotEqual(0, missing.Exit);
        var small = await Psql("stage-tenant-proof-key.sql", "too-short", FreshId());
        Assert.NotEqual(0, small.Exit);
        Assert.DoesNotContain("too-short", small.Output);
        var legacyTooSmall = await Psql("provision-tenant-proof.sql", "short");
        Assert.NotEqual(0, legacyTooSmall.Exit);
    }

    [Fact]
    public async Task Competing_key_stagings_cannot_overwrite_or_flip_a_verified_key()
    {
        var id = FreshId();
        var a = "synthetic-competing-a-" + Guid.NewGuid().ToString("N");
        var b = "synthetic-competing-b-" + Guid.NewGuid().ToString("N");
        var outcomes = await Task.WhenAll(
            Psql("stage-tenant-proof-key.sql", a, id),
            Psql("stage-tenant-proof-key.sql", b, id));
        Assert.Single(outcomes, x => x.Exit == 0);
        var stored = await ReadVersioned(id);
        Assert.Contains(stored.Secret, new[] { a, b });
        Assert.False(stored.Revoked);
        Assert.All(outcomes, x =>
        {
            Assert.DoesNotContain(a, x.Output);
            Assert.DoesNotContain(b, x.Output);
        });
    }

    [Fact]
    public async Task COPY_logs_query_text_not_private_key_even_with_maximum_server_statement_logging()
    {
        var id = FreshId();
        var key = "synthetic-canary-secret-" + Guid.NewGuid().ToString("N") +
                  "-'; select current_user; --";
        var since = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");
        var staged = await Psql("stage-tenant-proof-key.sql", key, id,
            verboseServerLogging: true);
        Assert.Equal(0, staged.Exit);
        Assert.DoesNotContain(key, staged.Output);
        Assert.Equal((key, false), await ReadVersioned(id));

        // The legacy route uses an already-present synthetic secret; it must
        // not be printed in statement logs by the idempotent rerun either.
        var legacy = await Psql("provision-tenant-proof.sql", ExistingLegacyKey,
            verboseServerLogging: true);
        Assert.Equal(0, legacy.Exit);
        Assert.DoesNotContain(ExistingLegacyKey, legacy.Output);

        using var find = new Process();
        find.StartInfo = new ProcessStartInfo("docker") {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var a in new[] {
            "ps", "--filter", "ancestor=postgres:17-alpine", "--format", "{{.ID}}"
        }) find.StartInfo.ArgumentList.Add(a);
        try { find.Start(); }
        catch (System.ComponentModel.Win32Exception)
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI PostgreSQL must expose its server log for privacy testing.");
            return;
        }
        var container = (await find.StandardOutput.ReadToEndAsync()).Trim();
        var findError = await find.StandardError.ReadToEndAsync();
        await find.WaitForExitAsync();
        if (find.ExitCode != 0 || string.IsNullOrWhiteSpace(container))
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI requires Docker access to PostgreSQL server logs.");
            return;
        }
        Assert.DoesNotContain('\n', container);
        using var logs = new Process();
        logs.StartInfo = new ProcessStartInfo("docker") {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var a in new[] { "logs", "--since", since, container })
            logs.StartInfo.ArgumentList.Add(a);
        logs.Start();
        var output = logs.StandardOutput.ReadToEndAsync();
        var errors = logs.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await logs.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, logs.ExitCode);
        var text = await output + await errors;
        Assert.Contains("statement: COPY", text);
        Assert.DoesNotContain(key, text);
        Assert.DoesNotContain(ExistingLegacyKey, text);
    }
}
