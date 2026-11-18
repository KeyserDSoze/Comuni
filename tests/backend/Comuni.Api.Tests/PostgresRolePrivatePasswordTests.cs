using System.Diagnostics;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first PostgreSQL 17 tests for SCRAM-only role password provisioning.
/// Test database, identities and passwords are synthetic and disposable.
/// </summary>
public sealed class PostgresRolePrivatePasswordTests
{
    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Owner disposable PostgreSQL required.");
    private static string Runtime => Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Runtime disposable PostgreSQL required.");
    private static string Platform => Environment.GetEnvironmentVariable("TEST_PLATFORM_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Platform reader disposable PostgreSQL required.");

    private static string Root()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return dir.FullName;
        throw new InvalidOperationException("Repository root not found");
    }

    private static async Task<(int Exit, string Output)> Run(
        string script, string envKey, string? password, string? connection = null,
        bool logStatements = false)
    {
        var builder = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            WorkingDirectory = Root(), RedirectStandardOutput = true,
            RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var part in new[] {
            "-X", "-q", "-v", "ON_ERROR_STOP=1",
            "-h", builder.Host, "-p", builder.Port.ToString(), "-U", builder.Username,
            "-d", builder.Database, "-f",
            Path.Combine(Root(), "scripts/postgres", script)
        }) start.ArgumentList.Add(part);
        start.Environment["PGPASSWORD"] = builder.Password
            ?? throw new InvalidOperationException("Disposable DB password required.");
        start.Environment.Remove("RUNTIME_DB_PASSWORD");
        start.Environment.Remove("PLATFORM_READ_DB_PASSWORD");
        if (password is not null) start.Environment[envKey] = password;
        if (logStatements)
            start.Environment["PGOPTIONS"] = "-c log_statement=all " +
                "-c log_parameter_max_length=-1 -c log_parameter_max_length_on_error=-1";

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("psql unavailable");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<(bool HasScram, bool SafeRole, bool NoMembership)> RoleStatus(
        string role, string forbiddenPassword)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT rolpassword, rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
                AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
                AND NOT rolinherit,
                NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
            FROM pg_authid r WHERE rolname=@role
            """, db);
        cmd.Parameters.AddWithValue("role", role);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var verifier = reader.GetString(0);
        Assert.StartsWith("SCRAM-SHA-256$4096:", verifier);
        Assert.DoesNotContain(forbiddenPassword, verifier);
        Assert.DoesNotContain("md5", verifier, StringComparison.OrdinalIgnoreCase);
        return (true, reader.GetBoolean(1), reader.GetBoolean(2));
    }

    private static async Task CheckLogin(
        string baseline, string password, string role, bool platformRole)
    {
        var builder = new NpgsqlConnectionStringBuilder(baseline) {
            Password = password, Pooling = false
        };
        await using var db = new NpgsqlConnection(builder.ConnectionString);
        await db.OpenAsync();
        await using var sql = new NpgsqlCommand(
            platformRole
                ? """
                    SELECT current_user = @role,
                        has_table_privilege(current_user,
                            'platform.platform_organization_inventory','SELECT'),
                        NOT has_table_privilege(current_user,
                            'platform.organizations','SELECT'),
                        NOT has_table_privilege(current_user,
                            'platform.platform_operators','SELECT')
                    """
                : """
                    SELECT current_user = @role,
                        has_schema_privilege(current_user,'platform','USAGE'),
                        NOT has_schema_privilege(current_user,'platform','CREATE'),
                        NOT has_table_privilege(current_user,
                            'platform.tenant_proof_keys','SELECT')
                    """, db);
        sql.Parameters.AddWithValue("role", role);
        await using var reader = await sql.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        for (var i = 0; i < 4; i++) Assert.True(reader.GetBoolean(i));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Role_password_rotation_uses_real_SCRAM_login_and_keeps_least_privilege(bool platformRole)
    {
        var role = platformRole ? "comuni_platform_reader" : "comuni_app_runtime";
        var script = platformRole ? "provision-platform-read-role.sql" : "provision-runtime-role.sql";
        var name = platformRole ? "PLATFORM_READ_DB_PASSWORD" : "RUNTIME_DB_PASSWORD";
        var baseline = platformRole ? Platform : Runtime;
        var original = new NpgsqlConnectionStringBuilder(baseline).Password
            ?? throw new InvalidOperationException("Original CI password unavailable");
        var rotated = "test-only-scram-provision-" + Guid.NewGuid().ToString("N") + "-' ; --";

        try
        {
            var result = await Run(script, name, rotated, logStatements: true);
            Assert.Equal(0, result.Exit);
            Assert.DoesNotContain(rotated, result.Output);
            Assert.Equal((true, true, true), await RoleStatus(role, rotated));
            await CheckLogin(baseline, rotated, role, platformRole);

            // A repeated provisioning must remain valid and preserve grants.
            var retry = await Run(script, name, rotated);
            Assert.Equal(0, retry.Exit);
            Assert.DoesNotContain(rotated, retry.Output);
            await CheckLogin(baseline, rotated, role, platformRole);
        }
        finally
        {
            // CI uses a disposable shared database; restore credentials before
            // any other test class accesses these SQL principals.
            var restore = await Run(script, name, original);
            Assert.Equal(0, restore.Exit);
        }
        await CheckLogin(baseline, original, role, platformRole);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Invalid_or_runtime_principal_credentials_cannot_rotate_or_gain_grants(bool platformRole)
    {
        var script = platformRole ? "provision-platform-read-role.sql" : "provision-runtime-role.sql";
        var name = platformRole ? "PLATFORM_READ_DB_PASSWORD" : "RUNTIME_DB_PASSWORD";
        var baseline = platformRole ? Platform : Runtime;
        var role = platformRole ? "comuni_platform_reader" : "comuni_app_runtime";
        var old = new NpgsqlConnectionStringBuilder(baseline).Password!;
        foreach (var password in new string?[] { null, "", "weak", new string('a', 1100),
            "non-ascii-città-" + new string('z', 40) })
        {
            var result = await Run(script, name, password);
            Assert.NotEqual(0, result.Exit);
            if (!string.IsNullOrEmpty(password))
                Assert.DoesNotContain(password, result.Output);
        }

        var injected = "synthetic-strong-runtime-denied-" + Guid.NewGuid().ToString("N");
        var runtime = await Run(script, name, injected, connection: Runtime);
        Assert.NotEqual(0, runtime.Exit);
        Assert.DoesNotContain(injected, runtime.Output);
        await CheckLogin(baseline, old, role, platformRole);
    }

    [Fact]
    public async Task PostgreSQL_server_statement_logs_do_not_include_plaintext_password()
    {
        var role = "comuni_platform_reader";
        var script = "provision-platform-read-role.sql";
        var baseline = Platform;
        var original = new NpgsqlConnectionStringBuilder(baseline).Password!;
        var canary = "sql-password-canary-" + Guid.NewGuid().ToString("N") + "-' ; --";
        var since = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");
        try
        {
            var result = await Run(script, "PLATFORM_READ_DB_PASSWORD", canary,
                logStatements: true);
            Assert.Equal(0, result.Exit);
            Assert.DoesNotContain(canary, result.Output);
            await CheckLogin(Platform, canary, role, true);
        }
        finally
        {
            Assert.Equal(0, (await Run(script, "PLATFORM_READ_DB_PASSWORD", original)).Exit);
        }

        using var find = new Process();
        find.StartInfo = new ProcessStartInfo("docker") {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var part in new[] {
            "ps", "--filter", "ancestor=postgres:17-alpine", "--format", "{{.ID}}"
        }) find.StartInfo.ArgumentList.Add(part);
        try { find.Start(); }
        catch (System.ComponentModel.Win32Exception)
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI must inspect PostgreSQL logs for password leakage.");
            return;
        }
        var container = (await find.StandardOutput.ReadToEndAsync()).Trim();
        var findErrors = await find.StandardError.ReadToEndAsync();
        await find.WaitForExitAsync();
        if (find.ExitCode != 0 || string.IsNullOrWhiteSpace(container))
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI PostgreSQL server logs must be available.");
            return;
        }
        Assert.DoesNotContain('\n', container);
        using var logs = new Process();
        logs.StartInfo = new ProcessStartInfo("docker") {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var part in new[] { "logs", "--since", since, container })
            logs.StartInfo.ArgumentList.Add(part);
        logs.Start();
        var output = logs.StandardOutput.ReadToEndAsync();
        var error = logs.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await logs.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, logs.ExitCode);
        var actualServerLog = await output + await error;
        Assert.Contains("statement: COPY", actualServerLog);
        Assert.DoesNotContain(canary, actualServerLog);
        Assert.DoesNotContain(original, actualServerLog);
    }
}
