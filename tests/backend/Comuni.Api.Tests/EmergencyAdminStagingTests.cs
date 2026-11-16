using System.Diagnostics;
using System.Net;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first emergency Admin staging on disposable PostgreSQL and local RS256
/// tokens. This does not authenticate real reviewers or operate an actual IdP.
/// </summary>
public sealed class EmergencyAdminStagingTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    private const string Issuer = OidcApiFactory.Issuer;
    private const string Old = "emergency-compromised-admin";
    private const string New = "emergency-verified-new-admin";
    private const string Ticket = "INC-2026-00085";
    private const string Reason = "compromised-admin";
    private const string FirstReviewer = "security-reviewer";
    private const string SecondReviewer = "municipal-reviewer";

    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner connection required.");

    private static string Script(string file)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return Path.Combine(dir.FullName, "scripts", "postgres", file);
        }
        throw new InvalidOperationException("Repository root is missing.");
    }

    private static async Task<(int Code, string Output)> Run(
        string file, Guid org, string? oldIssuer = Issuer, string? oldSubject = Old,
        string? newIssuer = Issuer, string? newSubject = New, string? incident = Ticket,
        string? reviewer1 = FirstReviewer, string? reviewer2 = SecondReviewer,
        string? reason = Reason, string? connection = null,
        string? lifecycleAction = "suspend", bool logStatements = false)
    {
        var path = Script(file);
        Assert.True(File.Exists(path), "RED: owner-only emergency script missing.");
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var psi = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var arg in new[] {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", db.Host,
            "-p", db.Port.ToString(), "-U", db.Username, "-d", db.Database, "-f", path
        }) psi.ArgumentList.Add(arg);
        psi.Environment["PGPASSWORD"] = db.Password;
        void Set(string key, string? value)
        {
            if (value is null) psi.Environment.Remove(key);
            else psi.Environment[key] = value;
        }
        Set("COMUNI_EMERGENCY_ORGANIZATION_ID", org.ToString("D"));
        Set("COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER", oldIssuer);
        Set("COMUNI_EMERGENCY_OLD_SUBJECT", oldSubject);
        Set("COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER", newIssuer);
        Set("COMUNI_EMERGENCY_NEW_SUBJECT", newSubject);
        Set("COMUNI_EMERGENCY_INCIDENT_TICKET", incident);
        Set("COMUNI_EMERGENCY_SECURITY_REVIEWER", reviewer1);
        Set("COMUNI_EMERGENCY_MUNICIPAL_REVIEWER", reviewer2);
        Set("COMUNI_EMERGENCY_REASON_CODE", reason);
        Set("COMUNI_LIFECYCLE_ORGANIZATION_ID", org.ToString("D"));
        Set("COMUNI_LIFECYCLE_ACTION", lifecycleAction);
        Set("COMUNI_LIFECYCLE_CHANGE_TICKET",
            lifecycleAction == "reactivate" ? "CHANGE-2026-REACT85" : "CHANGE-2026-SUSP85");
        Set("COMUNI_LIFECYCLE_APPROVER", "independent-reviewer");
        Set("COMUNI_LIFECYCLE_REASON_CODE", "security-incident");
        if (logStatements)
            psi.Environment["PGOPTIONS"] =
                "-c log_statement=all -c log_parameter_max_length=0 -c log_parameter_max_length_on_error=0";
        using var process = Process.Start(psi) ??
            throw new InvalidOperationException("psql could not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static Task<(int Code, string Output)> Stage(
        Guid org, string? oldIssuer = Issuer, string? oldSubject = Old,
        string? newIssuer = Issuer, string? newSubject = New, string? incident = Ticket,
        string? reviewer1 = FirstReviewer, string? reviewer2 = SecondReviewer,
        string? reason = Reason, string? connection = null, bool logStatements = false) =>
        Run("stage-emergency-admin-replacement.sql", org, oldIssuer, oldSubject,
            newIssuer, newSubject, incident, reviewer1, reviewer2, reason, connection,
            logStatements: logStatements);

    private static Task<(int Code, string Output)> Lifecycle(Guid org, string action = "suspend") =>
        Run("set-organization-suspension.sql", org, lifecycleAction: action);

    private static async Task<Guid> Seed(bool activated = true, bool suspended = false,
        params string[] administrators)
    {
        var org = Guid.NewGuid();
        await using var connection = new NpgsqlConnection(Owner);
        await connection.OpenAsync();
        await using (var cmd = new NpgsqlCommand("""
            INSERT INTO platform.organizations(id,name,is_activated,is_suspended)
            VALUES(@id,'Comune synthetic emergency',@activated,@suspended);
            INSERT INTO platform.organization_modules(organization_id,module_key,enabled)
            VALUES(@id,'protocol',TRUE);
            """, connection))
        {
            cmd.Parameters.AddWithValue("id", org);
            cmd.Parameters.AddWithValue("activated", activated);
            cmd.Parameters.AddWithValue("suspended", suspended);
            await cmd.ExecuteNonQueryAsync();
        }
        foreach (var sub in administrators)
        {
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                  (organization_id,subject,identity_issuer,role,is_active)
                VALUES (@org,@sub,@issuer,'Admin',TRUE)
                """, connection);
            cmd.Parameters.AddWithValue("org", org);
            cmd.Parameters.AddWithValue("sub", sub);
            cmd.Parameters.AddWithValue("issuer", Issuer);
            await cmd.ExecuteNonQueryAsync();
        }
        return org;
    }

    private static async Task<(bool Suspended, bool Module, long Active, long Inactive,
        long OldRevoked, long NewStaged, long Suspensions, long Reactivations)> State(Guid org)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT
                (SELECT is_suspended FROM platform.organizations WHERE id=@id),
                (SELECT enabled FROM platform.organization_modules
                 WHERE organization_id=@id AND module_key='protocol'),
                (SELECT COUNT(*) FROM platform.organization_memberships
                 WHERE organization_id=@id AND role='Admin' AND is_active),
                (SELECT COUNT(*) FROM platform.organization_memberships
                 WHERE organization_id=@id AND role='Admin' AND NOT is_active),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id=@id AND action='platform.membership.admin.emergency.revoked'),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id=@id AND action='platform.membership.admin.emergency.staged'),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id=@id AND action='platform.organization.suspended'),
                (SELECT COUNT(*) FROM platform.audit_events
                 WHERE organization_id=@id AND action='platform.organization.reactivated')
            """, db);
        cmd.Parameters.AddWithValue("id", org);
        await using var row = await cmd.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetBoolean(0), row.GetBoolean(1), row.GetInt64(2), row.GetInt64(3),
            row.GetInt64(4), row.GetInt64(5), row.GetInt64(6), row.GetInt64(7));
    }

    [Fact]
    public async Task Emergency_private_inputs_must_never_be_spliced_into_logged_SQL()
    {
        var sql = await File.ReadAllTextAsync(
            Script("stage-emergency-admin-replacement.sql"));
        Assert.Contains("CREATE TEMP TABLE", sql);
        Assert.Contains("ON COMMIT DROP", sql);
        Assert.Contains(
            "FROM PROGRAM 'python3 scripts/postgres/stream-private-input.py emergency'",
            sql);
        Assert.Contains("FROM pg_temp.comuni_private_input", sql);
        foreach (var prohibited in new[] {
            ":'emergency_org'", ":'emergency_old_issuer'",
            ":'emergency_old_subject'", ":'emergency_new_issuer'",
            ":'emergency_new_subject'", ":'emergency_ticket'",
            ":'emergency_security_reviewer'",
            ":'emergency_municipal_reviewer'", ":'emergency_reason'"
        })
            Assert.DoesNotContain(prohibited, sql);
    }

    [Fact]
    public async Task Emergency_client_copy_does_not_log_opaque_subject_with_statement_logging_all()
    {
        var org = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(org)).Code);
        var opaque = "privacy-probe-'::;SELECT-" + Guid.NewGuid().ToString("N");
        var start = DateTimeOffset.UtcNow.AddSeconds(-3).ToString("O");
        var result = await Stage(org, newSubject: opaque, logStatements: true);
        Assert.Equal(0, result.Code);
        Assert.DoesNotContain(opaque, result.Output);
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(org));

        // GitHub Actions PostgreSQL 17 service uses container stderr logging.
        // Inspect actual server logs under log_statement=all, not just psql stdout.
        using var dockerPs = new Process();
        dockerPs.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] { "ps", "--filter", "ancestor=postgres:17-alpine",
                                    "--format", "{{.ID}}" })
            dockerPs.StartInfo.ArgumentList.Add(arg);
        try
        {
            dockerPs.Start();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI PostgreSQL must be inspectable for statement log leakage.");
            return;
        }
        var containerIds = (await dockerPs.StandardOutput.ReadToEndAsync()).Trim();
        var psErrors = await dockerPs.StandardError.ReadToEndAsync();
        await dockerPs.WaitForExitAsync();
        if (dockerPs.ExitCode != 0 || string.IsNullOrWhiteSpace(containerIds))
        {
            Assert.False(Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true",
                "CI PostgreSQL service must expose its server logs to verify privacy.");
            return;
        }
        Assert.DoesNotContain('\n', containerIds);
        using var dockerLog = new Process();
        dockerLog.StartInfo = new ProcessStartInfo("docker")
        {
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] { "logs", "--since", start, containerIds })
            dockerLog.StartInfo.ArgumentList.Add(arg);
        dockerLog.Start();
        var stdout = dockerLog.StandardOutput.ReadToEndAsync();
        var stderr = dockerLog.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await dockerLog.WaitForExitAsync(timeout.Token);
        Assert.Equal(0, dockerLog.ExitCode);
        var serverLog = await stdout + await stderr;
        Assert.Contains("statement: COPY", serverLog);
        Assert.DoesNotContain(opaque, serverLog);
    }

    [Fact]
    public async Task Stage_replaces_sole_admin_atomically_but_cannot_reactivate_suspended_organization()
    {
        var org = await Seed(administrators: [Old]);
        using var compromised = factory.Authenticated(factory.Token(
            subject: Old, organizationId: org.ToString("D")));
        using var newAdmin = factory.Authenticated(factory.Token(
            subject: New, organizationId: org.ToString("D")));
        Assert.Equal(HttpStatusCode.OK, (await compromised.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await newAdmin.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(0, (await Lifecycle(org)).Code);
        Assert.Equal(HttpStatusCode.Forbidden, (await compromised.GetAsync("/api/v1/context")).StatusCode);

        var staged = await Stage(org);
        Assert.True(staged.Code == 0,
            "Owner-only staging failed with redacted diagnostic: " +
            staged.Output
                .Replace(Issuer, "[issuer]", StringComparison.Ordinal)
                .Replace(Old, "[old-sub]", StringComparison.Ordinal)
                .Replace(New, "[new-sub]", StringComparison.Ordinal)
                .Replace(Ticket, "[ticket]", StringComparison.Ordinal)
                .Replace(FirstReviewer, "[reviewer]", StringComparison.Ordinal)
                .Replace(SecondReviewer, "[reviewer]", StringComparison.Ordinal)
                .Replace(Reason, "[reason]", StringComparison.Ordinal)
                .Replace(org.ToString("D"), "[organization]", StringComparison.Ordinal));
        foreach (var privateValue in new[] { Issuer, Old, New, Ticket, FirstReviewer, SecondReviewer,
            Reason, org.ToString("D") })
            Assert.DoesNotContain(privateValue, staged.Output);
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(org));
        Assert.Equal(HttpStatusCode.Forbidden, (await compromised.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await newAdmin.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await newAdmin.GetAsync("/api/v1/admin/modules")).StatusCode);

        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                SELECT action,resource_type,actor_subject,correlation_id,resource_id
                FROM platform.audit_events
                WHERE organization_id=@id AND action IN (
                    'platform.membership.admin.emergency.revoked',
                    'platform.membership.admin.emergency.staged')
                ORDER BY action
                """, db);
            cmd.Parameters.AddWithValue("id", org);
            await using var reader = await cmd.ExecuteReaderAsync();
            var count = 0;
            while (await reader.ReadAsync())
            {
                Assert.Equal("platform.membership", reader.GetString(1));
                Assert.StartsWith("db-owner:", reader.GetString(2));
                Assert.Equal("emergency:" + Ticket, reader.GetString(3));
                Assert.NotEqual(Guid.Empty, reader.GetGuid(4));
                count++;
            }
            Assert.Equal(2, count);
        }
        // Reactivation requires an INDEPENDENT owner change after IdP session revocation;
        // the script above intentionally never performs this action.
        Assert.Equal(0, (await Lifecycle(org, "reactivate")).Code);
        Assert.Equal((false, true, 1L, 1L, 1L, 1L, 1L, 1L), await State(org));
        Assert.Equal(HttpStatusCode.Forbidden, (await compromised.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await compromised.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await newAdmin.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await newAdmin.GetAsync("/api/v1/admin/modules")).StatusCode);
    }

    [Fact]
    public async Task Exact_replay_is_noop_but_changed_incident_or_target_is_denied()
    {
        var org = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(org)).Code);
        Assert.Equal(0, (await Stage(org)).Code);
        Assert.Equal(0, (await Stage(org)).Code);
        Assert.NotEqual(0, (await Stage(org, incident: "INC-2026-SECOND85")).Code);
        Assert.NotEqual(0, (await Stage(org, newSubject: "new-attacker-admin")).Code);
        Assert.NotEqual(0, (await Stage(org, oldIssuer: "https://other.example.test/")).Code);
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(org));
    }

    [Fact]
    public async Task Non_suspended_pending_missing_or_forged_suspension_is_rejected()
    {
        var operational = await Seed(administrators: [Old]);
        Assert.NotEqual(0, (await Stage(operational)).Code);
        Assert.NotEqual(0, (await Stage(Guid.NewGuid())).Code);
        var pending = await Seed(activated: false, administrators: [Old]);
        Assert.NotEqual(0, (await Stage(pending)).Code);
        var forged = await Seed(suspended: true, administrators: [Old]);
        Assert.NotEqual(0, (await Stage(forged)).Code); // no suspension audit
        Assert.Equal((true, true, 1L, 0L, 0L, 0L, 0L, 0L), await State(forged));
        Assert.Equal((false, true, 1L, 0L, 0L, 0L, 0L, 0L), await State(operational));
    }

    [Fact]
    public async Task Multiple_admins_inactive_or_legacy_admins_are_not_emergency_sole_admin()
    {
        var multiple = await Seed(administrators: [Old, "another-valid-admin"]);
        Assert.Equal(0, (await Lifecycle(multiple)).Code);
        Assert.NotEqual(0, (await Stage(multiple)).Code);
        var inactive = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(inactive)).Code);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                UPDATE platform.organization_memberships SET is_active=FALSE
                WHERE organization_id=@id AND subject=@sub
                """, db);
            cmd.Parameters.AddWithValue("id", inactive);
            cmd.Parameters.AddWithValue("sub", Old);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Stage(inactive)).Code);
        var unbound = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(unbound)).Code);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                UPDATE platform.organization_memberships SET identity_issuer=NULL
                WHERE organization_id=@id AND subject=@sub
                """, db);
            cmd.Parameters.AddWithValue("id", unbound);
            cmd.Parameters.AddWithValue("sub", Old);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Stage(unbound)).Code);
    }

    [Fact]
    public async Task Reviewer_validation_target_collision_and_runtime_credentials_fail_closed()
    {
        var org = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(org)).Code);
        foreach (var attempt in new[] {
            Stage(org, reviewer1: null),
            Stage(org, reviewer2: null),
            Stage(org, reviewer1: SecondReviewer),
            Stage(org, reviewer2: FirstReviewer),
            Stage(org, oldSubject: New),
            Stage(org, oldSubject: " old "),
            Stage(org, newSubject: Old),
            Stage(org, newSubject: "bad\nsubject"),
            Stage(org, oldIssuer: "http://issuer.example.test"),
            Stage(org, newIssuer: "http://issuer.example.test"),
            Stage(org, incident: null),
            Stage(org, incident: "bad ticket"),
            Stage(org, reason: null),
            Stage(org, reason: "compromised'; DROP TABLE platform.organizations; --")
        })
        {
            Assert.NotEqual(0, (await attempt).Code);
        }
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                 (organization_id,subject,identity_issuer,role,is_active)
                VALUES (@org,@sub,@issuer,'Reader',TRUE)
                """, db);
            cmd.Parameters.AddWithValue("org", org);
            cmd.Parameters.AddWithValue("sub", New);
            cmd.Parameters.AddWithValue("issuer", Issuer);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Stage(org)).Code);
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted runtime DB principal required");
        Assert.NotEqual(0, (await Stage(org, connection: runtime)).Code);
        Assert.Equal((true, true, 1L, 0L, 0L, 0L, 1L, 0L), await State(org));
    }

    [Fact]
    public async Task Compromised_identity_with_another_membership_must_not_leave_residual_access()
    {
        var org = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(org)).Code);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                    (organization_id,subject,identity_issuer,role,is_active)
                VALUES (@id,@sub,@issuer,'Reader',TRUE)
                """, db);
            cmd.Parameters.AddWithValue("id", org);
            cmd.Parameters.AddWithValue("sub", Old);
            cmd.Parameters.AddWithValue("issuer", Issuer);
            await cmd.ExecuteNonQueryAsync();
        }
        // A transfer of Admin alone would leave a compromised Reader
        // authorized after an independent reactivation. Reject the entire
        // change instead of silently assuming all old access was revoked.
        Assert.NotEqual(0, (await Stage(org)).Code);
        Assert.Equal((true, true, 1L, 0L, 0L, 0L, 1L, 0L), await State(org));
        await using var check = new NpgsqlConnection(Owner);
        await check.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT COUNT(*) FROM platform.organization_memberships
            WHERE organization_id=@id AND subject=@sub AND is_active
            """, check);
        query.Parameters.AddWithValue("id", org);
        query.Parameters.AddWithValue("sub", Old);
        Assert.Equal(2L, (long)(await query.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task Concurrent_change_for_one_tenant_serializes_and_cannot_cross_tenants()
    {
        var org = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(org)).Code);
        var two = await Task.WhenAll(
            Stage(org, newSubject: New),
            Stage(org, newSubject: "other-new-admin"));
        Assert.Single(two.Where(x => x.Code == 0));
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(org));

        var other = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(other)).Code);
        Assert.Equal(0, (await Stage(other)).Code);
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(other));
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(org));
        var identical = await Seed(administrators: [Old]);
        Assert.Equal(0, (await Lifecycle(identical)).Code);
        var retries = await Task.WhenAll(Stage(identical), Stage(identical));
        Assert.All(retries, result => Assert.Equal(0, result.Code));
        Assert.Equal((true, true, 1L, 1L, 1L, 1L, 1L, 0L), await State(identical));
    }
}
