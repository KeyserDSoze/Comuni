using System.Diagnostics;
using System.Net;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// #87: RED-first contract for normal Admin enrollment after independently
/// suspended, emergency-staged and reactivated municipality.
/// All issuers, subjects and approvals are synthetic (no real IdP).
/// </summary>
public sealed class PostEmergencyAdminEnrollmentTests(OidcApiFactory factory)
    : IClassFixture<OidcApiFactory>
{
    private const string Issuer = OidcApiFactory.Issuer;
    private const string Old = "post-emergency-compromised";
    private const string Rescued = "post-emergency-rescued";
    private const string Additional = "post-emergency-additional";
    private const string Incident = "INC-2026-RECOVERY87";
    private const string Change = "CHANGE-2026-AFTER87";

    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL owner required.");

    private static string Root()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return dir.FullName;
        throw new InvalidOperationException("Repository root not found.");
    }

    private static async Task<int> Execute(Guid org, string file, string? target = Additional,
        string? ticket = Change, string? connection = null)
    {
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            WorkingDirectory = Root(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var arg in new[] {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", db.Host, "-p", db.Port.ToString(),
            "-U", db.Username, "-d", db.Database, "-f", Path.Combine(Root(), "scripts", "postgres", file)
        })
            start.ArgumentList.Add(arg!);
        start.Environment["PGPASSWORD"] = db.Password;
        void Env(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        Env("COMUNI_LIFECYCLE_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_LIFECYCLE_ACTION", file == "set-organization-suspension.sql" && ticket == "reactivate"
            ? "reactivate" : "suspend");
        Env("COMUNI_LIFECYCLE_CHANGE_TICKET", ticket == "reactivate"
            ? "CHANGE-2026-REACT87" : "CHANGE-2026-SUSP87");
        Env("COMUNI_LIFECYCLE_APPROVER", "lifecycle-reviewer");
        Env("COMUNI_LIFECYCLE_REASON_CODE", "incident-review");

        Env("COMUNI_EMERGENCY_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_EMERGENCY_OLD_IDENTITY_ISSUER", Issuer);
        Env("COMUNI_EMERGENCY_OLD_SUBJECT", Old);
        Env("COMUNI_EMERGENCY_NEW_IDENTITY_ISSUER", Issuer);
        Env("COMUNI_EMERGENCY_NEW_SUBJECT", Rescued);
        Env("COMUNI_EMERGENCY_INCIDENT_TICKET", Incident);
        Env("COMUNI_EMERGENCY_SECURITY_REVIEWER", "security-reviewer");
        Env("COMUNI_EMERGENCY_MUNICIPAL_REVIEWER", "municipal-reviewer");
        Env("COMUNI_EMERGENCY_REASON_CODE", "account-compromise");

        Env("COMUNI_ADD_ADMIN_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_ADD_ADMIN_IDENTITY_ISSUER", Issuer);
        Env("COMUNI_ADD_ADMIN_SUBJECT", target);
        Env("COMUNI_ADD_ADMIN_CHANGE_TICKET", ticket);
        Env("COMUNI_ADD_ADMIN_APPROVER", "enrollment-reviewer");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("psql unavailable");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        var output = await stdout + await stderr;
        foreach (var secret in new[] { Issuer, Old, Rescued, Additional, Incident, org.ToString("D") })
            Assert.DoesNotContain(secret, output);
        return process.ExitCode;
    }

    private static async Task<Guid> Seed()
    {
        var id = Guid.NewGuid();
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var sql = new NpgsqlCommand("""
            INSERT INTO platform.organizations(id,name,is_activated,is_suspended)
            VALUES(@id,'Comune sintetico issue 87',TRUE,FALSE);
            INSERT INTO platform.organization_memberships
                (organization_id,subject,identity_issuer,role,is_active)
            VALUES(@id,@sub,@issuer,'Admin',TRUE);
            INSERT INTO platform.organization_modules(organization_id,module_key,enabled)
            VALUES(@id,'protocol',TRUE);
            """, db);
        sql.Parameters.AddWithValue("id", id);
        sql.Parameters.AddWithValue("sub", Old);
        sql.Parameters.AddWithValue("issuer", Issuer);
        await sql.ExecuteNonQueryAsync();
        return id;
    }

    private static async Task<Guid> Staged(bool reactivate = true)
    {
        var org = await Seed();
        Assert.Equal(0, await Execute(org, "set-organization-suspension.sql", ticket: "suspend"));
        Assert.Equal(0, await Execute(org, "stage-emergency-admin-replacement.sql"));
        if (reactivate)
            Assert.Equal(0, await Execute(org, "set-organization-suspension.sql", ticket: "reactivate"));
        return org;
    }

    private static Task<int> Enroll(Guid org, string? target = Additional, string? ticket = Change,
        string? connection = null) =>
        Execute(org, "enroll-additional-admin.sql", target, ticket, connection);

    private static async Task<(long Active, long Inactive, long Added, long Revoked, long Staged)> Counts(Guid org)
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var sql = new NpgsqlCommand("""
            SELECT
              (SELECT COUNT(*) FROM platform.organization_memberships
               WHERE organization_id=@id AND role='Admin' AND is_active),
              (SELECT COUNT(*) FROM platform.organization_memberships
               WHERE organization_id=@id AND role='Admin' AND NOT is_active),
              (SELECT COUNT(*) FROM platform.audit_events
               WHERE organization_id=@id AND action='platform.membership.admin.added'),
              (SELECT COUNT(*) FROM platform.audit_events
               WHERE organization_id=@id AND action='platform.membership.admin.emergency.revoked'),
              (SELECT COUNT(*) FROM platform.audit_events
               WHERE organization_id=@id AND action='platform.membership.admin.emergency.staged')
            """, db);
        sql.Parameters.AddWithValue("id", org);
        await using var r = await sql.ExecuteReaderAsync();
        Assert.True(await r.ReadAsync());
        return (r.GetInt64(0), r.GetInt64(1), r.GetInt64(2), r.GetInt64(3), r.GetInt64(4));
    }

    private static async Task InjectAudit(Guid org, string action, string correlation,
        string subject, string actor = "db-owner:synthetic")
    {
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var sql = new NpgsqlCommand("""
            INSERT INTO platform.audit_events
                (id, organization_id, actor_subject, action, resource_type, resource_id,
                 correlation_id, occurred_at)
            VALUES (gen_random_uuid(), @id, @actor, @action, 'platform.membership',
                md5(@id::text || '|Admin|' || @sub || '|' || @issuer)::uuid, @corr, now())
            """, db);
        sql.Parameters.AddWithValue("id", org);
        sql.Parameters.AddWithValue("actor", actor);
        sql.Parameters.AddWithValue("action", action);
        sql.Parameters.AddWithValue("sub", subject);
        sql.Parameters.AddWithValue("issuer", Issuer);
        sql.Parameters.AddWithValue("corr", correlation);
        await sql.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task Verified_pair_and_separate_reactivation_allow_one_more_admin_without_reactivating_old_identity()
    {
        var org = await Staged();
        using var old = factory.Authenticated(factory.Token(subject: Old, organizationId: org.ToString("D")));
        using var recovered = factory.Authenticated(factory.Token(subject: Rescued, organizationId: org.ToString("D")));
        using var added = factory.Authenticated(factory.Token(subject: Additional, organizationId: org.ToString("D")));
        Assert.Equal(HttpStatusCode.Forbidden, (await old.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await recovered.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await added.GetAsync("/api/v1/context")).StatusCode);

        Assert.Equal(0, await Enroll(org));
        Assert.Equal(0, await Enroll(org)); // exact replay
        Assert.Equal((2L, 1L, 1L, 1L, 1L), await Counts(org));
        Assert.Equal(HttpStatusCode.Forbidden, (await old.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await recovered.GetAsync("/api/v1/admin/modules")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await added.GetAsync("/api/v1/admin/modules")).StatusCode);
    }

    [Fact]
    public async Task Suspended_tenant_never_enrolls_and_staged_identity_is_not_usable_yet()
    {
        var org = await Staged(reactivate: false);
        Assert.NotEqual(0, await Enroll(org));
        using var staged = factory.Authenticated(factory.Token(subject: Rescued, organizationId: org.ToString("D")));
        Assert.Equal(HttpStatusCode.Forbidden, (await staged.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal((1L, 1L, 0L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Manually_clearing_suspension_flag_without_owner_reactivation_audit_cannot_grant_Admin()
    {
        var org = await Staged(reactivate: false);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var sql = new NpgsqlCommand("""
                UPDATE platform.organizations SET is_suspended=FALSE WHERE id=@id
                """, db);
            sql.Parameters.AddWithValue("id", org);
            Assert.Equal(1, await sql.ExecuteNonQueryAsync());
        }
        Assert.NotEqual(0, await Enroll(org));
        Assert.Equal((1L, 1L, 0L, 1L, 1L), await Counts(org));
    }

    [Theory]
    [InlineData("platform.membership.admin.emergency.revoked", "post-emergency-compromised")]
    [InlineData("platform.membership.admin.emergency.staged", "post-emergency-rescued")]
    public async Task Duplicate_incident_audit_rejects_new_enrollment(string action, string subject)
    {
        var org = await Staged();
        await InjectAudit(org, action, "emergency:" + Incident, subject);
        Assert.NotEqual(0, await Enroll(org));
        Assert.Equal(0L, (await Counts(org)).Added);
    }

    [Fact]
    public async Task Orphan_emergency_audit_and_invalid_owner_provenance_fail_closed()
    {
        var org = await Staged();
        await InjectAudit(org, "platform.membership.admin.emergency.revoked",
            "emergency:INC-2026-UNMATCHED87", "other-inactive", "external:unverified");
        Assert.NotEqual(0, await Enroll(org));
        Assert.Equal(0L, (await Counts(org)).Added);
    }

    [Fact]
    public async Task Conflicting_targets_tickets_and_runtime_are_rejected_after_emergency()
    {
        var org = await Staged();
        Assert.NotEqual(0, await Enroll(org, target: Old));
        Assert.NotEqual(0, await Enroll(org, target: Rescued));
        Assert.NotEqual(0, await Enroll(org, ticket: Incident));
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted PostgreSQL login is required");
        Assert.NotEqual(0, await Enroll(org, connection: runtime));
        Assert.Equal((1L, 1L, 0L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Concurrent_reuse_of_same_approval_can_grant_only_one_identity_in_own_tenant()
    {
        var org = await Staged();
        var other = await Staged();
        var candidates = await Task.WhenAll(
            Enroll(org, "additional-a"),
            Enroll(org, "additional-b"));
        Assert.Single(candidates, result => result == 0);
        Assert.Equal((2L, 1L, 1L, 1L, 1L), await Counts(org));
        Assert.Equal((1L, 1L, 0L, 1L, 1L), await Counts(other));
        Assert.Equal(0, await Enroll(other));
        Assert.Equal((2L, 1L, 1L, 1L, 1L), await Counts(other));
    }
}
