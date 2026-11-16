using System.Diagnostics;
using System.Net;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Test-first owner-only Admin replacement after a verified revocation (#83).
/// Real disposable PostgreSQL + psql, signed local OIDC, no production identity.
/// </summary>
public sealed class AdminRecoveryTests(OidcApiFactory factory) : IClassFixture<OidcApiFactory>
{
    private const string Issuer = OidcApiFactory.Issuer;
    private const string First = "recovery-initial-admin";
    private const string Second = "recovery-second-admin";
    private const string Third = "recovery-replacement-admin";
    private const string Fourth = "recovery-fourth-admin";
    private const string ReplacementTicket = "CHANGE-2026-RECOVER83";

    private static string Owner => Environment.GetEnvironmentVariable("TEST_DATABASE_CONNECTION")
        ?? throw new InvalidOperationException("Disposable PostgreSQL database is required.");

    private static string Script(string name)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "AGENTS.md")))
                return Path.Combine(dir.FullName, "scripts", "postgres", name);
        }
        throw new InvalidOperationException("Project root not found.");
    }

    private static async Task<(int Code, string Output)> Run(
        string file, Guid org, string subject = Third, string? issuer = Issuer,
        string? ticket = ReplacementTicket, string? reviewer = "independent-reviewer",
        string? connection = null)
    {
        var path = Script(file);
        Assert.True(File.Exists(path));
        var db = new NpgsqlConnectionStringBuilder(connection ?? Owner);
        var start = new ProcessStartInfo("psql")
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        };
        foreach (var arg in new[] {
            "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", db.Host,
            "-p", db.Port.ToString(), "-U", db.Username, "-d", db.Database, "-f", path
        }) start.ArgumentList.Add(arg);
        start.Environment["PGPASSWORD"] = db.Password;
        void Env(string key, string? value)
        {
            if (value is null) start.Environment.Remove(key);
            else start.Environment[key] = value;
        }
        Env("COMUNI_BOOTSTRAP_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_BOOTSTRAP_IDENTITY_ISSUER", Issuer);
        Env("COMUNI_BOOTSTRAP_SUBJECT", First);
        Env("COMUNI_BOOTSTRAP_CHANGE_TICKET", "CHANGE-2026-BOOT83");
        Env("COMUNI_BOOTSTRAP_APPROVER", "independent-reviewer");

        Env("COMUNI_ADD_ADMIN_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_ADD_ADMIN_IDENTITY_ISSUER", issuer);
        Env("COMUNI_ADD_ADMIN_SUBJECT", subject);
        Env("COMUNI_ADD_ADMIN_CHANGE_TICKET", ticket);
        Env("COMUNI_ADD_ADMIN_APPROVER", reviewer);

        Env("COMUNI_REVOKE_ADMIN_ORGANIZATION_ID", org.ToString("D"));
        Env("COMUNI_REVOKE_ADMIN_IDENTITY_ISSUER", Issuer);
        Env("COMUNI_REVOKE_ADMIN_SUBJECT", First);
        Env("COMUNI_REVOKE_ADMIN_CHANGE_TICKET", "CHANGE-2026-REVOKE83");
        Env("COMUNI_REVOKE_ADMIN_APPROVER", "independent-reviewer");
        Env("COMUNI_REVOKE_ADMIN_REASON_CODE", "operator-departure");

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("psql process unavailable.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, await stdout + await stderr);
    }

    private static async Task<Guid> Seed(bool active = true, bool suspended = false)
    {
        var id = Guid.NewGuid();
        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var sql = new NpgsqlCommand("""
            INSERT INTO platform.organizations (id, name, is_activated, is_suspended)
            VALUES (@id, 'Comune recovery sintetico', @active, @suspended)
            """, db);
        sql.Parameters.AddWithValue("id", id);
        sql.Parameters.AddWithValue("active", active);
        sql.Parameters.AddWithValue("suspended", suspended);
        await sql.ExecuteNonQueryAsync();
        return id;
    }

    private static Task<(int Code, string Output)> Bootstrap(Guid org) =>
        Run("bootstrap-initial-admin.sql", org);

    private static Task<(int Code, string Output)> Add(
        Guid org, string subject = Third, string? issuer = Issuer,
        string? ticket = ReplacementTicket, string? reviewer = "independent-reviewer",
        string? connection = null) =>
        Run("enroll-additional-admin.sql", org, subject, issuer, ticket, reviewer, connection);

    private static Task<(int Code, string Output)> RevokeFirst(Guid org) =>
        Run("revoke-admin.sql", org);

    private static async Task<Guid> SeedRevoked()
    {
        var org = await Seed();
        Assert.Equal(0, (await Bootstrap(org)).Code);
        Assert.Equal(0, (await Add(org, Second, ticket: "CHANGE-2026-ADD83")).Code);
        Assert.Equal(0, (await RevokeFirst(org)).Code);
        return org;
    }

    private static async Task<(long Active, long Inactive, long Added, long Revoked)> Counts(Guid org)
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
                 WHERE organization_id=@id AND action='platform.membership.admin.revoked')
            """, db);
        sql.Parameters.AddWithValue("id", org);
        await using var row = await sql.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetInt64(0), row.GetInt64(1), row.GetInt64(2), row.GetInt64(3));
    }

    [Fact]
    public async Task Replacement_after_verified_revocation_preserves_history_and_works_with_oidc()
    {
        var org = await SeedRevoked();
        Assert.Equal((1L, 1L, 1L, 1L), await Counts(org));
        using var revoked = factory.Authenticated(factory.Token(subject: First, organizationId: org.ToString("D")));
        using var surviving = factory.Authenticated(factory.Token(subject: Second, organizationId: org.ToString("D")));
        using var replacement = factory.Authenticated(factory.Token(subject: Third, organizationId: org.ToString("D")));
        Assert.Equal(HttpStatusCode.Forbidden, (await revoked.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await replacement.GetAsync("/api/v1/context")).StatusCode);

        var change = await Add(org);
        Assert.Equal(0, change.Code);
        foreach (var secret in new[] { Issuer, Third, ReplacementTicket, org.ToString("D") })
            Assert.DoesNotContain(secret, change.Output);
        Assert.Equal((2L, 1L, 2L, 1L), await Counts(org));
        Assert.Equal(HttpStatusCode.Forbidden, (await revoked.GetAsync("/api/v1/admin/memberships")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await surviving.GetAsync("/api/v1/admin/memberships")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await replacement.GetAsync("/api/v1/admin/memberships")).StatusCode);
        Assert.Equal(0, (await Add(org)).Code);
        Assert.Equal((2L, 1L, 2L, 1L), await Counts(org));

        await using var db = new NpgsqlConnection(Owner);
        await db.OpenAsync();
        await using var sql = new NpgsqlCommand("""
            SELECT subject, identity_issuer, is_active
            FROM platform.organization_memberships
            WHERE organization_id=@id AND role='Admin' ORDER BY subject
            """, db);
        sql.Parameters.AddWithValue("id", org);
        await using (var records = await sql.ExecuteReaderAsync())
        {
            var subjects = new Dictionary<string, bool>();
            while (await records.ReadAsync())
            {
                Assert.Equal(Issuer, records.GetString(1));
                subjects.Add(records.GetString(0), records.GetBoolean(2));
            }
            Assert.Equal(3, subjects.Count);
            Assert.False(subjects[First]);
            Assert.True(subjects[Second]);
            Assert.True(subjects[Third]);
        }
        await using var audits = new NpgsqlCommand("""
            SELECT actor_subject, resource_type, correlation_id
            FROM platform.audit_events
            WHERE organization_id=@id AND action='platform.membership.admin.added'
              AND correlation_id='admin-enroll:CHANGE-2026-RECOVER83'
            """, db);
        audits.Parameters.AddWithValue("id", org);
        await using var ev = await audits.ExecuteReaderAsync();
        Assert.True(await ev.ReadAsync());
        Assert.StartsWith("db-owner:", ev.GetString(0));
        Assert.Equal("platform.membership", ev.GetString(1));
        Assert.Equal("admin-enroll:" + ReplacementTicket, ev.GetString(2));
        Assert.False(await ev.ReadAsync());
    }

    [Fact]
    public async Task Previously_revoked_subject_cannot_be_reactivated_with_same_or_new_issuer()
    {
        var org = await SeedRevoked();
        Assert.NotEqual(0, (await Add(org, First)).Code);
        Assert.NotEqual(0, (await Add(org, First, issuer: "https://other.example.test/")).Code);
        Assert.NotEqual(0, (await Add(org, Second)).Code);
        Assert.Equal((1L, 1L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Cannot_reuse_existing_ticket_or_existing_reader_even_after_revocation()
    {
        var org = await SeedRevoked();
        Assert.NotEqual(0, (await Add(org, Third, ticket: "CHANGE-2026-ADD83")).Code);
        Assert.NotEqual(0, (await Add(org, Third, ticket: "CHANGE-2026-BOOT83")).Code);
        Assert.NotEqual(0, (await Add(org, Third, ticket: "CHANGE-2026-REVOKE83")).Code);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var sql = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                   (organization_id, subject, role, identity_issuer, is_active)
                VALUES (@id, @sub, 'Reader', @issuer, TRUE)
                """, db);
            sql.Parameters.AddWithValue("id", org);
            sql.Parameters.AddWithValue("sub", Third);
            sql.Parameters.AddWithValue("issuer", Issuer);
            await sql.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(org)).Code);
        Assert.Equal((1L, 1L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Unattested_inactive_admin_or_legacy_unbound_admin_fails_closed()
    {
        var org = await SeedRevoked();
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                  (organization_id, subject, role, identity_issuer, is_active)
                VALUES (@id, 'unattested-disabled-admin', 'Admin', @issuer, FALSE)
                """, db);
            cmd.Parameters.AddWithValue("id", org);
            cmd.Parameters.AddWithValue("issuer", Issuer);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(org)).Code);

        var legacy = await SeedRevoked();
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO platform.organization_memberships
                  (organization_id, subject, role, identity_issuer, is_active)
                VALUES (@id, 'unbound-legacy-admin', 'Admin', NULL, TRUE)
                """, db);
            cmd.Parameters.AddWithValue("id", legacy);
            await cmd.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(legacy)).Code);
    }

    [Fact]
    public async Task Duplicate_or_missing_revocation_evidence_is_never_accepted()
    {
        var org = await SeedRevoked();
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var copy = new NpgsqlCommand("""
                INSERT INTO platform.audit_events
                    (id,organization_id,actor_subject,action,resource_type,
                     resource_id,correlation_id,occurred_at)
                SELECT gen_random_uuid(),organization_id,actor_subject,action,resource_type,
                       resource_id,correlation_id,now()
                FROM platform.audit_events
                WHERE organization_id=@id AND action='platform.membership.admin.revoked'
                """, db);
            copy.Parameters.AddWithValue("id", org);
            Assert.Equal(1, await copy.ExecuteNonQueryAsync());
        }
        Assert.NotEqual(0, (await Add(org)).Code);
        Assert.Equal((1L, 1L, 1L, 2L), await Counts(org));
    }

    [Fact]
    public async Task Deleted_historic_admin_cannot_be_regranted_because_its_audit_survives()
    {
        var org = await SeedRevoked();
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var delete = new NpgsqlCommand("""
                DELETE FROM platform.organization_memberships
                WHERE organization_id=@id AND subject=@sub AND role='Admin' AND NOT is_active
                """, db);
            delete.Parameters.AddWithValue("id", org);
            delete.Parameters.AddWithValue("sub", First);
            Assert.Equal(1, await delete.ExecuteNonQueryAsync());
        }
        // Simulate an unauthorized schema-owner hard delete; the audit remains.
        Assert.NotEqual(0, (await Add(org, First)).Code);
        Assert.Equal((1L, 0L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Recovery_requires_operational_org_independent_approval_and_schema_owner()
    {
        var org = await SeedRevoked();
        Assert.NotEqual(0, (await Add(org, issuer: "http://not-https.example.test")).Code);
        Assert.NotEqual(0, (await Add(org, issuer: "https://evil.test@identity.example.test")).Code);
        Assert.NotEqual(0, (await Add(org, subject: " signed-in-admin ")).Code);
        Assert.NotEqual(0, (await Add(org, subject: "bad\nsubject")).Code);
        Assert.NotEqual(0, (await Add(org, ticket: null)).Code);
        Assert.NotEqual(0, (await Add(org, reviewer: null)).Code);
        Assert.NotEqual(0, (await Add(org, ticket: "bad ticket")).Code);
        var runtime = Environment.GetEnvironmentVariable("TEST_RUNTIME_DATABASE_CONNECTION")
            ?? throw new InvalidOperationException("Restricted SQL runtime connection required.");
        Assert.NotEqual(0, (await Add(org, connection: runtime)).Code);
        Assert.NotEqual(0, (await Add(Guid.NewGuid())).Code);
        Assert.NotEqual(0, (await Add(Guid.Empty)).Code);
        var pending = await Seed(active: false);
        Assert.Equal(0, (await Bootstrap(pending)).Code);
        Assert.NotEqual(0, (await Add(pending)).Code);
        await using (var db = new NpgsqlConnection(Owner))
        {
            await db.OpenAsync();
            await using var sql = new NpgsqlCommand(
                "UPDATE platform.organizations SET is_suspended=TRUE WHERE id=@id", db);
            sql.Parameters.AddWithValue("id", org);
            await sql.ExecuteNonQueryAsync();
        }
        Assert.NotEqual(0, (await Add(org)).Code);
        Assert.Equal((1L, 1L, 1L, 1L), await Counts(org));
    }

    [Fact]
    public async Task Concurrent_recovery_attempts_serialize_and_preserve_prior_revocation()
    {
        var org = await SeedRevoked();
        var same = await Task.WhenAll(Add(org), Add(org));
        Assert.All(same, x => Assert.Equal(0, x.Code));
        Assert.Equal((2L, 1L, 2L, 1L), await Counts(org));

        var another = await SeedRevoked();
        var competing = await Task.WhenAll(Add(another, Third), Add(another, Fourth));
        Assert.Single(competing, x => x.Code == 0);
        Assert.Equal((2L, 1L, 2L, 1L), await Counts(another));
    }

    [Fact]
    public async Task Recovery_only_affects_the_selected_tenant_and_keeps_original_audits()
    {
        var first = await SeedRevoked();
        var second = await SeedRevoked();
        Assert.Equal(0, (await Add(first)).Code);
        Assert.Equal((2L, 1L, 2L, 1L), await Counts(first));
        Assert.Equal((1L, 1L, 1L, 1L), await Counts(second));
        using var otherSurvivor = factory.Authenticated(
            factory.Token(subject: Second, organizationId: second.ToString("D")));
        using var otherRevoked = factory.Authenticated(
            factory.Token(subject: First, organizationId: second.ToString("D")));
        Assert.Equal(HttpStatusCode.OK, (await otherSurvivor.GetAsync("/api/v1/context")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await otherRevoked.GetAsync("/api/v1/context")).StatusCode);
    }
}
