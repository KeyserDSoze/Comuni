using System.Security.Cryptography;
using System.Text;
using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Direct repository contracts on the REAL restricted PostgreSQL runtime login,
/// signed tenant proof, separate synthetic municipalities and append-only audit.
/// </summary>
public sealed class MembershipAdministrationIntegrityTests
{
    private static string OwnerConnection => Environment.GetEnvironmentVariable(
        "TEST_DATABASE_CONNECTION") ?? throw new InvalidOperationException("Synthetic PostgreSQL owner required.");

    private static string RuntimeConnection => Environment.GetEnvironmentVariable(
        "TEST_RUNTIME_DATABASE_CONNECTION") ?? throw new InvalidOperationException("Restricted SQL runtime required.");

    private static TenantProofSigner Signer() => new(
        Environment.GetEnvironmentVariable("Security__TenantProofKey")
            ?? throw new InvalidOperationException("Synthetic RLS signing key required."));

    private sealed class TestOrganization(Guid id) : ICurrentOrganization
    {
        public Guid OrganizationId => id;
    }

    private static ComuniDbContext Db(Guid id) => new(
        new DbContextOptionsBuilder<ComuniDbContext>().UseNpgsql(RuntimeConnection).Options,
        new TestOrganization(id));

    private static MembershipAdministrationRepository Repo(ComuniDbContext db, TenantProofSigner signer) =>
        new(db, signer, new MembershipIssuerPolicy(false));

    private static async Task<Guid> SeedAsync()
    {
        var id = Guid.NewGuid();
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var command = new NpgsqlCommand(
            "INSERT INTO platform.organizations(id,name) VALUES (@org,'Synthetic Membership Audit Integrity')", db);
        command.Parameters.AddWithValue("org", id);
        await command.ExecuteNonQueryAsync();
        return id;
    }

    private static Guid Pseudonym(Guid org, string subject, string role, string? issuer)
    {
        // Independent test oracle for ADR 0021's existing wire-compatible hash.
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{org:D}|{role}|{subject}|{issuer ?? ""}"));
        return new Guid(hash.AsSpan(0, 16));
    }

    private static AuditEvent Audit(Guid org, string subject, string role, bool enabled,
        string? issuer = null, string? action = null, string type = "platform.membership",
        Guid? resourceId = null, Guid? eventOrg = null) =>
        AuditEvent.Create(eventOrg ?? org, "synthetic-admin",
            action ?? $"platform.membership.{role.ToLowerInvariant()}.{(enabled ? "activated" : "deactivated")}",
            type, resourceId ?? Pseudonym(org, subject, role, issuer), "server-synthetic-correlation");

    private static async Task<(long Rows, long Audits, bool? Active)> CountsAsync(
        Guid org, string subject, string role)
    {
        await using var db = new NpgsqlConnection(OwnerConnection);
        await db.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT (SELECT count(*) FROM platform.organization_memberships
                    WHERE organization_id=@org AND subject=@subject AND role=@role),
                   (SELECT count(*) FROM platform.audit_events
                    WHERE organization_id=@org AND resource_type='platform.membership'),
                   (SELECT is_active FROM platform.organization_memberships
                    WHERE organization_id=@org AND subject=@subject AND role=@role)
            """, db);
        query.Parameters.AddWithValue("org", org);
        query.Parameters.AddWithValue("subject", subject);
        query.Parameters.AddWithValue("role", role);
        await using var row = await query.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        return (row.GetInt64(0), row.GetInt64(1), row.IsDBNull(2) ? null : row.GetBoolean(2));
    }

    [Fact]
    public async Task Reject_forged_membership_audits_invalid_subjects_and_cross_tenant_context()
    {
        var own = await SeedAsync();
        var other = await SeedAsync();
        const string subject = "synthetic-target";
        const string issuer = "Comuni.Tests";
        await using var db = Db(own);
        var signer = Signer();
        await using var transaction = await TenantDatabaseTransaction.BeginAsync(
            db, signer, CancellationToken.None);
        var repository = Repo(db, signer);
        var bad = new (string Description, Guid Org, string Subject, string Role,
            string? Issuer, AuditEvent Audit)[]
        {
            ("reversed action", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer, action:"platform.membership.reader.deactivated")),
            ("wrong role action", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer, action:"platform.membership.officer.activated")),
            ("module action", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer, action:"platform.module.protocol.enabled")),
            ("wrong resource type", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer, type:"platform.module")),
            ("wrong pseudonym", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer, resourceId:Guid.NewGuid())),
            ("mismatched issuer pseudonym", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, "https://other.example.test")),
            ("wrong audit organization", own, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer, eventOrg:other)),
            ("cross tenant write", other, subject, "Reader", issuer,
                Audit(other, subject, "Reader", true, issuer)),
            ("empty tenant", Guid.Empty, subject, "Reader", issuer,
                Audit(own, subject, "Reader", true, issuer)),
            ("Admin role", own, subject, "Admin", issuer,
                Audit(own, subject, "Admin", true, issuer)),
            ("padded subject", own, " padded-sub", "Reader", issuer,
                Audit(own, " padded-sub", "Reader", true, issuer)),
            ("control in subject", own, "bad\nsubject", "Reader", issuer,
                Audit(own, "bad\nsubject", "Reader", true, issuer))
        };

        foreach (var item in bad)
        {
            var ex = await Record.ExceptionAsync(() => repository.SetActiveAsync(
                item.Org, item.Subject, item.Role, true, item.Issuer,
                item.Audit, CancellationToken.None));
            Assert.IsType<UnauthorizedAccessException>(ex);
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            repository.ListAsync(other, CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            repository.ListAsync(Guid.Empty, CancellationToken.None));

        Assert.Equal((0L, 0L, (bool?)null), await CountsAsync(own, subject, "Reader"));
        Assert.Equal((0L, 0L, (bool?)null), await CountsAsync(other, subject, "Reader"));
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task Correct_grants_revocations_idempotence_and_rollback_remain_atomic()
    {
        var own = await SeedAsync();
        var other = await SeedAsync();
        const string subject = "synthetic-member";
        const string issuer = "Comuni.Tests";
        var signer = Signer();

        await using (var db = Db(own))
        {
            await using var transaction = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            var repository = Repo(db, signer);
            Assert.Empty(await repository.ListAsync(own, CancellationToken.None));
            Assert.Equal(MembershipUpdateStatus.Updated,
                await repository.SetActiveAsync(own, subject, "Reader", true, issuer,
                    Audit(own, subject, "Reader", true, issuer), CancellationToken.None));
            Assert.Equal(MembershipUpdateStatus.Unchanged,
                await repository.SetActiveAsync(own, subject, "Reader", true, issuer,
                    Audit(own, subject, "Reader", true, issuer), CancellationToken.None));
            Assert.Equal(MembershipUpdateStatus.Updated,
                await repository.SetActiveAsync(own, subject, "Officer", true, issuer,
                    Audit(own, subject, "Officer", true, issuer), CancellationToken.None));
            Assert.Equal(MembershipUpdateStatus.Updated,
                await repository.SetActiveAsync(own, subject, "Reader", false, issuer,
                    Audit(own, subject, "Reader", false, issuer), CancellationToken.None));
            Assert.Equal(MembershipUpdateStatus.Unchanged,
                await repository.SetActiveAsync(own, subject, "Reader", false, issuer,
                    Audit(own, subject, "Reader", false, issuer), CancellationToken.None));
            await transaction.CommitAsync();
        }

        Assert.Equal((1L, 3L, (bool?)false), await CountsAsync(own, subject, "Reader"));
        Assert.Equal((1L, 3L, (bool?)true), await CountsAsync(own, subject, "Officer"));
        Assert.Equal((0L, 0L, (bool?)null), await CountsAsync(other, subject, "Reader"));

        await using (var db = Db(own))
        {
            await using var transaction = await TenantDatabaseTransaction.BeginAsync(
                db, signer, CancellationToken.None);
            Assert.Equal(MembershipUpdateStatus.Updated,
                await Repo(db, signer).SetActiveAsync(own, subject, "Reader", true, issuer,
                    Audit(own, subject, "Reader", true, issuer), CancellationToken.None));
            await transaction.RollbackAsync();
        }
        Assert.Equal((1L, 3L, (bool?)false), await CountsAsync(own, subject, "Reader"));

        await using var owner = new NpgsqlConnection(OwnerConnection);
        await owner.OpenAsync();
        await using var query = new NpgsqlCommand("""
            SELECT action, resource_id, actor_subject
            FROM platform.audit_events
            WHERE organization_id=@org AND resource_type='platform.membership'
            ORDER BY occurred_at, id
            """, owner);
        query.Parameters.AddWithValue("org", own);
        var events = new List<(string Action, Guid ResourceId, string Actor)>();
        await using (var row = await query.ExecuteReaderAsync())
            while (await row.ReadAsync())
                events.Add((row.GetString(0), row.GetGuid(1), row.GetString(2)));
        Assert.Equal(3, events.Count);
        Assert.Contains(events, e =>
            e.Action == "platform.membership.reader.activated" &&
            e.ResourceId == Pseudonym(own, subject, "Reader", issuer));
        Assert.Contains(events, e =>
            e.Action == "platform.membership.reader.deactivated" &&
            e.ResourceId == Pseudonym(own, subject, "Reader", issuer));
        Assert.Contains(events, e =>
            e.Action == "platform.membership.officer.activated" &&
            e.ResourceId == Pseudonym(own, subject, "Officer", issuer));
        Assert.All(events, e => Assert.Equal("synthetic-admin", e.Actor));
        Assert.DoesNotContain(subject, string.Join("|", events.Select(e => e.Action)));
    }
}
