using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class MembershipAdministrationApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private async Task<Guid> SeedAsync()
    {
        var org = Guid.NewGuid();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organizations (id, name) VALUES ({org}, {"Comune test membership"})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active) VALUES ({org}, {"test-admin"}, {"Admin"}, {true}), ({org}, {"test-reader"}, {"Reader"}, {true}), ({org}, {"test-officer"}, {"Officer"}, {true})");
        return org;
    }

    [Fact]
    public async Task Anonymous_and_non_admin_users_cannot_read_or_assign_memberships()
    {
        var org = await SeedAsync();
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.GetAsync("/api/v1/admin/memberships")).StatusCode);
        foreach (var role in new[] { "Reader", "Officer" })
        {
            using var client = factory.ClientFor(org.ToString(), role);
            Assert.Equal(HttpStatusCode.Forbidden,
                (await client.GetAsync("/api/v1/admin/memberships")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden,
                (await client.PutAsJsonAsync("/api/v1/admin/memberships/Reader",
                    new { subject = "test-new", enabled = true })).StatusCode);
        }
        using var spoof = factory.ClientFor(org.ToString(), "Admin", "test-reader");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await spoof.PutAsJsonAsync("/api/v1/admin/memberships/Officer",
                new { subject = "test-new", enabled = true })).StatusCode);
    }

    [Fact]
    public async Task Admin_lists_only_own_organization_and_cannot_override_tenant_in_body()
    {
        var first = await SeedAsync();
        var second = await SeedAsync();
        using var client = factory.ClientFor(first.ToString(), "Admin");
        using var list = JsonDocument.Parse(await client.GetStringAsync("/api/v1/admin/memberships"));
        Assert.Contains(list.RootElement.EnumerateArray(),
            x => x.GetProperty("subject").GetString() == "test-admin" && x.GetProperty("role").GetString() == "Admin");

        var newSubject = "idp-test-" + Guid.NewGuid().ToString("N");
        Assert.Equal(HttpStatusCode.OK,
            (await client.PutAsJsonAsync("/api/v1/admin/memberships/Reader",
                new { subject = newSubject, enabled = true, organizationId = second, actorSubject = "forged" })).StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var rows = await db.OrganizationMemberships.IgnoreQueryFilters().AsNoTracking()
            .Where(x => x.Subject == newSubject).ToArrayAsync();
        var row = Assert.Single(rows);
        Assert.Equal(first, row.OrganizationId);
        Assert.True(row.IsActive);
    }

    [Fact]
    public async Task Admin_can_assign_disable_and_restore_reader_and_officer_access_immediately()
    {
        var org = await SeedAsync();
        using var admin = factory.ClientFor(org.ToString(), "Admin");
        var subject = "idp-member-" + Guid.NewGuid().ToString("N");
        foreach (var role in new[] { "Reader", "Officer" })
        {
            var url = "/api/v1/admin/memberships/" + role;
            Assert.Equal(HttpStatusCode.OK,
                (await admin.PutAsJsonAsync(url, new { subject, enabled = true })).StatusCode);
            using var client = factory.ClientFor(org.ToString(), role, subject);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/context")).StatusCode);

            Assert.Equal(HttpStatusCode.OK,
                (await admin.PutAsJsonAsync(url, new { subject, enabled = false })).StatusCode);
            // The other role may still allow access, so check the DB membership itself.
            using (var scope = factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
                Assert.False(await db.OrganizationMemberships.IgnoreQueryFilters().AsNoTracking()
                    .Where(x => x.OrganizationId == org && x.Subject == subject && x.Role == role)
                    .Select(x => x.IsActive).SingleAsync());
            }
            Assert.Equal(HttpStatusCode.OK,
                (await admin.PutAsJsonAsync(url, new { subject, enabled = true })).StatusCode);
        }

        // Turn off both memberships: a valid JWT can no longer access any tenant API.
        foreach (var role in new[] { "Reader", "Officer" })
            Assert.Equal(HttpStatusCode.OK,
                (await admin.PutAsJsonAsync("/api/v1/admin/memberships/" + role,
                    new { subject, enabled = false })).StatusCode);
        using var denied = factory.ClientFor(org.ToString(), "Admin", subject);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await denied.GetAsync("/api/v1/context")).StatusCode);
    }

    [Fact]
    public async Task Admin_and_unknown_role_assignment_are_rejected_without_creating_any_row()
    {
        var org = await SeedAsync();
        using var client = factory.ClientFor(org.ToString(), "Admin");
        var subject = "idp-test-" + Guid.NewGuid().ToString("N");
        foreach (var role in new[] { "Admin", "Superadmin", "owner", "ReaderX" })
            Assert.Equal(HttpStatusCode.BadRequest,
                (await client.PutAsJsonAsync("/api/v1/admin/memberships/" + role,
                    new { subject, enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await client.PutAsJsonAsync("/api/v1/admin/memberships/Reader",
                new { subject = "  ", enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await client.PutAsJsonAsync("/api/v1/admin/memberships/Reader",
                new { subject, wrong = true })).StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        Assert.False(await db.OrganizationMemberships.IgnoreQueryFilters()
            .AnyAsync(x => x.Subject == subject));
    }

    [Fact]
    public async Task Noop_is_idempotent_and_audit_is_server_attributed_and_atomically_written()
    {
        var org = await SeedAsync();
        var subject = "idp-test-" + Guid.NewGuid().ToString("N");
        using var admin = factory.ClientFor(org.ToString(), "Admin");
        admin.DefaultRequestHeaders.TryAddWithoutValidation("X-Actor-Subject", "forged");
        var url = "/api/v1/admin/memberships/Reader";
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(url,
            new { subject, enabled = true, actorSubject = "forged", correlationId = "forged" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(url,
            new { subject, enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(url,
            new { subject, enabled = false })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync(url,
            new { subject, enabled = false })).StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var events = await db.AuditEvents.IgnoreQueryFilters().AsNoTracking()
            .Where(x => x.OrganizationId == org && x.ResourceType == "platform.membership"
                && (x.Action == "platform.membership.reader.activated" ||
                    x.Action == "platform.membership.reader.deactivated"))
            .ToArrayAsync();
        Assert.Equal(2, events.Length);
        Assert.Equal(events[0].ResourceId, events[1].ResourceId);
        Assert.All(events, audit =>
        {
            Assert.Equal("test-admin", audit.ActorSubject);
            Assert.NotEqual("forged", audit.CorrelationId);
            Assert.NotEqual(Guid.Empty, audit.ResourceId);
            Assert.DoesNotContain(subject, JsonSerializer.Serialize(audit));
        });
    }

    [Fact]
    public async Task Suspended_organization_denies_membership_listing_and_changes()
    {
        var org = await SeedAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE platform.organizations SET is_suspended = TRUE WHERE id = {org}");
        }
        using var client = factory.ClientFor(org.ToString(), "Admin");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync("/api/v1/admin/memberships")).StatusCode);
        var target = "no-creation-" + Guid.NewGuid().ToString("N");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PutAsJsonAsync("/api/v1/admin/memberships/Officer",
                new { subject = target, enabled = true })).StatusCode);
        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        Assert.False(await verifyDb.OrganizationMemberships.IgnoreQueryFilters()
            .AnyAsync(x => x.OrganizationId == org && x.Subject == target));
    }

    [Fact]
    public async Task Deactivation_of_unknown_subject_is_not_a_membership_creation()
    {
        var org = await SeedAsync();
        using var admin = factory.ClientFor(org.ToString(), "Admin");
        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.PutAsJsonAsync("/api/v1/admin/memberships/Reader",
                new { subject = "absent-" + Guid.NewGuid().ToString("N"), enabled = false })).StatusCode);
    }
}
