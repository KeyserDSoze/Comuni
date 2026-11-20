using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Comuni.Infrastructures.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED-first #128: the code-owned catalog must never turn future or
/// orphaned database module flags into usable municipal capabilities.
/// </summary>
public sealed class ModuleCatalogApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static readonly string[] Keys =
    [
        "administrative", "archive", "cemetery", "demographics", "finance",
        "local-police", "personnel", "protocol", "public-works", "taxes",
        "urban-planning", "utilities"
    ];

    private async Task<Guid> SeedAsync(bool protocolEnabled, bool rogueArchive)
    {
        var id = Guid.NewGuid();
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organizations (id, name) VALUES ({id}, {"Catalog test municipality"})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_modules (organization_id, module_key, enabled) VALUES ({id}, {"protocol"}, {protocolEnabled})");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active) VALUES ({id}, {"test-admin"}, {"Admin"}, {true}), ({id}, {"test-reader"}, {"Reader"}, {true}), ({id}, {"test-officer"}, {"Officer"}, {true})");
        if (rogueArchive)
            await db.Database.ExecuteSqlInterpolatedAsync(
                $"INSERT INTO platform.organization_modules (organization_id, module_key, enabled) VALUES ({id}, {"archive"}, {true})");
        return id;
    }

    [Fact]
    public async Task Catalog_is_admin_only_and_does_not_trust_jwt_role_claim()
    {
        var org = await SeedAsync(true, false);
        const string endpoint = "/api/v1/admin/modules/catalog";
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(endpoint)).StatusCode);
        foreach (var role in new[] { "Reader", "Officer" })
        {
            using var denied = factory.ClientFor(org.ToString(), role);
            Assert.Equal(HttpStatusCode.Forbidden, (await denied.GetAsync(endpoint)).StatusCode);
        }
        using var forged = factory.ClientFor(org.ToString(), "Admin", "test-reader");
        Assert.Equal(HttpStatusCode.Forbidden, (await forged.GetAsync(endpoint)).StatusCode);
        using var admin = factory.ClientFor(org.ToString(), "Admin");
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync(endpoint)).StatusCode);
    }

    [Fact]
    public async Task Catalog_distinguishes_implemented_from_planned_and_scopes_configured_state()
    {
        var orgA = await SeedAsync(true, true);
        var orgB = await SeedAsync(false, false);

        foreach (var (org, enabled) in new[] { (orgA, true), (orgB, false) })
        {
            using var admin = factory.ClientFor(org.ToString(), "Admin");
            using var result = JsonDocument.Parse(
                await admin.GetStringAsync("/api/v1/admin/modules/catalog"));
            var modules = result.RootElement.EnumerateArray().ToArray();
            Assert.Equal(Keys, modules.Select(x => x.GetProperty("key").GetString()).ToArray());
            foreach (var module in modules)
            {
                Assert.Equal(6, module.EnumerateObject().Count());
                Assert.False(string.IsNullOrWhiteSpace(module.GetProperty("name").GetString()));
                Assert.Empty(module.GetProperty("dependsOn").EnumerateArray());
                var protocol = module.GetProperty("key").GetString() == "protocol";
                Assert.Equal(protocol ? "available" : "planned",
                    module.GetProperty("status").GetString());
                Assert.Equal(protocol, module.GetProperty("configurable").GetBoolean());
                Assert.Equal(protocol && enabled, module.GetProperty("enabled").GetBoolean());
            }
        }
    }

    [Fact]
    public async Task Future_flag_in_database_cannot_activate_unimplemented_module_or_modify_audit()
    {
        var orgA = await SeedAsync(true, true);
        var orgB = await SeedAsync(false, false);
        using var admin = factory.ClientFor(orgA.ToString(), "Admin");

        using var context = JsonDocument.Parse(await admin.GetStringAsync("/api/v1/context"));
        Assert.Equal(new[] { "protocol" },
            context.RootElement.GetProperty("modules").EnumerateArray()
                .Select(x => x.GetString()).ToArray());

        using var legacy = JsonDocument.Parse(await admin.GetStringAsync("/api/v1/admin/modules"));
        Assert.Equal("protocol", Assert.Single(legacy.RootElement.EnumerateArray())
            .GetProperty("key").GetString());

        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.PutAsJsonAsync("/api/v1/admin/modules/archive",
                new { enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.PutAsJsonAsync("/api/v1/admin/modules/finance",
                new { enabled = true })).StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
        var rows = await db.OrganizationModules.IgnoreQueryFilters()
            .AsNoTracking().Where(x => x.OrganizationId == orgA || x.OrganizationId == orgB)
            .ToListAsync();
        Assert.True(rows.Single(x => x.OrganizationId == orgA && x.ModuleKey == "archive").Enabled);
        Assert.True(rows.Single(x => x.OrganizationId == orgA && x.ModuleKey == "protocol").Enabled);
        Assert.False(rows.Single(x => x.OrganizationId == orgB && x.ModuleKey == "protocol").Enabled);
        Assert.False(await db.AuditEvents.IgnoreQueryFilters()
            .AnyAsync(x => x.OrganizationId == orgA && x.Action.Contains(".archive.")));
    }
}
