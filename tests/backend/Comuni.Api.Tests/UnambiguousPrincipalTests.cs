using System.Net;
using System.Security.Claims;
using Comuni.Api.Security;
using Comuni.Business.Organizations;
using Comuni.Business.Platform;
using Comuni.Domains.Organizations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// RED: a signed principal is not a unique municipal/platform identity when
/// it carries duplicate issuer, subject, or organization claims. Synthetic only.
/// </summary>
public sealed class UnambiguousPrincipalTests
{
    private static readonly string TenantA = ApiFactory.OrgA;
    private const string Issuer = "https://identity.example.test/tenant/v2.0";

    private static ClaimsPrincipal Principal(params Claim[] extra) =>
        new(new ClaimsIdentity(
            [
                new Claim("organization_id", TenantA),
                new Claim("sub", "test-admin"),
                new Claim("iss", Issuer),
                .. extra
            ], "ValidatedTestJwt"));

    private static ClaimsPrincipal PlatformPrincipal(params Claim[] extra) =>
        new(new ClaimsIdentity(
            [
                new Claim("sub", "platform-operator"),
                new Claim("iss", Issuer),
                .. extra
            ], "ValidatedTestOidc"));

    private static DefaultHttpContext Http(ClaimsPrincipal principal)
    {
        var context = new DefaultHttpContext { User = principal };
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        return context;
    }

    [Theory]
    [InlineData("organization_id", ApiFactory.OrgA)]
    [InlineData("organization_id", ApiFactory.OrgB)]
    [InlineData("sub", "test-admin")]
    [InlineData("sub", "another-subject")]
    [InlineData("iss", Issuer)]
    [InlineData("iss", "https://other.example.test/")]
    public async Task Duplicate_municipal_identity_denies_authorization_without_database_lookup(
        string duplicatedClaim, string duplicateValue)
    {
        var principal = Principal(new Claim(duplicatedClaim, duplicateValue));
        var request = Http(principal);
        var tenant = new HttpCurrentOrganization(new HttpContextAccessor { HttpContext = request });
        var actor = new HttpCurrentActorContext(new HttpContextAccessor { HttpContext = request });
        var memberships = new CountingMembershipStore();
        var organizations = new CountingDirectory();
        var requirement = new OrganizationRoleRequirement("Admin");
        var authorization = new AuthorizationHandlerContext([requirement], principal, null);

        await new OrganizationRoleHandler(memberships, organizations).HandleAsync(authorization);

        Assert.False(authorization.HasSucceeded);
        Assert.Equal(0, organizations.Calls);
        Assert.Equal(0, memberships.Calls);
        Assert.Equal(Guid.Empty, tenant.OrganizationId);
        Assert.Equal(string.Empty, actor.ActorSubject);
        Assert.Null(actor.IdentityIssuer);
        Assert.StartsWith("ip:", ApiProtectionSettings.PartitionKey(request));
    }

    [Fact]
    public async Task Unique_municipal_identity_remains_authorized_and_partitioned_by_tenant()
    {
        var principal = Principal();
        var request = Http(principal);
        var tenant = new HttpCurrentOrganization(new HttpContextAccessor { HttpContext = request });
        var actor = new HttpCurrentActorContext(new HttpContextAccessor { HttpContext = request });
        var memberships = new CountingMembershipStore();
        var directory = new CountingDirectory();
        var requirement = new OrganizationRoleRequirement("Admin");
        var authorization = new AuthorizationHandlerContext([requirement], principal, null);

        await new OrganizationRoleHandler(memberships, directory).HandleAsync(authorization);

        Assert.True(authorization.HasSucceeded);
        Assert.Equal(1, directory.Calls);
        Assert.Equal(1, memberships.Calls);
        Assert.Equal(Guid.Parse(TenantA), tenant.OrganizationId);
        Assert.Equal("test-admin", actor.ActorSubject);
        Assert.Equal(Issuer, actor.IdentityIssuer);
        Assert.StartsWith("tenant:", ApiProtectionSettings.PartitionKey(request));
    }

    [Theory]
    [InlineData("sub", "platform-operator")]
    [InlineData("sub", "another-operator")]
    [InlineData("iss", Issuer)]
    [InlineData("iss", "https://other.example.test/")]
    public async Task Duplicate_platform_identity_denies_operator_without_database_lookup(
        string duplicatedClaim, string duplicateValue)
    {
        var principal = PlatformPrincipal(new Claim(duplicatedClaim, duplicateValue));
        var store = new CountingPlatformStore();
        var requirement = new PlatformOperatorRequirement();
        var authorization = new AuthorizationHandlerContext([requirement], principal, null);

        await new PlatformOperatorHandler(store, new MembershipIssuerPolicy(true))
            .HandleAsync(authorization);

        Assert.False(authorization.HasSucceeded);
        Assert.Equal(0, store.Calls);
    }

    [Fact]
    public async Task Unique_platform_identity_still_works_but_tenant_platform_mixing_never_does()
    {
        var store = new CountingPlatformStore();
        var requirement = new PlatformOperatorRequirement();
        var valid = new AuthorizationHandlerContext([requirement], PlatformPrincipal(), null);
        await new PlatformOperatorHandler(store, new MembershipIssuerPolicy(true)).HandleAsync(valid);
        Assert.True(valid.HasSucceeded);
        Assert.Equal(1, store.Calls);

        var mixed = new AuthorizationHandlerContext(
            [requirement], PlatformPrincipal(new Claim("organization_id", TenantA)), null);
        await new PlatformOperatorHandler(store, new MembershipIssuerPolicy(true)).HandleAsync(mixed);
        Assert.False(mixed.HasSucceeded);
        Assert.Equal(1, store.Calls);
    }

    private sealed class CountingMembershipStore : IOrganizationMembershipStore
    {
        public int Calls { get; private set; }
        public Task<IReadOnlyList<string>> ActiveRolesAsync(Guid organizationId,
            string subject, string? issuer, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<IReadOnlyList<string>>(["Admin"]);
        }
    }

    private sealed class CountingDirectory : IOrganizationDirectory
    {
        public int Calls { get; private set; }
        public Task<bool> IsOperationalAsync(Guid organizationId, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(true);
        }
        public Task<Organization?> FindAsync(Guid id, CancellationToken ct) =>
            Task.FromResult<Organization?>(null);
        public Task<IReadOnlyList<string>> EnabledModulesAsync(Guid id, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<string>>([]);
    }

    private sealed class CountingPlatformStore : IPlatformOperatorStore
    {
        public int Calls { get; private set; }
        public Task<bool> IsActiveAsync(string issuer, string subject, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(true);
        }
    }
}
