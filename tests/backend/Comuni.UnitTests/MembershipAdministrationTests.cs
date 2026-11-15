using Comuni.Business.Audit;
using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Xunit;

namespace Comuni.UnitTests;

public sealed class MembershipAdministrationTests
{
    private sealed class Actor : ICurrentActorContext
    {
        public string ActorSubject => "verified-admin";
        public string CorrelationId => "trusted-request-trace";
    }

    private sealed class Store : IMembershipAdministrationStore
    {
        public AuditEvent? Audit { get; private set; }
        public int Changes { get; private set; }
        public Task<IReadOnlyList<MembershipState>> ListAsync(Guid tenant, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<MembershipState>>([]);
        public Task<MembershipUpdateStatus> SetActiveAsync(Guid tenant, string subject, string role,
            bool active, AuditEvent audit, CancellationToken ct)
        {
            Changes++;
            Audit = audit;
            return Task.FromResult(MembershipUpdateStatus.Updated);
        }
    }

    [Fact]
    public async Task Only_operational_roles_are_manageable_not_Admin()
    {
        var store = new Store();
        var service = new MembershipAdministrationService(store, new Actor());
        var org = Guid.NewGuid();
        foreach (var role in new[] { "Admin", "Superadmin", "reader", " " })
            await Assert.ThrowsAsync<ArgumentException>(() =>
                service.SetActiveAsync(org, "subject", role, true, CancellationToken.None));
        Assert.Equal(0, store.Changes);
    }

    [Fact]
    public async Task Actor_origin_action_and_tenant_specific_resource_are_server_owned()
    {
        var org = Guid.NewGuid();
        var store = new Store();
        var service = new MembershipAdministrationService(store, new Actor());
        Assert.Equal(MembershipUpdateStatus.Updated,
            await service.SetActiveAsync(org, "idp-subject", "Reader", true, CancellationToken.None));
        var audit = Assert.IsType<AuditEvent>(store.Audit);
        Assert.Equal(org, audit.OrganizationId);
        Assert.Equal("verified-admin", audit.ActorSubject);
        Assert.Equal("trusted-request-trace", audit.CorrelationId);
        Assert.Equal("platform.membership.reader.activated", audit.Action);
        Assert.Equal("platform.membership", audit.ResourceType);
        Assert.NotEqual(org, audit.ResourceId);
    }

    [Fact]
    public async Task Invalid_subject_or_empty_tenant_is_denied_without_store_calls()
    {
        var store = new Store();
        var service = new MembershipAdministrationService(store, new Actor());
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.SetActiveAsync(Guid.Empty, "subject", "Reader", true, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.SetActiveAsync(Guid.NewGuid(), "  ", "Reader", true, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.SetActiveAsync(Guid.NewGuid(), "contains\nnewline", "Officer", true, CancellationToken.None));
        Assert.Equal(0, store.Changes);
    }
}
