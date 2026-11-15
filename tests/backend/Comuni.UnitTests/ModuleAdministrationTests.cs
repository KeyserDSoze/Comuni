using Comuni.Business.Audit;
using Comuni.Business.Organizations;
using Comuni.Domains.Audit;
using Xunit;

namespace Comuni.UnitTests;

public sealed class ModuleAdministrationTests
{
    [Fact]
    public async Task Unknown_module_is_not_persisted_or_audited()
    {
        var store = new FakeStore();
        var service = new ModuleAdministrationService(store, new FakeActor());
        var result = await service.SetEnabledAsync(Guid.NewGuid(), "not-installed", false, CancellationToken.None);
        Assert.Equal(ModuleUpdateStatus.NotFound, result);
        Assert.Equal(0, store.WriteCount);
    }

    [Fact]
    public async Task Disabling_protocol_generates_minimal_tenant_scoped_audit()
    {
        var store = new FakeStore();
        var service = new ModuleAdministrationService(store, new FakeActor());
        var org = Guid.NewGuid();
        var result = await service.SetEnabledAsync(org, "protocol", false, CancellationToken.None);
        Assert.Equal(ModuleUpdateStatus.Updated, result);
        var audit = Assert.IsType<AuditEvent>(store.LastAudit);
        Assert.Equal(org, audit.OrganizationId);
        Assert.Equal(org, audit.ResourceId);
        Assert.Equal("platform.module.protocol.disabled", audit.Action);
        Assert.Equal("platform.module", audit.ResourceType);
        Assert.Equal("unit-admin", audit.ActorSubject);
        Assert.Equal("unit-trace", audit.CorrelationId);
    }

    [Fact]
    public async Task No_op_returns_unchanged_and_does_not_generate_audit()
    {
        var store = new FakeStore { Status = ModuleUpdateStatus.Unchanged };
        var service = new ModuleAdministrationService(store, new FakeActor());
        var result = await service.SetEnabledAsync(Guid.NewGuid(), "protocol", true, CancellationToken.None);
        Assert.Equal(ModuleUpdateStatus.Unchanged, result);
        Assert.Null(store.PersistedAudit);
    }

    [Fact]
    public async Task Missing_tenant_fails_closed()
    {
        var service = new ModuleAdministrationService(new FakeStore(), new FakeActor());
        await Assert.ThrowsAsync<ArgumentException>(
            () => service.SetEnabledAsync(Guid.Empty, "protocol", true, CancellationToken.None));
    }

    private sealed class FakeActor : ICurrentActorContext
    {
        public string ActorSubject => "unit-admin";
        public string CorrelationId => "unit-trace";
    }

    private sealed class FakeStore : IModuleAdministrationStore
    {
        public ModuleUpdateStatus Status { get; set; } = ModuleUpdateStatus.Updated;
        public int WriteCount { get; private set; }
        public AuditEvent? LastAudit { get; private set; }
        public AuditEvent? PersistedAudit { get; private set; }

        public Task<IReadOnlyList<ModuleState>> ListAsync(Guid organizationId, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<ModuleState>>([new ModuleState("protocol", true)]);

        public Task<ModuleUpdateStatus> SetEnabledAsync(Guid organizationId, string key,
            bool enabled, AuditEvent audit, CancellationToken ct)
        {
            WriteCount++;
            LastAudit = audit;
            if (Status == ModuleUpdateStatus.Updated) PersistedAudit = audit;
            return Task.FromResult(Status);
        }
    }
}
