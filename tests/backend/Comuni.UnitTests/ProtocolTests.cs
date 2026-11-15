using Comuni.Business.Protocol;
using Comuni.Domains.Protocol;
using Xunit;

namespace Comuni.UnitTests;

public sealed class ProtocolTests
{
    [Fact]
    public void Registration_requires_an_organization()
    {
        Assert.Throws<ArgumentException>(() => ProtocolRecord.Register(Guid.Empty, "Istanza"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Registration_rejects_blank_subject(string subject)
    {
        Assert.Throws<ArgumentException>(() => ProtocolRecord.Register(Guid.NewGuid(), subject));
    }

    [Fact]
    public void Registration_preserves_the_organization_and_normalizes_subject()
    {
        var organization = Guid.NewGuid();
        var record = ProtocolRecord.Register(organization, "  Richiesta certificato  ");

        Assert.Equal(organization, record.OrganizationId);
        Assert.Equal("Richiesta certificato", record.Subject);
        Assert.NotEqual(Guid.Empty, record.Id);
    }

    [Fact]
    public async Task Use_case_denies_disabled_module_before_writing()
    {
        var repo = new FakeRepository();
        var service = new ProtocolService(repo, new FakeModules(false));

        await Assert.ThrowsAsync<ModuleDisabledException>(
            () => service.RegisterAsync(Guid.NewGuid(), "Istanza", CancellationToken.None));

        Assert.Empty(repo.Saved);
    }

    [Fact]
    public async Task Use_case_scopes_every_read_to_the_given_organization()
    {
        var repo = new FakeRepository();
        var service = new ProtocolService(repo, new FakeModules(true));
        var organization = Guid.NewGuid();

        await service.ListAsync(organization, CancellationToken.None);

        Assert.Equal(organization, repo.LastQueriedOrganization);
    }

    private sealed class FakeRepository : IProtocolRepository
    {
        public List<ProtocolRecord> Saved { get; } = [];
        public Guid LastQueriedOrganization { get; private set; }

        public Task<IReadOnlyList<ProtocolRecord>> ListAsync(Guid organizationId, CancellationToken ct)
        {
            LastQueriedOrganization = organizationId;
            return Task.FromResult<IReadOnlyList<ProtocolRecord>>([]);
        }

        public Task AddAsync(ProtocolRecord record, CancellationToken ct)
        {
            Saved.Add(record);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeModules(bool enabled) : IOrganizationModuleStore
    {
        public Task<bool> IsEnabledAsync(Guid organizationId, string moduleKey, CancellationToken ct)
        {
            Assert.Equal("protocol", moduleKey);
            return Task.FromResult(enabled);
        }
    }
}
