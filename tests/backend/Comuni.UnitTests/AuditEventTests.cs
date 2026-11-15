using Comuni.Domains.Audit;
using Xunit;

namespace Comuni.UnitTests;

public sealed class AuditEventTests
{
    [Fact]
    public void Valid_event_has_owned_context_and_resource()
    {
        var organization = Guid.NewGuid();
        var resource = Guid.NewGuid();
        var item = AuditEvent.Create(organization, "user-1", "protocol.record.created",
            "protocol.record", resource, "correlation-1");

        Assert.NotEqual(Guid.Empty, item.Id);
        Assert.Equal(organization, item.OrganizationId);
        Assert.Equal("user-1", item.ActorSubject);
        Assert.Equal("protocol.record.created", item.Action);
        Assert.Equal("protocol.record", item.ResourceType);
        Assert.Equal(resource, item.ResourceId);
        Assert.Equal("correlation-1", item.CorrelationId);
        Assert.InRange(item.OccurredAt, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    [Fact]
    public void Cannot_create_audit_without_organization()
    {
        Assert.Throws<ArgumentException>(() => AuditEvent.Create(Guid.Empty, "u", "protocol.record.created",
            "protocol.record", Guid.NewGuid(), "corr"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Cannot_create_audit_without_actor(string actor)
    {
        Assert.Throws<ArgumentException>(() => AuditEvent.Create(Guid.NewGuid(), actor, "protocol.record.created",
            "protocol.record", Guid.NewGuid(), "corr"));
    }

    [Fact]
    public void Cannot_create_audit_without_correlation_or_resource()
    {
        Assert.Throws<ArgumentException>(() => AuditEvent.Create(Guid.NewGuid(), "actor", "protocol.record.created",
            "protocol.record", Guid.Empty, "corr"));
        Assert.Throws<ArgumentException>(() => AuditEvent.Create(Guid.NewGuid(), "actor", "protocol.record.created",
            "protocol.record", Guid.NewGuid(), ""));
    }
}
