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

    [Theory]
    [InlineData("actorSubject", " actor")]
    [InlineData("actorSubject", "actor ")]
    [InlineData("actorSubject", "ac\rtor")]
    [InlineData("actorSubject", "ac\0tor")]
    [InlineData("action", " protocol.record.created")]
    [InlineData("action", "protocol.record.created ")]
    [InlineData("action", "protocol.\nrecord.created")]
    [InlineData("resourceType", " protocol.record")]
    [InlineData("resourceType", "protocol.record ")]
    [InlineData("resourceType", "protocol.\trecord")]
    [InlineData("correlationId", " corr")]
    [InlineData("correlationId", "corr ")]
    [InlineData("correlationId", "corr\nforged")]
    [InlineData("correlationId", "corr\0forged")]
    public void Rejects_noncanonical_or_controlled_audit_values(
        string field, string input)
    {
        var failure = Assert.Throws<ArgumentException>(() =>
            CreateWithField(field, input));
        Assert.Equal(field, failure.ParamName);
    }

    [Theory]
    [InlineData("actorSubject", 161)]
    [InlineData("action", 121)]
    [InlineData("resourceType", 101)]
    [InlineData("correlationId", 129)]
    public void Rejects_overlong_metadata(string field, int size)
    {
        var failure = Assert.Throws<ArgumentException>(() =>
            CreateWithField(field, new string('x', size)));
        Assert.Equal(field, failure.ParamName);
    }

    [Theory]
    [InlineData("actorSubject")]
    [InlineData("action")]
    [InlineData("resourceType")]
    [InlineData("correlationId")]
    public void Rejects_missing_or_whitespace_only_metadata(string field)
    {
        foreach (var input in new string?[] { null, "", "   " })
        {
            var failure = Assert.Throws<ArgumentException>(() =>
                CreateWithField(field, input));
            Assert.Equal(field, failure.ParamName);
        }
    }

    private static AuditEvent CreateWithField(string field, string? input) =>
        AuditEvent.Create(Guid.NewGuid(),
            field == "actorSubject" ? input! : "oidc-subject",
            field == "action" ? input! : "protocol.record.created",
            field == "resourceType" ? input! : "protocol.record",
            Guid.NewGuid(),
            field == "correlationId" ? input! : "server-correlation");

    [Fact]
    public void Valid_unicode_and_case_sensitive_metadata_is_preserved_exactly()
    {
        const string actor = "issuer|Älice/CaseSensitive";
        const string correlation = "trace:Σ-42";
        var audit = AuditEvent.Create(Guid.NewGuid(), actor,
            "platform.module.protocol.enabled", "platform.module",
            Guid.NewGuid(), correlation);
        Assert.Equal(actor, audit.ActorSubject);
        Assert.Equal(correlation, audit.CorrelationId);
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
