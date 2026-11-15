namespace Comuni.Domains.Protocol;

/// <summary>
/// Metadata record for the initial vertical slice. Not an AgID-compliant protocol registration.
/// </summary>
public sealed class ProtocolRecord
{
    private ProtocolRecord() { } // Entity Framework Core

    private ProtocolRecord(Guid id, Guid organizationId, string subject, DateTimeOffset registeredAt)
    {
        Id = id;
        OrganizationId = organizationId;
        Subject = subject;
        RegisteredAt = registeredAt;
    }

    public Guid Id { get; private set; }
    public Guid OrganizationId { get; private set; }
    public string Subject { get; private set; } = string.Empty;
    public DateTimeOffset RegisteredAt { get; private set; }

    public static ProtocolRecord Register(Guid organizationId, string subject)
    {
        if (organizationId == Guid.Empty) throw new ArgumentException("Organization ID is required.", nameof(organizationId));
        if (string.IsNullOrWhiteSpace(subject)) throw new ArgumentException("Subject cannot be blank.", nameof(subject));
        var normalized = subject.Trim();
        if (normalized.Length > 250) throw new ArgumentException("Subject exceeds 250 characters.", nameof(subject));
        return new ProtocolRecord(Guid.NewGuid(), organizationId, normalized, DateTimeOffset.UtcNow);
    }
}
