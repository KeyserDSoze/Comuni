namespace Comuni.Domains.Audit;

/// <summary>
/// Minimal, append-only cross-domain event metadata. No request body, document subject or JWT.
/// PostgreSQL mutation triggers provide a guard, not protection against database superusers.
/// </summary>
public sealed class AuditEvent
{
    private AuditEvent() { } // EF Core materialization

    private AuditEvent(Guid organizationId, string actorSubject, string action,
        string resourceType, Guid resourceId, string correlationId)
    {
        Id = Guid.NewGuid();
        OrganizationId = organizationId;
        ActorSubject = actorSubject;
        Action = action;
        ResourceType = resourceType;
        ResourceId = resourceId;
        CorrelationId = correlationId;
        OccurredAt = DateTimeOffset.UtcNow;
    }

    public Guid Id { get; private set; }
    public Guid OrganizationId { get; private set; }
    public string ActorSubject { get; private set; } = string.Empty;
    public string Action { get; private set; } = string.Empty;
    public string ResourceType { get; private set; } = string.Empty;
    public Guid ResourceId { get; private set; }
    public string CorrelationId { get; private set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; private set; }

    public static AuditEvent Create(Guid organizationId, string actorSubject, string action,
        string resourceType, Guid resourceId, string correlationId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization ID is required.", nameof(organizationId));
        if (resourceId == Guid.Empty)
            throw new ArgumentException("Resource ID is required.", nameof(resourceId));
        return new AuditEvent(organizationId,
            Required(actorSubject, 160, nameof(actorSubject)),
            Required(action, 120, nameof(action)),
            Required(resourceType, 100, nameof(resourceType)),
            resourceId,
            Required(correlationId, 128, nameof(correlationId)));
    }

    private static string Required(string value, int maxLength, string argumentName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > maxLength)
            throw new ArgumentException($"Value must have 1-{maxLength} characters.", argumentName);
        return value.Trim();
    }
}
