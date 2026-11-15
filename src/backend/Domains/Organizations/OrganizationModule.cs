namespace Comuni.Domains.Organizations;

public sealed class OrganizationModule
{
    private OrganizationModule() { } // Entity Framework Core

    public OrganizationModule(Guid organizationId, string moduleKey, bool enabled)
    {
        if (organizationId == Guid.Empty) throw new ArgumentException("Organization ID is required.", nameof(organizationId));
        if (string.IsNullOrWhiteSpace(moduleKey)) throw new ArgumentException("Module key is required.", nameof(moduleKey));
        OrganizationId = organizationId;
        ModuleKey = moduleKey;
        Enabled = enabled;
    }

    public Guid OrganizationId { get; private set; }
    public string ModuleKey { get; private set; } = string.Empty;
    public bool Enabled { get; private set; }

    public void SetEnabled(bool enabled) => Enabled = enabled;
}
