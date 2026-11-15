namespace Comuni.Domains.Organizations;

public sealed class Organization
{
    private Organization() { } // Entity Framework Core

    public Organization(Guid id, string name)
    {
        if (id == Guid.Empty) throw new ArgumentException("Organization ID is required.", nameof(id));
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Organization name is required.", nameof(name));
        Id = id;
        Name = name.Trim();
    }

    public Guid Id { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public bool IsSuspended { get; private set; }

    public void Suspend() => IsSuspended = true;
    public void Reactivate() => IsSuspended = false;
}
