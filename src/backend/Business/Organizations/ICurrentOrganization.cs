namespace Comuni.Business.Organizations;

/// <summary>
/// Identity is determined exclusively from a validated authentication principal.
/// Never accept it from client-supplied headers, route parameters or request bodies.
/// </summary>
public interface ICurrentOrganization
{
    Guid OrganizationId { get; }
}
