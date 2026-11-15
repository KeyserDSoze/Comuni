using Microsoft.AspNetCore.Authorization;

namespace Comuni.Api.Security;

/// <summary>
/// A validated JWT identifies the caller; active roles are authorized from PostgreSQL.
/// A forged role claim cannot grant privileges.
/// </summary>
public sealed class OrganizationRoleRequirement(params string[] allowedRoles) : IAuthorizationRequirement
{
    public IReadOnlyList<string> AllowedRoles { get; } = allowedRoles;
}
