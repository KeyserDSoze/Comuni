namespace Comuni.Business.Platform;

/// <summary>
/// Read-only platform operator authentication. A municipal organization
/// membership can never imply this capability.
/// </summary>
public interface IPlatformOperatorStore
{
    Task<bool> IsActiveAsync(string validatedIssuer, string subject, CancellationToken cancellationToken);
}
