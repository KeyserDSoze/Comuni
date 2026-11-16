using Microsoft.Extensions.Configuration;

namespace Comuni.Api.Security;

/// <summary>
/// Isolated startup connection configuration seam. TDD red phase retains
/// the previous unvalidated connection-string behavior intentionally.
/// </summary>
public static class RuntimePostgresConnectionSettings
{
    public static string Read(IConfiguration configuration, string environmentName) =>
        configuration.GetConnectionString("Default")
        ?? throw new InvalidOperationException("ConnectionStrings:Default is required.");
}
