using Comuni.Infrastructures.Persistence;
using Microsoft.Extensions.Configuration;

namespace Comuni.Api.Security;

/// <summary>
/// Central signing configuration seam; production version pinning is the
/// RED-first contract in TenantProofSigningSettingsTests.
/// </summary>
public static class TenantProofSigningSettings
{
    public static TenantProofSigner Read(IConfiguration config, string environmentName) =>
        new(config["Security:TenantProofKey"] ?? string.Empty,
            config["Security:TenantProofKeyId"]);
}
