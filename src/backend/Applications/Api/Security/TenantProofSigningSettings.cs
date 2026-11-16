using Comuni.Infrastructures.Persistence;
using Microsoft.Extensions.Configuration;

namespace Comuni.Api.Security;

/// <summary>
/// Select the signer before any request or DB access. The SQL verifier may
/// still accept older legacy assertions during an approved rotation grace.
/// </summary>
public static class TenantProofSigningSettings
{
    public static TenantProofSigner Read(IConfiguration config, string environmentName)
    {
        var keyId = config["Security:TenantProofKeyId"];

        // Production, Staging, and all other hosted environments fail closed.
        // Only Development and Testing can issue unversioned demo assertions.
        if (environmentName is not ("Development" or "Testing") &&
            (string.IsNullOrWhiteSpace(keyId) ||
             string.Equals(keyId, "legacy", StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                "Security:TenantProofKeyId must be an explicit non-legacy version in Production.");
        }

        // Existing signer enforces minimum key strength and an ASCII key-ID
        // allowlist. Never echo secret bytes in errors or logs.
        return new TenantProofSigner(
            config["Security:TenantProofKey"] ?? string.Empty, keyId);
    }
}
