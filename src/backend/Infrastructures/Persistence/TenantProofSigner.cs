using System.Security.Cryptography;
using System.Text;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Creates short-lived tenant assertions verified inside PostgreSQL with a secret not
/// readable by the SQL runtime role. Never expose signing key or assertions to HTTP clients.
/// </summary>
public sealed class TenantProofSigner
{
    private readonly byte[] _key;

    public TenantProofSigner(string key)
    {
        if (string.IsNullOrWhiteSpace(key) || Encoding.UTF8.GetByteCount(key) < 32)
            throw new InvalidOperationException("Security:TenantProofKey requires at least 32 UTF-8 bytes.");
        _key = Encoding.UTF8.GetBytes(key);
    }

    public string Create(Guid organizationId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("A verified organization is required.", nameof(organizationId));

        // The nonce prevents deterministic proofs; PostgreSQL checks the 3-minute expiry.
        var expires = DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds();
        var message = $"{organizationId:N}|{expires}|{Guid.NewGuid():N}";
        var digest = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(message));
        return $"{message}|{Convert.ToHexStringLower(digest)}";
    }
}
