using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Comuni.Infrastructures.Persistence;

/// <summary>
/// Short-lived tenant assertions signed in the trusted API process, verified by PostgreSQL.
/// An optional authenticated key-id selects a staged version. Omitted key-id uses the
/// legacy format only while the owner permits that version in PostgreSQL.
/// </summary>
public sealed class TenantProofSigner
{
    private readonly byte[] _key;
    private readonly string? _keyId;

    public TenantProofSigner(string key, string? keyId = null)
    {
        if (string.IsNullOrWhiteSpace(key) || Encoding.UTF8.GetByteCount(key) < 32)
            throw new InvalidOperationException("Security:TenantProofKey requires at least 32 UTF-8 bytes.");

        if (!string.IsNullOrEmpty(keyId) &&
            (keyId.Length > 32 || !Regex.IsMatch(keyId, @"\A[a-z][a-z0-9_-]{0,31}\z")))
            throw new ArgumentException("Key ID must be 1-32 lowercase ASCII letters, digits, hyphens or underscores, starting with a letter.", nameof(keyId));

        _key = Encoding.UTF8.GetBytes(key);
        _keyId = string.IsNullOrEmpty(keyId) ? null : keyId;
    }

    public string Create(Guid organizationId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("A verified organization is required.", nameof(organizationId));

        var expires = DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds();
        var payload = $"{organizationId:N}|{expires}|{Guid.NewGuid():N}";
        // The key ID is covered by the MAC: an injected SQL statement cannot relabel
        // an assertion for a different version, even when versions overlap.
        var message = _keyId is null ? payload : $"{_keyId}|{payload}";
        var digest = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(message));
        return $"{message}|{Convert.ToHexStringLower(digest)}";
    }
}
