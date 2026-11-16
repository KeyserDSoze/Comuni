using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Comuni.Api.Security;

/// <summary>
/// JWT processors may collapse duplicate JSON names before creating claims.
/// Check the exact JOSE header AND payload bytes of the cryptographically
/// validated SecurityToken, BEFORE accepting a municipal/platform principal.
/// </summary>
public static class JwtPayloadDuplicatePropertyGuard
{
    // Bounded independent of JwtBearer MaximumTokenSizeInBytes. A large or
    // deeply nested external IdP payload must fail closed, not exhaust memory.
    private const int MaxHeaderBytes = 8 * 1024;
    private const int MaxPayloadBytes = 64 * 1024;
    private const int MaxDepth = 32;
    private const int MaxEncodedHeaderChars = ((MaxHeaderBytes + 2) / 3) * 4;
    private const int MaxEncodedPayloadChars = ((MaxPayloadBytes + 2) / 3) * 4;

    public static bool IsAcceptable(SecurityToken? validatedToken)
    {
        var compact = validatedToken switch
        {
            JsonWebToken jwt => jwt.EncodedToken,
            JwtSecurityToken jwt => jwt.RawData,
            _ => null
        };
        if (string.IsNullOrEmpty(compact))
            return false;

        var firstDot = compact.IndexOf('.');
        var secondDot = firstDot < 0 ? -1 : compact.IndexOf('.', firstDot + 1);
        if (firstDot <= 0 || secondDot <= firstDot + 1 ||
            compact.IndexOf('.', secondDot + 1) != -1)
            return false;

        // Bound both JOSE header and payload before Base64Url decoding.
        // The JOSE header can carry a duplicated alg/kid that the JWT parser
        // already collapsed before signature verification. Even after a
        // successful signature check, reject its original JSON ambiguity.
        var headerLength = firstDot;
        var payloadLength = secondDot - firstDot - 1;
        if (headerLength > MaxEncodedHeaderChars ||
            payloadLength > MaxEncodedPayloadChars)
            return false;

        try
        {
            // Only the SecurityToken returned by JwtBearer AFTER its signature
            // and issuer/audience/lifetime checks. Never a raw request header.
            return IsCanonicalObject(compact[..firstDot], MaxHeaderBytes) &&
                   IsCanonicalObject(
                       compact.Substring(firstDot + 1, payloadLength),
                       MaxPayloadBytes);
        }
        catch (Exception error) when (
            error is ArgumentException or FormatException or JsonException or InvalidOperationException)
        {
            // No token, key, issuer, subject, hostname or raw exception text in
            // the auth rejection path.
            return false;
        }
    }

    private static bool IsCanonicalObject(string encoded, int maxDecodedBytes)
    {
        var bytes = Base64UrlEncoder.DecodeBytes(encoded);
        if (bytes.Length > maxDecodedBytes)
            return false;

        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = MaxDepth
        });
        return document.RootElement.ValueKind == JsonValueKind.Object &&
               HasUniqueObjectPropertyNames(document.RootElement);
    }

    private static bool HasUniqueObjectPropertyNames(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
            return element.EnumerateArray().All(HasUniqueObjectPropertyNames);

        if (element.ValueKind != JsonValueKind.Object)
            return true;

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            // EnumerateObject exposes duplicates even when JWT claim
            // materialization used last-value-wins semantics.
            if (!names.Add(property.Name) ||
                !HasUniqueObjectPropertyNames(property.Value))
                return false;
        }
        return true;
    }
}
