namespace Comuni.Business.Organizations;

/// <summary>
/// In OIDC mode every membership must be explicitly bound to the validated
/// issuer URL. Unbound legacy rows are accepted only by the DevelopmentJwt
/// test/demo mode; no fallback to these rows is allowed for production OIDC.
/// </summary>
public sealed class MembershipIssuerPolicy(bool requiresOidcBinding)
{
    public bool RequiresOidcBinding { get; } = requiresOidcBinding;

    public static bool IsTrustedFormat(string? issuer) =>
        issuer is { Length: > 0 and <= 512 } &&
        Uri.TryCreate(issuer, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Query) &&
        string.IsNullOrEmpty(uri.Fragment);
}
