using Microsoft.Extensions.Configuration;

namespace Comuni.Api.Security;

/// <summary>
/// Public browser OAuth client metadata; NEVER contains client secrets, access tokens,
/// or tenant selection. Backend JWT authorization still controls all protected operations.
/// </summary>
public sealed class BrowserOidcSettings
{
    private BrowserOidcSettings(
        string mode, bool enabled, string? issuer = null, string? clientId = null,
        string? authorizationEndpoint = null, string? tokenEndpoint = null, string? scope = null)
    {
        Mode = mode;
        Enabled = enabled;
        Issuer = issuer;
        ClientId = clientId;
        AuthorizationEndpoint = authorizationEndpoint;
        TokenEndpoint = tokenEndpoint;
        Scope = scope;
    }

    public string Mode { get; }
    public bool Enabled { get; }
    public string? Issuer { get; }
    public string? ClientId { get; }
    public string? AuthorizationEndpoint { get; }
    public string? TokenEndpoint { get; }
    public string? Scope { get; }

    public static BrowserOidcSettings Read(IConfiguration config, string mode, string environment)
    {
        if (mode != "Oidc")
            return new BrowserOidcSettings("DevelopmentJwt", false);

        const string root = "Authentication:Browser";
        var clientId = config["Authentication:BrowserClientId"]?.Trim();
        var authUrl = config["Authentication:BrowserAuthorizationEndpoint"]?.Trim();
        var tokenUrl = config["Authentication:BrowserTokenEndpoint"]?.Trim();
        var scope = config["Authentication:BrowserScope"]?.Trim();
        var secret = config["Authentication:BrowserClientSecret"];

        if (!string.IsNullOrEmpty(secret))
            throw new InvalidOperationException("Browser OAuth must never use a client secret.");

        // The API might be deployed before an IdP is selected; the frontend then
        // DISABLES OIDC login and must never silently fall back to a pasted JWT.
        if (string.IsNullOrWhiteSpace(clientId) && string.IsNullOrWhiteSpace(authUrl)
            && string.IsNullOrWhiteSpace(tokenUrl) && string.IsNullOrWhiteSpace(scope))
            return new BrowserOidcSettings("Oidc", false);

        if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 256 ||
            clientId.Any(char.IsWhiteSpace) ||
            string.IsNullOrWhiteSpace(authUrl) || string.IsNullOrWhiteSpace(tokenUrl) ||
            string.IsNullOrWhiteSpace(scope))
            throw new InvalidOperationException("All public Browser OIDC settings must be provided together.");

        var issuer = config["Authentication:Authority"]?.Trim();
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var issuerUri) ||
            issuerUri.Scheme != Uri.UriSchemeHttps || !issuerUri.IsDefaultPort ||
            !string.IsNullOrEmpty(issuerUri.UserInfo))
            throw new InvalidOperationException("A trusted HTTPS OIDC authority is required.");

        string StrictEndpoint(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort ||
                !uri.Host.Equals(issuerUri.Host, StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
                throw new InvalidOperationException("Browser OIDC endpoints must be HTTPS on the trusted issuer host.");
            return uri.AbsoluteUri;
        }

        var authorize = StrictEndpoint(authUrl);
        var exchange = StrictEndpoint(tokenUrl);
        if (authorize == exchange)
            throw new InvalidOperationException("OAuth authorize/token endpoints must differ.");

        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!scopes.Contains("openid", StringComparer.Ordinal) ||
            scopes.Contains("offline_access", StringComparer.Ordinal) ||
            !scopes.Any(x => x is not ("openid" or "profile" or "email")) ||
            scopes.Any(x => x.Any(char.IsWhiteSpace) || x.Contains('"') || x.Contains('\\')))
            throw new InvalidOperationException("Browser OIDC needs openid and an API scope, without offline_access.");

        return new BrowserOidcSettings(
            "Oidc", true, issuerUri.AbsoluteUri, clientId, authorize, exchange,
            string.Join(' ', scopes));
    }
}
