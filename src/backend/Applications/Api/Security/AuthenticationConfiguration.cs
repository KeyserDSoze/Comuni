using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Comuni.Api.Security;

/// <summary>
/// Two strictly separated trust modes. Only an OIDC issuer may authenticate production requests.
/// JWT roles are never authoritative; they are looked up in the organization's PostgreSQL memberships.
/// </summary>
public sealed class AuthenticationConfiguration
{
    private AuthenticationConfiguration(
        string mode, string issuer, string audience, string? signingKey)
    {
        Mode = mode;
        Issuer = issuer;
        Audience = audience;
        SigningKey = signingKey;
    }

    public string Mode { get; }
    public string Issuer { get; }
    public string Audience { get; }
    private string? SigningKey { get; }

    public static AuthenticationConfiguration Read(IConfiguration configuration, string environment)
    {
        var isTestOrDevelopment =
            string.Equals(environment, "Development", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(environment, "Testing", StringComparison.OrdinalIgnoreCase);

        var mode = configuration["Authentication:Mode"];
        mode = string.IsNullOrWhiteSpace(mode)
            ? isTestOrDevelopment ? "DevelopmentJwt" : "Oidc"
            : mode;

        if (string.Equals(mode, "DevelopmentJwt", StringComparison.Ordinal))
        {
            if (!isTestOrDevelopment)
                throw new InvalidOperationException("DevelopmentJwt authentication is forbidden outside Development and Testing.");

            var secret = configuration["Jwt:SigningKey"];
            if (string.IsNullOrEmpty(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
                throw new InvalidOperationException("Jwt:SigningKey must contain at least 32 bytes in demo mode.");
            var issuer = Required(configuration["Jwt:Issuer"], "Jwt:Issuer");
            var audience = Required(configuration["Jwt:Audience"], "Jwt:Audience");
            return new AuthenticationConfiguration("DevelopmentJwt", issuer, audience, secret);
        }

        if (!string.Equals(mode, "Oidc", StringComparison.Ordinal))
            throw new InvalidOperationException("Authentication:Mode must be Oidc or DevelopmentJwt.");

        // Never silently fall back to HS256 or accidentally carry a development shared secret into production.
        if (!isTestOrDevelopment && !string.IsNullOrEmpty(configuration["Jwt:SigningKey"]))
            throw new InvalidOperationException("Jwt:SigningKey must not be configured with production OIDC.");

        var authority = Required(configuration["Authentication:Authority"], "Authentication:Authority");
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var url) ||
            url.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(url.UserInfo) ||
            !string.IsNullOrEmpty(url.Query) ||
            !string.IsNullOrEmpty(url.Fragment))
            throw new InvalidOperationException("Authentication:Authority must be an absolute HTTPS issuer URL.");

        var targetAudience = Required(configuration["Authentication:Audience"], "Authentication:Audience");
        return new AuthenticationConfiguration("Oidc", authority, targetAudience, null);
    }

    public void Apply(JwtBearerOptions options)
    {
        options.MapInboundClaims = false;
        options.SaveToken = false;
        // JwtBearer has already checked signature, issuer, audience and
        // lifetime when this callback fires. Some identity token parsers
        // collapse duplicate JSON property names before claims are created.
        // Reject the original validated payload, not the already collapsed
        // ClaimsPrincipal, without logging tokens or identity data.
        options.Events.OnTokenValidated = context =>
        {
            if (!JwtPayloadDuplicatePropertyGuard.IsAcceptable(context.SecurityToken))
                context.Fail("JWT payload structure is invalid.");
            return Task.CompletedTask;
        };
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidAlgorithms = Mode == "Oidc"
                ? [SecurityAlgorithms.RsaSha256]
                : [SecurityAlgorithms.HmacSha256],
            NameClaimType = "sub",
            RoleClaimType = "role",
            ClockSkew = TimeSpan.FromMinutes(1)
        };

        if (Mode == "Oidc")
        {
            options.Authority = Issuer;
            options.Audience = Audience;
            options.RequireHttpsMetadata = true;
            options.RefreshOnIssuerKeyNotFound = true;
        }
        else
        {
            options.TokenValidationParameters.ValidIssuer = Issuer;
            options.TokenValidationParameters.ValidAudience = Audience;
            options.TokenValidationParameters.IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKey!));
        }
    }

    private static string Required(string? value, string name) =>
        string.IsNullOrWhiteSpace(value)
            ? throw new InvalidOperationException($"{name} must be configured.")
            : value.Trim();
}
