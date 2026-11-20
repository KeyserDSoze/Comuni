using System.Security.Claims;
using System.Globalization;
using System.Threading.RateLimiting;
using Comuni.Api.Security;
using Comuni.Business.Audit;
using Comuni.Business.Organizations;
using Comuni.Business.Platform;
using Comuni.Business.Protocol;
using Comuni.Domains.Protocol;
using Comuni.Infrastructures.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var authentication = AuthenticationConfiguration.Read(
    builder.Configuration, builder.Environment.EnvironmentName);
var connection = RuntimePostgresConnectionSettings.Read(
    builder.Configuration, builder.Environment.EnvironmentName);
var protection = ApiProtectionSettings.Read(builder.Configuration);
var browserOidc = BrowserOidcSettings.Read(builder.Configuration, authentication.Mode, builder.Environment.EnvironmentName);
var platformInventory = PlatformInventorySettings.Read(
    builder.Configuration, authentication.Mode, connection, builder.Environment.EnvironmentName);
var tenantProofKey = builder.Configuration["Security:TenantProofKey"];
var tenantProofSigner = TenantProofSigningSettings.Read(builder.Configuration, builder.Environment.EnvironmentName);

builder.Services.AddSingleton(tenantProofSigner);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentOrganization, HttpCurrentOrganization>();
builder.Services.AddScoped<ICurrentActorContext, HttpCurrentActorContext>();
builder.Services.AddDbContext<ComuniDbContext>(options => options.UseNpgsql(connection));
builder.Services.AddScoped<OrganizationDirectory>();
builder.Services.AddScoped<IOrganizationDirectory>(s => s.GetRequiredService<OrganizationDirectory>());
builder.Services.AddScoped<IOrganizationModuleStore>(s => s.GetRequiredService<OrganizationDirectory>());
builder.Services.AddSingleton(new MembershipIssuerPolicy(authentication.Mode == "Oidc"));
builder.Services.AddScoped<IOrganizationMembershipStore, OrganizationMembershipStore>();
builder.Services.AddScoped<IPlatformOperatorStore, PlatformOperatorStore>();
if (platformInventory.Enabled)
    builder.Services.AddScoped<IPlatformInventoryStore>(
        _ => new PlatformInventoryStore(platformInventory.ConnectionString!));
builder.Services.AddScoped<IAuthorizationHandler, OrganizationRoleHandler>();
builder.Services.AddScoped<IAuthorizationHandler, PlatformOperatorHandler>();
builder.Services.AddScoped<IProtocolRepository, ProtocolRepository>();
builder.Services.AddScoped<ProtocolService>();
builder.Services.AddScoped<IModuleAdministrationStore, ModuleAdministrationRepository>();
builder.Services.AddScoped<ModuleAdministrationService>();
builder.Services.AddScoped<IMembershipAdministrationStore, MembershipAdministrationRepository>();
builder.Services.AddScoped<MembershipAdministrationService>();
builder.Services.AddScoped<IOrganizationAuditReader, OrganizationAuditReader>();
builder.Services.AddScoped<MunicipalAuditService>();
builder.Services.AddRateLimiter(options =>
{
    // In-memory partition per replica, not a distributed denial-of-service defence.
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        context => RateLimitPartition.GetFixedWindowLimiter(
            ApiProtectionSettings.PartitionKey(context),
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = protection.PermitLimit,
                Window = TimeSpan.FromSeconds(protection.WindowSeconds),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    options.OnRejected = (context, cancellationToken) =>
    {
        var retrySeconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var duration)
            ? Math.Max(1, (int)Math.Ceiling(duration.TotalSeconds))
            : protection.WindowSeconds;
        context.HttpContext.Response.Headers["Retry-After"] =
            retrySeconds.ToString(CultureInfo.InvariantCulture);
        return ValueTask.CompletedTask;
    };
});

builder.Services.AddOpenApi();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(authentication.Apply);

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Read", policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(new OrganizationRoleRequirement("Admin", "Officer", "Reader")));
    options.AddPolicy("Write", policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(new OrganizationRoleRequirement("Admin", "Officer")));
    options.AddPolicy("Admin", policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(new OrganizationRoleRequirement("Admin")));
    options.AddPolicy("PlatformOperator", policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(new PlatformOperatorRequirement()));
});

var app = builder.Build();

// Local demo only. In production migrations are applied explicitly during deployment.
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
    await db.Database.MigrateAsync();
    // Development-only owner migration bootstrap; production uses a private provisioning runner.
    await db.Database.ExecuteSqlInterpolatedAsync($"""
        INSERT INTO platform.tenant_proof_secret (id, signing_key)
        VALUES (1, {tenantProofKey})
        ON CONFLICT (id) DO UPDATE SET signing_key = EXCLUDED.signing_key;
        INSERT INTO platform.tenant_proof_keys (key_id, signing_key)
        VALUES ('legacy', {tenantProofKey})
        ON CONFLICT (key_id) DO UPDATE SET signing_key = EXCLUDED.signing_key,
            revoked_at = NULL, not_before = '-infinity', valid_until = 'infinity';
        """);

    await db.Database.ExecuteSqlRawAsync("""
        INSERT INTO platform.organizations (id, name) VALUES
          ('11111111-1111-1111-1111-111111111111', 'Comune Aurora'),
          ('22222222-2222-2222-2222-222222222222', 'Comune Borgo')
        ON CONFLICT (id) DO NOTHING;
        INSERT INTO platform.organization_modules (organization_id, module_key, enabled) VALUES
          ('11111111-1111-1111-1111-111111111111', 'protocol', TRUE),
          ('22222222-2222-2222-2222-222222222222', 'protocol', FALSE)
        ON CONFLICT (organization_id, module_key) DO NOTHING;
        INSERT INTO platform.organization_memberships (organization_id, subject, role, is_active) VALUES
          ('11111111-1111-1111-1111-111111111111', 'local-developer', 'Officer', TRUE),
          ('11111111-1111-1111-1111-111111111111', 'local-admin', 'Admin', TRUE),
          ('22222222-2222-2222-2222-222222222222', 'local-developer', 'Reader', TRUE)
        ON CONFLICT (organization_id, subject, role) DO NOTHING;
        """);
}

// Apply response headers before any middleware can short-circuit with 401/403/429.
app.Use(async (context, next) =>
{
    ApiProtectionSettings.ApplyResponseHeaders(context);
    await next(context);
});

app.UseAuthentication();
// Limit API requests only; operational health probes and static PWA assets are not throttled.
app.UseWhen(
    context => context.Request.Path.StartsWithSegments("/api"),
    branch => branch.UseRateLimiter());
// JWT authentication runs first. Each authorized tenant API request uses one
// PostgreSQL transaction with SET LOCAL context across policies and endpoints.
app.Use(async (context, next) =>
{
    if (!context.Request.Path.StartsWithSegments("/api") ||
        !VerifiedPrincipalIdentity.TryMunicipal(context.User, out _, out _, out _))
    {
        await next(context);
        return;
    }

    var db = context.RequestServices.GetRequiredService<ComuniDbContext>();
    var signer = context.RequestServices.GetRequiredService<TenantProofSigner>();
    await using var tenantTransaction = await TenantDatabaseTransaction.BeginAsync(
        db, signer, context.RequestAborted);
    await next(context);
    // Denied and invalid requests must not commit even if a future handler writes before failing.
    if (context.Response.StatusCode < 400)
        await tenantTransaction.CommitAsync(context.RequestAborted);
});
app.UseAuthorization();

// This is public OAuth CLIENT METADATA only, never an access-token minting endpoint.
app.MapGet("/api/v1/auth/browser", () => Results.Ok(browserOidc))
    .WithName("GetBrowserOidcConfiguration").AllowAnonymous();

// No organization IDs or sensitive roster details on this minimal read-only
// platform identity endpoint. It does NOT grant cross-organization data access.
app.MapGet("/api/v1/platform/session", () => Results.Ok(new { role = "Superadmin" }))
    .WithName("GetPlatformSession").RequireAuthorization("PlatformOperator");

// PlatformInventory is disabled by default. It never falls back to the
// municipal SQL runtime or a schema-owner connection. Auth policy is applied
// BEFORE any query parsing or cross-organization read.
app.MapGet("/api/v1/platform/organizations", async (
    HttpContext context, CancellationToken ct) =>
{
    if (!platformInventory.Enabled)
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);

    // Keyset pagination only. Do not allow hidden tenant/subject selectors.
    if (context.Request.Query.Keys.Any(k => k is not ("limit" or "after")) ||
        context.Request.Query.Any(k => k.Value.Count != 1))
        return Results.BadRequest(new { code = "invalid_inventory_query" });

    var limit = 10;
    if (context.Request.Query.TryGetValue("limit", out var limitValue) &&
        (!int.TryParse(limitValue.ToString(), System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out limit) ||
         limit is < 1 or > 25))
        return Results.BadRequest(new { code = "invalid_inventory_query" });

    Guid? after = null;
    if (context.Request.Query.TryGetValue("after", out var afterValue))
    {
        if (!Guid.TryParseExact(afterValue.ToString(), "D", out var cursor) ||
            cursor == Guid.Empty)
            return Results.BadRequest(new { code = "invalid_inventory_query" });
        after = cursor;
    }

    if (!VerifiedPrincipalIdentity.TryPlatform(context.User, out var issuer, out var subject))
        return Results.Forbid();

    try
    {
        var inventory = context.RequestServices.GetRequiredService<IPlatformInventoryStore>();
        return Results.Ok(await inventory.ListAsync(issuer, subject, limit, after, ct));
    }
    catch (UnauthorizedAccessException)
    {
        return Results.Forbid();
    }
}).WithName("ListPlatformOrganizations").RequireAuthorization("PlatformOperator");

app.MapOpenApi();
app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }))
    .WithName("Live").AllowAnonymous();
app.MapGet("/health/ready", async (
    ComuniDbContext db, TenantProofSigner signer, CancellationToken ct) =>
        await TenantRlsReadinessProbe.CheckAsync(db, signer, ct)
            ? Results.Ok(new { status = "ready" })
            : Results.StatusCode(StatusCodes.Status503ServiceUnavailable))
    .WithName("Ready").AllowAnonymous();

app.MapGet("/api/v1/context", async (
    ICurrentOrganization current, IOrganizationDirectory organizations,
    IOrganizationMembershipStore memberships, ClaimsPrincipal user, CancellationToken ct) =>
{
    var organization = await organizations.FindAsync(current.OrganizationId, ct);
    if (organization is null) return Results.NotFound();
    var enabledModules = await organizations.EnabledModulesAsync(current.OrganizationId, ct);
    if (!VerifiedPrincipalIdentity.TryMunicipal(
            user, out var claimedOrganization, out var subject, out var issuer) ||
        claimedOrganization != current.OrganizationId)
        return Results.Forbid();
    var roles = await memberships.ActiveRolesAsync(current.OrganizationId, subject, issuer, ct);
    return Results.Ok(new
    {
        organizationId = organization.Id,
        organizationName = organization.Name,
        roles,
        modules = enabledModules
    });
}).WithName("GetContext").RequireAuthorization("Read");

app.MapGet("/api/v1/protocol/records", async (
    ICurrentOrganization current, ProtocolService service, CancellationToken ct) =>
{
    try
    {
        var records = await service.ListAsync(current.OrganizationId, ct);
        return Results.Ok(records.Select(ToResponse));
    }
    catch (ModuleDisabledException)
    {
        return Results.Problem(title: "Modulo non abilitato", statusCode: StatusCodes.Status403Forbidden);
    }
}).WithName("ListProtocolRecords").RequireAuthorization("Read");

app.MapPost("/api/v1/protocol/records", async (
    CreateProtocolRecordRequest request, ICurrentOrganization current,
    ProtocolService service, CancellationToken ct) =>
{
    try
    {
        var record = await service.RegisterAsync(current.OrganizationId, request.Subject ?? "", ct);
        return Results.Created($"/api/v1/protocol/records/{record.Id}", ToResponse(record));
    }
    catch (ModuleDisabledException)
    {
        return Results.Problem(title: "Modulo non abilitato", statusCode: StatusCodes.Status403Forbidden);
    }
    catch (ArgumentException ex)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["subject"] = [ex.Message] });
    }
}).WithName("RegisterProtocolRecord").RequireAuthorization("Write");


// Administration is scoped to the organization in the validated JWT.
// Only server-side PostgreSQL memberships with Admin role may perform these operations.
app.MapGet("/api/v1/admin/modules", async (
    ICurrentOrganization current, ModuleAdministrationService service, CancellationToken ct) =>
    Results.Ok(await service.ListAsync(current.OrganizationId, ct)))
    .WithName("ListOrganizationModules").RequireAuthorization("Admin");

app.MapPut("/api/v1/admin/modules/{moduleKey}", async (
    string moduleKey, SetModuleEnabledRequest request, ICurrentOrganization current,
    ModuleAdministrationService service, CancellationToken ct) =>
{
    if (request.Enabled is null)
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["enabled"] = ["The enabled boolean field is required."]
        });

    var status = await service.SetEnabledAsync(
        current.OrganizationId, moduleKey, request.Enabled.Value, ct);
    return status == ModuleUpdateStatus.NotFound
        ? Results.NotFound()
        : Results.Ok(new ModuleState(moduleKey, request.Enabled.Value));
}).WithName("SetOrganizationModule").RequireAuthorization("Admin");

// The audit response is an organization-scoped read-only projection. Each
// successful consultation also creates a minimal server-originated append-only
// audit event atomically within the existing signed tenant SQL transaction.
// No client-supplied tenant, query or role can expand this sensitive view.
app.MapGet("/api/v1/admin/audit", async (
    HttpContext context, ICurrentOrganization current,
    MunicipalAuditService service, CancellationToken ct) =>
{
    if (context.Request.Query.Count > 0)
        return Results.BadRequest(new { code = "invalid_audit_query" });

    return Results.Ok(await service.ListRecentAsync(current.OrganizationId, ct));
}).WithName("ListRecentMunicipalAudit").RequireAuthorization("Admin");

// The organization comes exclusively from the validated JWT (never from the body).
// No Admin grants/revocations here: the first/last Admin is out of this scoped flow.
app.MapGet("/api/v1/admin/memberships", async (
    ICurrentOrganization current, MembershipAdministrationService service, CancellationToken ct) =>
    Results.Ok(await service.ListAsync(current.OrganizationId, ct)))
    .WithName("ListOrganizationMemberships").RequireAuthorization("Admin");

app.MapPut("/api/v1/admin/memberships/{role}", async (
    string role, SetMembershipActiveRequest request,
    ICurrentOrganization current, MembershipAdministrationService service,
    ICurrentActorContext actor, MembershipIssuerPolicy issuerPolicy, CancellationToken ct) =>
{
    if (role is not ("Reader" or "Officer"))
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["role"] = ["Only Reader or Officer can be managed by this endpoint."]
        });
    if (request.Enabled is null || string.IsNullOrWhiteSpace(request.Subject) ||
        request.Subject.Length > 160 || request.Subject != request.Subject.Trim() ||
        request.Subject.Any(char.IsControl))
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["subject"] = ["A valid IdP subject and enabled boolean are required."]
        });

    var status = await service.SetActiveAsync(current.OrganizationId,
        request.Subject, role, request.Enabled.Value, ct);
    return status switch
    {
        MembershipUpdateStatus.NotFound => Results.NotFound(),
        MembershipUpdateStatus.IssuerConflict => Results.Conflict(new
        {
            code = "identity_issuer_mismatch",
            message = "This membership is bound to another issuer or requires verified migration."
        }),
        _ => Results.Ok(new MembershipState(request.Subject, role, request.Enabled.Value,
            issuerPolicy.RequiresOidcBinding ? actor.IdentityIssuer : null))
    };
}).WithName("SetOrganizationMembership").RequireAuthorization("Admin");

// A single backend image also serves the built React PWA in production.
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapFallbackToFile("index.html");

app.Run();

static ProtocolRecordResponse ToResponse(ProtocolRecord record) =>
    new(record.Id, record.Subject, record.RegisteredAt);

public sealed record SetModuleEnabledRequest(bool? Enabled);
public sealed record SetMembershipActiveRequest(string? Subject, bool? Enabled);
public sealed record CreateProtocolRecordRequest(string? Subject);
public sealed record ProtocolRecordResponse(Guid Id, string Subject, DateTimeOffset RegisteredAt);
public partial class Program { } // WebApplicationFactory entry point for integration tests.
