using System.Security.Claims;
using System.Globalization;
using System.Threading.RateLimiting;
using Comuni.Api.Security;
using Comuni.Business.Audit;
using Comuni.Business.Organizations;
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
var connection = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("ConnectionStrings:Default is required.");
var protection = ApiProtectionSettings.Read(builder.Configuration);
var browserOidc = BrowserOidcSettings.Read(builder.Configuration, authentication.Mode, builder.Environment.EnvironmentName);
var tenantProofKey = builder.Configuration["Security:TenantProofKey"];
var tenantProofSigner = new TenantProofSigner(tenantProofKey ?? string.Empty, builder.Configuration["Security:TenantProofKeyId"]);

builder.Services.AddSingleton(tenantProofSigner);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentOrganization, HttpCurrentOrganization>();
builder.Services.AddScoped<ICurrentActorContext, HttpCurrentActorContext>();
builder.Services.AddDbContext<ComuniDbContext>(options => options.UseNpgsql(connection));
builder.Services.AddScoped<OrganizationDirectory>();
builder.Services.AddScoped<IOrganizationDirectory>(s => s.GetRequiredService<OrganizationDirectory>());
builder.Services.AddScoped<IOrganizationModuleStore>(s => s.GetRequiredService<OrganizationDirectory>());
builder.Services.AddScoped<IOrganizationMembershipStore, OrganizationMembershipStore>();
builder.Services.AddScoped<IAuthorizationHandler, OrganizationRoleHandler>();
builder.Services.AddScoped<IProtocolRepository, ProtocolRepository>();
builder.Services.AddScoped<ProtocolService>();
builder.Services.AddScoped<IModuleAdministrationStore, ModuleAdministrationRepository>();
builder.Services.AddScoped<ModuleAdministrationService>();
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
        context.User.Identity?.IsAuthenticated != true ||
        !Guid.TryParse(context.User.FindFirst("organization_id")?.Value, out var tenantId) ||
        tenantId == Guid.Empty)
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

app.MapOpenApi();
app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }))
    .WithName("Live").AllowAnonymous();
app.MapGet("/health/ready", async (ComuniDbContext db, CancellationToken ct) =>
        await db.Database.CanConnectAsync(ct)
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
    var subject = user.FindFirst("sub")?.Value ?? string.Empty;
    var roles = await memberships.ActiveRolesAsync(current.OrganizationId, subject, ct);
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

// A single backend image also serves the built React PWA in production.
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapFallbackToFile("index.html");

app.Run();

static ProtocolRecordResponse ToResponse(ProtocolRecord record) =>
    new(record.Id, record.Subject, record.RegisteredAt);

public sealed record SetModuleEnabledRequest(bool? Enabled);
public sealed record CreateProtocolRecordRequest(string? Subject);
public sealed record ProtocolRecordResponse(Guid Id, string Subject, DateTimeOffset RegisteredAt);
public partial class Program { } // WebApplicationFactory entry point for integration tests.
