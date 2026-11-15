using System.Security.Claims;
using System.Text;
using Comuni.Api.Security;
using Comuni.Business.Organizations;
using Comuni.Business.Protocol;
using Comuni.Domains.Protocol;
using Comuni.Infrastructures.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var key = builder.Configuration["Jwt:SigningKey"]
    ?? throw new InvalidOperationException("Jwt:SigningKey is required (use Key Vault in Azure).");
if (Encoding.UTF8.GetByteCount(key) < 32)
    throw new InvalidOperationException("Jwt:SigningKey must be at least 32 bytes long.");

var issuer = builder.Configuration["Jwt:Issuer"]
    ?? throw new InvalidOperationException("Jwt:Issuer is required.");
var audience = builder.Configuration["Jwt:Audience"]
    ?? throw new InvalidOperationException("Jwt:Audience is required.");
var connection = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("ConnectionStrings:Default is required.");

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentOrganization, HttpCurrentOrganization>();
builder.Services.AddDbContext<ComuniDbContext>(options => options.UseNpgsql(connection));
builder.Services.AddScoped<OrganizationDirectory>();
builder.Services.AddScoped<IOrganizationDirectory>(s => s.GetRequiredService<OrganizationDirectory>());
builder.Services.AddScoped<IOrganizationModuleStore>(s => s.GetRequiredService<OrganizationDirectory>());
builder.Services.AddScoped<IProtocolRepository, ProtocolRepository>();
builder.Services.AddScoped<ProtocolService>();
builder.Services.AddOpenApi();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            ValidateLifetime = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            RoleClaimType = "role",
            NameClaimType = "sub",
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Read", policy => policy
        .RequireAuthenticatedUser()
        .RequireRole("Admin", "Officer", "Reader")
        .RequireAssertion(ctx => ValidOrganization(ctx.User)));
    options.AddPolicy("Write", policy => policy
        .RequireAuthenticatedUser()
        .RequireRole("Admin", "Officer")
        .RequireAssertion(ctx => ValidOrganization(ctx.User)));
});

var app = builder.Build();

// Local demo only. In production migrations are applied explicitly during deployment.
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ComuniDbContext>();
    await db.Database.MigrateAsync();
    await db.Database.ExecuteSqlRawAsync("""
        INSERT INTO platform.organizations (id, name) VALUES
          ('11111111-1111-1111-1111-111111111111', 'Comune Aurora'),
          ('22222222-2222-2222-2222-222222222222', 'Comune Borgo')
        ON CONFLICT (id) DO NOTHING;
        INSERT INTO platform.organization_modules (organization_id, module_key, enabled) VALUES
          ('11111111-1111-1111-1111-111111111111', 'protocol', TRUE),
          ('22222222-2222-2222-2222-222222222222', 'protocol', FALSE)
        ON CONFLICT (organization_id, module_key) DO NOTHING;
        """);
}

app.UseAuthentication();
app.UseAuthorization();

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
    ClaimsPrincipal user, CancellationToken ct) =>
{
    var organization = await organizations.FindAsync(current.OrganizationId, ct);
    if (organization is null) return Results.NotFound();
    var enabledModules = await organizations.EnabledModulesAsync(current.OrganizationId, ct);
    var roles = user.FindAll("role").Select(c => c.Value).Distinct().ToArray();
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

// A single backend image also serves the built React PWA in production.
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapFallbackToFile("index.html");

app.Run();

static bool ValidOrganization(ClaimsPrincipal user) =>
    Guid.TryParse(user.FindFirst("organization_id")?.Value, out var id) && id != Guid.Empty;

static ProtocolRecordResponse ToResponse(ProtocolRecord record) =>
    new(record.Id, record.Subject, record.RegisteredAt);

public sealed record CreateProtocolRecordRequest(string? Subject);
public sealed record ProtocolRecordResponse(Guid Id, string Subject, DateTimeOffset RegisteredAt);
public partial class Program { } // WebApplicationFactory entry point for integration tests.
