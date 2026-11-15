using Comuni.Business.Organizations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Comuni.Infrastructures.Persistence;

// Used by dotnet-ef tooling only. The runtime context comes from validated JWT claims.
public sealed class ComuniDbContextFactory : IDesignTimeDbContextFactory<ComuniDbContext>
{
    public ComuniDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("ConnectionStrings__Default")
            ?? "Host=localhost;Port=5432;Database=comuni;Username=comuni;Password=not-used-for-design-time";
        var options = new DbContextOptionsBuilder<ComuniDbContext>().UseNpgsql(connection).Options;
        return new ComuniDbContext(options, new DesignTimeOrganization());
    }

    private sealed class DesignTimeOrganization : ICurrentOrganization
    {
        public Guid OrganizationId => Guid.Empty;
    }
}
