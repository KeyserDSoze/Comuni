using Comuni.Business.Organizations;
using Comuni.Domains.Organizations;
using Comuni.Domains.Protocol;
using Microsoft.EntityFrameworkCore;

namespace Comuni.Infrastructures.Persistence;

public sealed class ComuniDbContext(
    DbContextOptions<ComuniDbContext> options,
    ICurrentOrganization currentOrganization) : DbContext(options)
{
    // EF parameterizes this instance property, rather than capturing an organization at model-build time.
    public Guid CurrentOrganizationId => currentOrganization.OrganizationId;

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationModule> OrganizationModules => Set<OrganizationModule>();
    public DbSet<OrganizationMembership> OrganizationMemberships => Set<OrganizationMembership>();
    public DbSet<ProtocolRecord> ProtocolRecords => Set<ProtocolRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Organization>(b =>
        {
            b.ToTable("organizations", "platform");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id");
            b.Property(x => x.Name).HasColumnName("name").HasMaxLength(200).IsRequired();
        });

        modelBuilder.Entity<OrganizationModule>(b =>
        {
            b.ToTable("organization_modules", "platform");
            b.HasKey(x => new { x.OrganizationId, x.ModuleKey });
            b.Property(x => x.OrganizationId).HasColumnName("organization_id");
            b.Property(x => x.ModuleKey).HasColumnName("module_key").HasMaxLength(80).IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            b.HasQueryFilter(x => x.OrganizationId == CurrentOrganizationId);
        });

        modelBuilder.Entity<OrganizationMembership>(b =>
        {
            b.ToTable("organization_memberships", "platform", t =>
                t.HasCheckConstraint("ck_organization_memberships_role", "role IN ('Admin','Officer','Reader')"));
            b.HasKey(x => new { x.OrganizationId, x.Subject, x.Role });
            b.Property(x => x.OrganizationId).HasColumnName("organization_id");
            b.Property(x => x.Subject).HasColumnName("subject").HasMaxLength(160).IsRequired();
            b.Property(x => x.Role).HasColumnName("role").HasMaxLength(16).IsRequired();
            b.Property(x => x.IsActive).HasColumnName("is_active").IsRequired();
            b.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
            b.HasQueryFilter(x => x.OrganizationId == CurrentOrganizationId);
        });

        modelBuilder.Entity<ProtocolRecord>(b =>
        {
            b.ToTable("records", "protocol");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id");
            b.Property(x => x.OrganizationId).HasColumnName("organization_id");
            b.Property(x => x.Subject).HasColumnName("subject").HasMaxLength(250).IsRequired();
            b.Property(x => x.RegisteredAt).HasColumnName("registered_at").HasColumnType("timestamp with time zone");
            b.HasIndex(x => new { x.OrganizationId, x.RegisteredAt });
            b.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);
            b.HasQueryFilter(x => x.OrganizationId == CurrentOrganizationId);
        });
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        var organizationId = CurrentOrganizationId;

        foreach (var entry in ChangeTracker.Entries<ProtocolRecord>())
        {
            if (entry.State is EntityState.Added or EntityState.Modified or EntityState.Deleted &&
                (organizationId == Guid.Empty || entry.Entity.OrganizationId != organizationId))
                throw new UnauthorizedAccessException("Cannot change data outside the current organization.");
        }

        foreach (var entry in ChangeTracker.Entries<OrganizationModule>())
        {
            if (entry.State is EntityState.Added or EntityState.Modified or EntityState.Deleted &&
                (organizationId == Guid.Empty || entry.Entity.OrganizationId != organizationId))
                throw new UnauthorizedAccessException("Cannot change module settings outside the current organization.");
        }

        foreach (var entry in ChangeTracker.Entries<OrganizationMembership>())
        {
            if (entry.State is EntityState.Added or EntityState.Modified or EntityState.Deleted &&
                (organizationId == Guid.Empty || entry.Entity.OrganizationId != organizationId))
                throw new UnauthorizedAccessException("Cannot change memberships outside the current organization.");
        }

        return base.SaveChangesAsync(cancellationToken);
    }
}
