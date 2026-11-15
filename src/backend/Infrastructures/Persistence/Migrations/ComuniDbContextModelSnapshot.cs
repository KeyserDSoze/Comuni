using System;
using Comuni.Infrastructures.Persistence;
using Comuni.Domains.Organizations;
using Comuni.Domains.Protocol;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

#nullable disable

namespace Comuni.Infrastructures.Persistence.Migrations;

[DbContext(typeof(ComuniDbContext))]
public sealed class ComuniDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
        modelBuilder.HasAnnotation("ProductVersion", "10.0.0");

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
        });
    }
}
