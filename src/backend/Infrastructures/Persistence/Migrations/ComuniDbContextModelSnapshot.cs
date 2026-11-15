using System;
using Comuni.Infrastructures.Persistence;
using Comuni.Domains.Organizations;
using Comuni.Domains.Protocol;
using Comuni.Domains.Audit;
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
            b.Property(x => x.IsSuspended).HasColumnName("is_suspended").HasDefaultValue(false).IsRequired();
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

        modelBuilder.Entity<OrganizationMembership>(b =>
        {
            b.ToTable("organization_memberships", "platform", t =>
            {
                t.HasCheckConstraint("ck_organization_memberships_role", "role IN ('Admin','Officer','Reader')");
                t.HasCheckConstraint("ck_membership_identity_issuer_https",
                    "identity_issuer IS NULL OR (identity_issuer LIKE 'https://%' AND identity_issuer !~ '[?#]')");
            });
            b.HasKey(x => new { x.OrganizationId, x.Subject, x.Role });
            b.Property(x => x.OrganizationId).HasColumnName("organization_id");
            b.Property(x => x.Subject).HasColumnName("subject").HasMaxLength(160).IsRequired();
            b.Property(x => x.IdentityIssuer).HasColumnName("identity_issuer").HasMaxLength(512);
            b.Property(x => x.Role).HasColumnName("role").HasMaxLength(16).IsRequired();
            b.Property(x => x.IsActive).HasColumnName("is_active").IsRequired();
            b.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuditEvent>(b =>
        {
            b.ToTable("audit_events", "platform");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id");
            b.Property(x => x.OrganizationId).HasColumnName("organization_id");
            b.Property(x => x.ActorSubject).HasColumnName("actor_subject").HasMaxLength(160).IsRequired();
            b.Property(x => x.Action).HasColumnName("action").HasMaxLength(120).IsRequired();
            b.Property(x => x.ResourceType).HasColumnName("resource_type").HasMaxLength(100).IsRequired();
            b.Property(x => x.ResourceId).HasColumnName("resource_id").IsRequired();
            b.Property(x => x.CorrelationId).HasColumnName("correlation_id").HasMaxLength(128).IsRequired();
            b.Property(x => x.OccurredAt).HasColumnName("occurred_at").HasColumnType("timestamp with time zone");
            b.HasIndex(x => new { x.OrganizationId, x.OccurredAt });
            b.HasIndex(x => new { x.OrganizationId, x.ResourceId });
            b.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId)
                .OnDelete(DeleteBehavior.Restrict);
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
