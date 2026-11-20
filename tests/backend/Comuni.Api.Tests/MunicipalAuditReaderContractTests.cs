using System.Reflection;
using Comuni.Business.Audit;
using Comuni.Infrastructures.Persistence;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// ADR 0036: every public Business consultation must append the audit event
/// in the same signed tenant transaction. A public unlogged read would let
/// future use cases bypass the otherwise-correct HTTP audit endpoint.
/// </summary>
public sealed class MunicipalAuditReaderContractTests
{
    [Fact]
    public void No_public_unlogged_audit_read_can_bypass_consultation_event()
    {
        Assert.Null(typeof(IOrganizationAuditReader).GetMethod(
            "ListRecentAsync", BindingFlags.Public | BindingFlags.Instance));

        Assert.Null(typeof(OrganizationAuditReader).GetMethod(
            "ListRecentAsync", BindingFlags.Public | BindingFlags.Instance));

        var tracked = typeof(IOrganizationAuditReader).GetMethod(
            "ListRecentAndRecordAsync", BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(tracked);
        // The caller must never supply an AuditEvent carrying a forged actor
        // or correlation: the repository obtains both from the trusted API context.
        Assert.Equal(
            new[] { typeof(Guid), typeof(CancellationToken) },
            tracked!.GetParameters().Select(p => p.ParameterType));
        Assert.Contains(
            typeof(ICurrentActorContext),
            typeof(OrganizationAuditReader).GetConstructors().Single()
                .GetParameters().Select(p => p.ParameterType));
    }
}
