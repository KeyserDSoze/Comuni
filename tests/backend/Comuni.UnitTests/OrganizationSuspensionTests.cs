using Comuni.Domains.Organizations;
using Xunit;

namespace Comuni.UnitTests;

public sealed class OrganizationSuspensionTests
{
    [Fact]
    public void New_organization_is_not_suspended_and_can_be_suspended_and_reactivated()
    {
        var organization = new Organization(Guid.NewGuid(), "Comune Test");
        Assert.False(organization.IsSuspended);

        organization.Suspend();
        Assert.True(organization.IsSuspended);

        organization.Reactivate();
        Assert.False(organization.IsSuspended);
    }
}
