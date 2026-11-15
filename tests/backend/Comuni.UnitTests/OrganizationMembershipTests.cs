using Comuni.Domains.Organizations;
using Xunit;

namespace Comuni.UnitTests;

public sealed class OrganizationMembershipTests
{
    [Fact]
    public void Requires_valid_organization()
    {
        Assert.Throws<ArgumentException>(() =>
            OrganizationMembership.Grant(Guid.Empty, "user-123", "Officer"));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Requires_subject(string subject)
    {
        Assert.Throws<ArgumentException>(() =>
            OrganizationMembership.Grant(Guid.NewGuid(), subject, "Reader"));
    }

    [Theory]
    [InlineData("Superadmin")]
    [InlineData("Owner")]
    [InlineData("")]
    public void Rejects_unknown_role(string role)
    {
        Assert.Throws<ArgumentException>(() =>
            OrganizationMembership.Grant(Guid.NewGuid(), "user", role));
    }

    [Fact]
    public void Can_suspend_and_reactivate_membership_without_changing_organization()
    {
        var org = Guid.NewGuid();
        var member = OrganizationMembership.Grant(org, " user-123 ", "Reader");
        Assert.Equal(org, member.OrganizationId);
        Assert.Equal("user-123", member.Subject);
        Assert.True(member.IsActive);
        member.Deactivate();
        Assert.False(member.IsActive);
        member.Activate();
        Assert.True(member.IsActive);
    }
}
