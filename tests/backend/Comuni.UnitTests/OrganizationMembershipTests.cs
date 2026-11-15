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

    [Theory]
    [InlineData("http://issuer.example.test/")]
    [InlineData("https://user:pass@issuer.example.test/")]
    [InlineData("https://issuer.example.test/?code=bad")]
    [InlineData("https://issuer.example.test/#frag")]
    public void Membership_rejects_untrusted_external_issuer(string issuer)
    {
        Assert.Throws<ArgumentException>(() =>
            OrganizationMembership.Grant(Guid.NewGuid(), "subject", "Reader", issuer));
    }

    [Fact]
    public void Membership_can_bind_to_a_specific_OIDC_issuer()
    {
        var issuer = "https://issuer.example.test/tenant";
        var membership = OrganizationMembership.Grant(Guid.NewGuid(), "sub", "Officer", issuer);
        Assert.Equal(issuer, membership.IdentityIssuer);
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
