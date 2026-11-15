using Comuni.Infrastructures.Persistence;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class TenantProofKeyIdTests
{
    private const string TestKey = "test-only-key-for-versioned-tenant-proof-2026";

    [Fact]
    public void Versioned_proof_authenticates_key_id_as_part_of_mac()
    {
        var tenant = Guid.NewGuid();
        var signer = new TenantProofSigner(TestKey, "rotation_2");
        var proof = signer.Create(tenant);
        var parts = proof.Split('|');

        Assert.Equal(5, parts.Length);
        Assert.Equal("rotation_2", parts[0]);
        Assert.Equal(tenant.ToString("N"), parts[1]);
        Assert.Matches("^[0-9]{10,12}$", parts[2]);
        Assert.Matches("^[0-9a-f]{32}$", parts[3]);
        Assert.Matches("^[0-9a-f]{64}$", parts[4]);
        Assert.DoesNotContain(TestKey, proof);
        Assert.NotEqual(proof, proof.Replace("rotation_2", "rotation_3", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("UPPER")]
    [InlineData("a|b")]
    [InlineData("this-key-id-is-longer-than-thirty-two-chars")]
    public void Key_ids_outside_the_allowlist_are_rejected(string keyId)
    {
        Assert.Throws<ArgumentException>(() => new TenantProofSigner(TestKey, keyId));
    }
}
