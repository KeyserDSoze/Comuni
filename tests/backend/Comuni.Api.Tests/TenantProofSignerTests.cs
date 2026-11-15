using Comuni.Infrastructures.Persistence;
using Xunit;

namespace Comuni.Api.Tests;

public sealed class TenantProofSignerTests
{
    private const string TestKey = "test-only-random-tenant-proof-key-2026-11-15";

    [Fact]
    public void New_proof_has_tenant_expiry_nonce_and_mac_without_leaking_key()
    {
        var signer = new TenantProofSigner(TestKey);
        var tenant = Guid.NewGuid();
        var a = signer.Create(tenant);
        var b = signer.Create(tenant);
        Assert.NotEqual(a, b);
        var parts = a.Split('|');
        Assert.Equal(4, parts.Length);
        Assert.Equal(tenant.ToString("N"), parts[0]);
        Assert.InRange(long.Parse(parts[1]), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 1,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300);
        Assert.Matches("^[0-9a-f]{32}$", parts[2]);
        Assert.Matches("^[0-9a-f]{64}$", parts[3]);
        Assert.DoesNotContain(TestKey, a);
    }

    [Fact]
    public void Missing_or_weak_key_and_empty_tenant_are_rejected()
    {
        Assert.Throws<InvalidOperationException>(() => new TenantProofSigner(""));
        Assert.Throws<InvalidOperationException>(() => new TenantProofSigner("short"));
        var signer = new TenantProofSigner(TestKey);
        Assert.Throws<ArgumentException>(() => signer.Create(Guid.Empty));
    }
}
