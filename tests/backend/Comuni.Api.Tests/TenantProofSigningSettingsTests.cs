using Comuni.Api.Security;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Comuni.Api.Tests;

/// <summary>
/// Fail closed when deploying an unversioned tenant RLS signer in Production.
/// PostgreSQL may still verify legacy proofs during an approved migration grace.
/// </summary>
public sealed class TenantProofSigningSettingsTests
{
    private const string TestKey = "synthetic-hmac-only-for-configuration-test-2026-11";

    private static IConfiguration Config(string? id = null, string key = TestKey)
    {
        var values = new Dictionary<string, string?> { ["Security:TenantProofKey"] = key };
        if (id is not null) values["Security:TenantProofKeyId"] = id;
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    [Theory]
    [InlineData("Production", null)]
    [InlineData("Production", "")]
    [InlineData("Production", "  ")]
    [InlineData("Production", "legacy")]
    [InlineData("Staging", null)]
    [InlineData("Staging", "legacy")]
    public void Hosted_environments_reject_unversioned_or_legacy_signers(string environmentName, string? keyId)
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => TenantProofSigningSettings.Read(Config(keyId), environmentName));
        Assert.Contains("Security:TenantProofKeyId", error.Message);
        Assert.DoesNotContain(TestKey, error.Message);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Testing")]
    public void Local_and_test_signers_keep_legacy_four_part_proof_for_demo(string environmentName)
    {
        var signer = TenantProofSigningSettings.Read(Config(), environmentName);
        var proof = signer.Create(Guid.NewGuid());
        Assert.Equal(4, proof.Split('|').Length);
        Assert.DoesNotContain(TestKey, proof);
    }

    [Fact]
    public void Production_versioned_signer_authenticates_nonlegacy_key_id()
    {
        var signer = TenantProofSigningSettings.Read(Config("rollout_2026_11"), "Production");
        var proof = signer.Create(Guid.NewGuid());
        var parts = proof.Split('|');
        Assert.Equal(5, parts.Length);
        Assert.Equal("rollout_2026_11", parts[0]);
        Assert.Matches("^[0-9a-f]{64}$", parts[4]);
        Assert.DoesNotContain(TestKey, proof);
    }

    [Theory]
    [InlineData("INVALID")]
    [InlineData("../escape")]
    [InlineData("unsafe|key")]
    public void Production_keeps_strict_key_id_validation(string keyId)
    {
        Assert.Throws<ArgumentException>(
            () => TenantProofSigningSettings.Read(Config(keyId), "Production"));
    }

    [Fact]
    public void Production_rejects_weak_material_even_for_a_versioned_id()
    {
        Assert.Throws<InvalidOperationException>(
            () => TenantProofSigningSettings.Read(Config("rotation_v2", "weak"), "Production"));
    }
}
