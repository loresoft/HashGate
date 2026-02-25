using System.Security.Claims;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace HashGate.AspNetCore.Tests;

public class HmacKeyProviderTests
{
    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .Build();

    private static HmacKeyProvider CreateProvider(
        IConfiguration? configuration = null,
        Action<HmacAuthenticationSchemeOptions>? configure = null)
    {
        var options = new HmacAuthenticationSchemeOptions();
        configure?.Invoke(options);

        return new HmacKeyProvider(
            configuration ?? BuildConfiguration(),
            NullLogger<HmacKeyProvider>.Instance,
            new TestOptionsMonitor(options));
    }

    // GenerateClaimsAsync

    [Fact]
    public void GenerateClaimsAsync_WhenClientIsNull_ThrowsArgumentNullException()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentNullException>(() => provider.GenerateClaimsAsync(null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void GenerateClaimsAsync_WhenClientIsEmpty_ThrowsArgumentException()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentException>(() => provider.GenerateClaimsAsync(string.Empty, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public void GenerateClaimsAsync_WhenClientIsWhitespace_ThrowsArgumentException()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentException>(() => provider.GenerateClaimsAsync("   ", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GenerateClaimsAsync_ReturnsIdentityWithClientNameClaim()
    {
        var provider = CreateProvider();

        var identity = await provider.GenerateClaimsAsync("test-client", cancellationToken: TestContext.Current.CancellationToken);

        var nameClaim = identity.FindFirst(ClaimTypes.Name);
        Assert.NotNull(nameClaim);
        Assert.Equal("test-client", nameClaim.Value);
    }

    [Fact]
    public async Task GenerateClaimsAsync_WhenSchemeIsNull_UsesDefaultScheme()
    {
        var provider = CreateProvider();

        var identity = await provider.GenerateClaimsAsync("test-client", scheme: null, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HmacAuthenticationShared.DefaultSchemeName, identity.AuthenticationType);
    }

    [Fact]
    public async Task GenerateClaimsAsync_WhenSchemeIsProvided_UsesProvidedScheme()
    {
        var provider = CreateProvider();

        var identity = await provider.GenerateClaimsAsync("test-client", scheme: "CustomScheme", cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("CustomScheme", identity.AuthenticationType);
    }

    // GetSecretAsync

    [Fact]
    public void GetSecretAsync_WhenClientIsNull_ThrowsArgumentNullException()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentNullException>(() => provider.GetSecretAsync(null!, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void GetSecretAsync_WhenClientIsEmpty_ThrowsArgumentException()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentException>(() => provider.GetSecretAsync(string.Empty, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void GetSecretAsync_WhenClientIsWhitespace_ThrowsArgumentException()
    {
        var provider = CreateProvider();

        Assert.Throws<ArgumentException>(() => provider.GetSecretAsync("   ", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetSecretAsync_WhenClientExists_ReturnsSecret()
    {
        var provider = CreateProvider();

        var secret = await provider.GetSecretAsync("test-client", TestContext.Current.CancellationToken);

        Assert.Equal("test-secret-abc123", secret);
    }

    [Fact]
    public async Task GetSecretAsync_WhenClientNotFound_ReturnsNull()
    {
        var provider = CreateProvider();

        var secret = await provider.GetSecretAsync("unknown-client", TestContext.Current.CancellationToken);

        Assert.Null(secret);
    }

    [Fact]
    public async Task GetSecretAsync_WithCustomSectionName_ReadsFromCustomSection()
    {
        var provider = CreateProvider(configure: o => o.SecretSectionName = "CustomSecrets");

        var secret = await provider.GetSecretAsync("custom-client", TestContext.Current.CancellationToken);

        Assert.Equal("custom-secret-def456", secret);
    }

    [Fact]
    public async Task GetSecretAsync_WithCustomSectionName_WhenClientNotInSection_ReturnsNull()
    {
        // test-client exists under HmacSecrets but not CustomSecrets
        var provider = CreateProvider(configure: o => o.SecretSectionName = "CustomSecrets");

        var secret = await provider.GetSecretAsync("test-client", TestContext.Current.CancellationToken);

        Assert.Null(secret);
    }
}
