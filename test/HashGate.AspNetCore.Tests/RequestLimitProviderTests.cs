using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.Tests;

public class RequestLimitProviderTests
{
    private static IConfiguration BuildConfiguration() =>
        new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .Build();

    private static RequestLimitProvider CreateProvider(
        IConfiguration? configuration = null,
        Action<RequestLimitOptions>? configure = null)
    {
        var options = new RequestLimitOptions();
        configure?.Invoke(options);

        return new RequestLimitProvider(
            NullLogger<RequestLimitProvider>.Instance,
            configuration ?? BuildConfiguration(),
            new RequestLimitOptionsMonitor(options));
    }

    // -----------------------------------------------------------------------
    // Client not in config
    // -----------------------------------------------------------------------

    [Fact]
    public async Task GetAsync_WhenClientNotInConfiguration_ReturnsNull()
    {
        var provider = CreateProvider();

        var result = await provider.GetAsync("unknown-client", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    // -----------------------------------------------------------------------
    // Fully configured client
    // -----------------------------------------------------------------------

    [Fact]
    public async Task GetAsync_WhenClientFullyConfigured_ReturnsConfiguredRequestsPerPeriod()
    {
        var provider = CreateProvider();

        var result = await provider.GetAsync("full-client", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal(100, result.Value.RequestsPerPeriod);
    }

    [Fact]
    public async Task GetAsync_WhenClientFullyConfigured_ReturnsConfiguredBurstFactor()
    {
        var provider = CreateProvider();

        var result = await provider.GetAsync("full-client", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal(3, result.Value.BurstFactor);
    }

    // -----------------------------------------------------------------------
    // Partial configuration — missing fields fall back to options defaults
    // -----------------------------------------------------------------------

    [Fact]
    public async Task GetAsync_WhenBurstFactorNotConfigured_FallsBackToOptionsDefault()
    {
        const int defaultBurstFactor = 7;
        var provider = CreateProvider(configure: o => o.BurstFactor = defaultBurstFactor);

        // rpp-only-client has RequestsPerPeriod=50 in config but no BurstFactor
        var result = await provider.GetAsync("rpp-only-client", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal(50, result.Value.RequestsPerPeriod);
        Assert.Equal(defaultBurstFactor, result.Value.BurstFactor);  // fell back
    }

    [Fact]
    public async Task GetAsync_WhenRequestsPerPeriodNotConfigured_FallsBackToOptionsDefault()
    {
        const int defaultRpp = 99;
        var provider = CreateProvider(configure: o => o.RequestsPerPeriod = defaultRpp);

        // bf-only-client has BurstFactor=5 in config but no RequestsPerPeriod
        var result = await provider.GetAsync("bf-only-client", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal(defaultRpp, result.Value.RequestsPerPeriod);    // fell back
        Assert.Equal(5, result.Value.BurstFactor);
    }

    // -----------------------------------------------------------------------
    // Custom section name
    // -----------------------------------------------------------------------

    [Fact]
    public async Task GetAsync_WithCustomSectionName_ReadsFromCorrectSection()
    {
        var provider = CreateProvider(configure: o => o.SectionName = "CustomRateLimits");

        var result = await provider.GetAsync("custom-client", TestContext.Current.CancellationToken);

        Assert.NotNull(result);
        Assert.Equal(new RequestLimit(RequestsPerPeriod: 200, BurstFactor: 4), result.Value);
    }

    [Fact]
    public async Task GetAsync_WithCustomSectionName_WhenClientNotInSection_ReturnsNull()
    {
        var provider = CreateProvider(configure: o => o.SectionName = "CustomRateLimits");

        // full-client exists under HmacRateLimits but not CustomRateLimits
        var result = await provider.GetAsync("full-client", TestContext.Current.CancellationToken);

        Assert.Null(result);
    }
}

/// <summary>Minimal <see cref="IOptionsMonitor{TOptions}"/> stub for unit tests.</summary>
public sealed class RequestLimitOptionsMonitor(RequestLimitOptions options)
    : IOptionsMonitor<RequestLimitOptions>
{
    public RequestLimitOptions CurrentValue { get; } = options;

    public RequestLimitOptions Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<RequestLimitOptions, string?> listener) => null;
}
