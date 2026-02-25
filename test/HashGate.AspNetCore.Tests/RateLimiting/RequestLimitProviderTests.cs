using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using HashGate.AspNetCore.RateLimiting;

namespace HashGate.AspNetCore.Tests.RateLimiting;

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

    [Fact]
    public void Get_WhenClientNotInConfiguration_ReturnsNull()
    {
        var provider = CreateProvider();

        var result = provider.Get("unknown-client");

        Assert.Null(result);
    }

    [Fact]
    public void Get_WhenClientFullyConfigured_ReturnsConfiguredGlobalLimit()
    {
        var provider = CreateProvider();

        var result = provider.Get("full-client");

        Assert.NotNull(result);
        Assert.Equal(new RequestLimit(RequestsPerPeriod: 100, BurstFactor: 3), result.Global);
    }

    [Fact]
    public void Get_WhenClientFullyConfigured_ReturnsConfiguredEndpointLimit()
    {
        var provider = CreateProvider();

        var result = provider.Get("full-client");

        Assert.NotNull(result);
        Assert.Equal(new RequestLimit(RequestsPerPeriod: 40, BurstFactor: 2), result.Endpoint);
    }

    [Fact]
    public void Get_WhenGlobalNotConfigured_FallsBackToDefaultGlobal()
    {
        var defaultGlobal = new RequestLimit(RequestsPerPeriod: 60, BurstFactor: 2);
        var provider = CreateProvider(configure: o => o.DefaultGlobal = defaultGlobal);

        var result = provider.Get("endpoint-only-client");

        Assert.NotNull(result);
        Assert.Equal(defaultGlobal, result.Global);
    }

    [Fact]
    public void Get_WhenEndpointNotConfigured_FallsBackToDefaultEndpoint()
    {
        var defaultEndpoint = new RequestLimit(RequestsPerPeriod: 20, BurstFactor: 2);
        var provider = CreateProvider(configure: o => o.DefaultEndpoint = defaultEndpoint);

        var result = provider.Get("global-only-client");

        Assert.NotNull(result);
        Assert.Equal(defaultEndpoint, result.Endpoint);
    }

    [Fact]
    public void Get_WhenGlobalNotConfigured_UsesCustomDefaultGlobal()
    {
        var customDefault = new RequestLimit(RequestsPerPeriod: 999, BurstFactor: 5);
        var provider = CreateProvider(configure: o => o.DefaultGlobal = customDefault);

        var result = provider.Get("endpoint-only-client");

        Assert.NotNull(result);
        Assert.Equal(customDefault, result.Global);
    }

    [Fact]
    public void Get_WhenEndpointNotConfigured_UsesCustomDefaultEndpoint()
    {
        var customDefault = new RequestLimit(RequestsPerPeriod: 999, BurstFactor: 5);
        var provider = CreateProvider(configure: o => o.DefaultEndpoint = customDefault);

        var result = provider.Get("global-only-client");

        Assert.NotNull(result);
        Assert.Equal(customDefault, result.Endpoint);
    }

    [Fact]
    public void Get_WithCustomSectionName_ReadsFromCorrectSection()
    {
        var provider = CreateProvider(configure: o => o.SectionName = "CustomRateLimits");

        var result = provider.Get("custom-client");

        Assert.NotNull(result);
        Assert.Equal(new RequestLimit(RequestsPerPeriod: 200, BurstFactor: 4), result.Global);
        Assert.Equal(new RequestLimit(RequestsPerPeriod: 80, BurstFactor: 3), result.Endpoint);
    }

    [Fact]
    public void Get_WithCustomSectionName_WhenClientNotInSection_ReturnsNull()
    {
        var provider = CreateProvider(configure: o => o.SectionName = "CustomRateLimits");

        // full-client exists under HmacRateLimits but not CustomRateLimits
        var result = provider.Get("full-client");

        Assert.Null(result);
    }
}

public class RequestLimitOptionsMonitor(RequestLimitOptions options) : IOptionsMonitor<RequestLimitOptions>
{
    public RequestLimitOptions CurrentValue { get; } = options;

    public RequestLimitOptions Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<RequestLimitOptions, string?> listener) => null;
}
