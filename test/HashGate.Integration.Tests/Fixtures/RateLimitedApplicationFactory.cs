namespace HashGate.Integration.Tests.Fixtures;

public sealed class RateLimitedApplicationFactory : IDisposable
{
    public const string ClientId = "rl-test";
    public const string ClientSecret = "rl-test-secret";

    public const string ExpectedRetryAfter = "60";
    public const string ExpectedRejectionBody = "Rate limit exceeded. Retry after 60s.";

    private readonly IHost _host;

    public RateLimitedApplicationFactory(int requestsPerPeriod = 100, int burstFactor = 1)
    {
        _host = new HostBuilder()
            .ConfigureWebHost(builder => ConfigureWebHost(builder, requestsPerPeriod, burstFactor))
            .Build();

        _host.Start();
    }

    private static void ConfigureWebHost(
        IWebHostBuilder builder,
        int requestsPerPeriod,
        int burstFactor)
    {
        builder
            .UseTestServer()
            .UseContentRoot(AppContext.BaseDirectory)
            .ConfigureAppConfiguration(ConfigureAppConfiguration)
            .ConfigureServices(services => ConfigureServices(services, requestsPerPeriod, burstFactor))
            .Configure(ConfigureApp);
    }

    private static void ConfigureAppConfiguration(WebHostBuilderContext _, IConfigurationBuilder config)
    {
        // Only HMAC secrets needed — rate limits are set via RequestLimitOptions, not configuration.
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"HmacSecrets:{ClientId}"] = ClientSecret,
        });
    }

    private static void ConfigureServices(
        IServiceCollection services,
        int requestsPerPeriod,
        int burstFactor)
    {
        services
            .AddAuthentication()
            .AddHmacAuthentication();

        // Single policy: per-endpoint per-client token bucket with uniform limits.
        services.AddHmacRateLimiter(configure: opts =>
        {
            opts.RequestsPerPeriod = requestsPerPeriod;
            opts.BurstFactor = burstFactor;
        });

        services.AddAuthorization();
        services.AddRouting();
    }

    private static void ConfigureApp(IApplicationBuilder app)
    {
        app.UseRouting();

        // UseRateLimiter must be after UseRouting (so GetEndpoint() resolves the matched
        // route for the per-endpoint partition key) and before UseAuthentication (so 429
        // is returned without running the HMAC verification for over-limit requests).
        app.UseRateLimiter();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/api/rl/items", () => Results.Ok())
                .RequireAuthorization()
                .RequireHmacRateLimiting();

            endpoints.MapGet("/api/rl/users", () => Results.Ok())
                .RequireAuthorization()
                .RequireHmacRateLimiting();
        });
    }

    // Creates a new HttpClient routed through the in-memory TestServer.
    // Base address is http://localhost/ — matches the "localhost" host value used by SignedRequestBuilder.
    public HttpClient CreateClient() => _host.GetTestClient();

    public void Dispose()
    {
        _host.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
        _host.Dispose();
    }
}
