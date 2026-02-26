// RateLimitedApplicationFactory — in-memory TestServer wired with both HMAC authentication
// and client rate limiting for end-to-end rate limit scenario tests.
//
// Middleware order (important):
//   app.UseRouting()        → endpoint matched; GetEndpoint() resolves for partition key
//   app.UseRateLimiter()    → rate limit enforced using client ID from Authorization header
//   app.UseAuthentication() → HMAC signature verified (only reached when not rate-limited)
//   app.UseAuthorization()  → RequireAuthorization() policy checked
//
// Rate limits are configured uniformly for all clients via RequestLimitOptions:
//   TokenLimit = RequestsPerPeriod × BurstFactor
//
// Exposed endpoints (both require HMAC auth + rate limiting):
//   GET /api/rl/items   — primary endpoint for most tests
//   GET /api/rl/users   — secondary endpoint for per-endpoint independence tests
//
// Usage: instantiate directly in each test method with the desired limits, then dispose.
// Each instance creates a fresh in-memory server with independent token bucket state.

using Microsoft.AspNetCore.TestHost;

namespace HashGate.Integration.Tests.Fixtures;

public sealed class RateLimitedApplicationFactory : IDisposable
{
    // ---------------------------------------------------------------------------
    // Shared client credentials — used by every test scenario.
    // Each test creates its own factory instance so token bucket state never
    // bleeds across tests (each fresh server starts with empty buckets).
    // ---------------------------------------------------------------------------

    public const string ClientId = "rl-test";
    public const string ClientSecret = "rl-test-secret";

    // Retry-After: Math.Max(1, (int)Math.Min(5, Period.TotalSeconds))
    //   = Math.Max(1, (int)Math.Min(5, 60.0)) = 5  (for the default 1-minute period)
    public const string ExpectedRetryAfter = "5";

    // Response body written by RequestLimitExtensions.OnRejectedAsync
    public const string ExpectedRejectionBody = "Rate limit exceeded. Retry shortly.";

    // ---------------------------------------------------------------------------
    // Host setup
    // ---------------------------------------------------------------------------

    private readonly IHost _host;

    /// <param name="requestsPerPeriod">
    /// Tokens replenished each period; also sets the base rate for the bucket ceiling.
    /// <c>TokenLimit = requestsPerPeriod × burstFactor</c>.
    /// </param>
    /// <param name="burstFactor">
    /// Multiplier for the bucket ceiling. Use 1 to disable bursting.
    /// </param>
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
