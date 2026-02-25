using Microsoft.AspNetCore.TestHost;

namespace HashGate.Integration.Tests.Fixtures;

// Shared in-memory test server. Wire-up matches Sample.MinimalApi exactly:
//   services.AddAuthentication().AddHmacAuthentication();
//   app.UseAuthentication(); app.UseAuthorization();
//
// Routes exposed:
//   POST   /api/echo          — body-tamper and content-hash-tamper tests
//   GET    /api/echo          — bodyless, timestamp, query-string, method tests
//   DELETE /api/echo          — bodyless DELETE test
//   GET    /api/echo/extended — distinct path for path-tamper tests
//
// Usage: implement IClassFixture<TestApplicationFactory> in test classes.
public sealed class TestApplicationFactory : IDisposable
{
    // Must match appsettings.Test.json "HmacSecrets" section.
    // HmacKeyProvider key lookup: _configuration[$"HmacSecrets:{TestClientId}"]
    public const string TestClientId = "test-client";
    public const string TestClientSecret = "test-secret-abc123";

    // Replay-attack tolerance. Default Options.ToleranceWindow = 5 (minutes).
    // ValidateTimestamp check: Math.Abs((UtcNow - requestTime).TotalMinutes) <= ToleranceWindow
    public const int ToleranceMinutes = 5;

    private readonly IHost _host;

    public TestApplicationFactory()
    {
        _host = new HostBuilder()
            .ConfigureWebHost(ConfigureWebHost)
            .Build();

        _host.Start();
    }

    private static void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseTestServer()
            .UseContentRoot(AppContext.BaseDirectory)
            .ConfigureAppConfiguration(ConfigureAppConfiguration)
            .ConfigureServices(ConfigureServices)
            .Configure(ConfigureApp);
    }

    private static void ConfigureAppConfiguration(WebHostBuilderContext _, IConfigurationBuilder config)
    {
        config.AddJsonFile("appsettings.Test.json", optional: false, reloadOnChange: false);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services
            .AddAuthentication()
            .AddHmacAuthentication();

        services.AddAuthorization();
        services.AddRouting();
    }

    private static void ConfigureApp(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapPost("/api/echo", EchoPostAsync).RequireAuthorization();
            endpoints.MapGet("/api/echo", EchoGet).RequireAuthorization();
            endpoints.MapDelete("/api/echo", EchoDelete).RequireAuthorization();
            endpoints.MapGet("/api/echo/extended", EchoExtended).RequireAuthorization();
        });
    }

    private static async Task<IResult> EchoPostAsync(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        return Results.Ok(new { body });
    }

    private static IResult EchoGet() => Results.Ok();

    private static IResult EchoDelete() => Results.Ok();

    private static IResult EchoExtended() => Results.Ok();

    // Creates a new HttpClient that routes requests through the in-memory TestServer.
    // The base address is http://localhost/ so the Host header seen by the server is "localhost".
    // SignedRequestBuilder uses "localhost" as the host value to match.
    public HttpClient CreateClient() => _host.GetTestClient();

    public void Dispose()
    {
        _host.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
        _host.Dispose();
    }
}
