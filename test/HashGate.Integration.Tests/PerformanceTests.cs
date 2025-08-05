using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using HashGate.HttpClient;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sample.Shared;
using HttpClient = System.Net.Http.HttpClient;

namespace HashGate.Integration.Tests;

/// <summary>
/// Performance and stress tests for the HashGate integration
/// </summary>
public class PerformanceTests : IClassFixture<WebApplicationFactory<TestWebApplication>>, IDisposable
{
    private readonly WebApplicationFactory<TestWebApplication> _factory;
    private readonly System.Net.Http.HttpClient _authenticatedClient;

    public PerformanceTests(WebApplicationFactory<TestWebApplication> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["HmacSecrets:PerfTestClient"] = "performance-test-secret-key"
                });
            });
        });

        _authenticatedClient = CreateHmacClient("PerfTestClient", "performance-test-secret-key");
    }

    [Fact]
    public async Task HighVolumeSequentialRequests_ShouldMaintainPerformance()
    {
        // Arrange
        const int requestCount = 100;
        var stopwatch = Stopwatch.StartNew();
        var successCount = 0;

        // Act
        for (int i = 0; i < requestCount; i++)
        {
            var response = await _authenticatedClient.GetAsync("/protected");
            if (response.StatusCode == HttpStatusCode.OK)
            {
                successCount++;
            }
            response.Dispose();
        }

        stopwatch.Stop();

        // Assert
        Assert.Equal(requestCount, successCount);
        Assert.True(stopwatch.ElapsedMilliseconds < 30000, $"Requests took too long: {stopwatch.ElapsedMilliseconds}ms");

        var averageTimePerRequest = stopwatch.ElapsedMilliseconds / (double)requestCount;
        Assert.True(averageTimePerRequest < 300, $"Average time per request too high: {averageTimePerRequest}ms");
    }

    [Fact]
    public async Task ConcurrentRequests_ShouldHandleLoad()
    {
        // Arrange
        const int concurrentRequests = 50;
        var stopwatch = Stopwatch.StartNew();

        // Act
        var tasks = Enumerable.Range(0, concurrentRequests)
            .Select(_ => _authenticatedClient.GetAsync("/protected"))
            .ToArray();

        var responses = await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        var successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        Assert.Equal(concurrentRequests, successCount);
        Assert.True(stopwatch.ElapsedMilliseconds < 15000, $"Concurrent requests took too long: {stopwatch.ElapsedMilliseconds}ms");

        // Cleanup
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    [Fact]
    public async Task MixedEndpointLoad_ShouldHandleVariousOperations()
    {
        // Arrange
        const int operationsPerType = 10;
        var stopwatch = Stopwatch.StartNew();
        var tasks = new List<Task<bool>>();

        // Act - Create mixed workload
        // GET requests to different endpoints
        for (int i = 0; i < operationsPerType; i++)
        {
            tasks.Add(PerformGetRequest("/protected"));
            tasks.Add(PerformGetRequest("/weather"));
            tasks.Add(PerformGetRequest("/users"));
            tasks.Add(PerformGetRequest("/auth-info"));
        }

        // POST requests
        for (int i = 0; i < operationsPerType; i++)
        {
            tasks.Add(PerformPostWeatherRequest());
            tasks.Add(PerformPostUserRequest());
        }

        var results = await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        var successCount = results.Count(r => r);
        var expectedCount = operationsPerType * 6; // 4 GET + 2 POST operations per iteration

        Assert.Equal(expectedCount, successCount);
        Assert.True(stopwatch.ElapsedMilliseconds < 20000, $"Mixed operations took too long: {stopwatch.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task LargePayloadRequests_ShouldHandleEfficiently()
    {
        // Arrange
        var largeUser = new User(
            new string('A', 1000),
            new string('B', 1000),
            $"large.payload.{Guid.NewGuid()}@example.com"
        );

        var stopwatch = Stopwatch.StartNew();

        // Act
        const int requestCount = 20;
        var tasks = Enumerable.Range(0, requestCount)
            .Select(_ => _authenticatedClient.PostAsJsonAsync("/users", largeUser))
            .ToArray();

        var responses = await Task.WhenAll(tasks);
        stopwatch.Stop();

        // Assert
        var successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        Assert.Equal(requestCount, successCount);
        Assert.True(stopwatch.ElapsedMilliseconds < 10000, $"Large payload requests took too long: {stopwatch.ElapsedMilliseconds}ms");

        // Cleanup
        foreach (var response in responses)
        {
            response.Dispose();
        }
    }

    [Fact]
    public async Task RepeatedAuthentication_ShouldNotDegradePerformance()
    {
        // Arrange
        const int iterations = 30;
        var times = new List<long>();

        // Act - Test multiple authentication cycles
        for (int i = 0; i < iterations; i++)
        {
            using var client = CreateHmacClient("PerfTestClient", "performance-test-secret-key");

            var stopwatch = Stopwatch.StartNew();
            var response = await client.GetAsync("/protected");
            stopwatch.Stop();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            times.Add(stopwatch.ElapsedMilliseconds);

            response.Dispose();
        }

        // Assert - Performance should remain consistent
        var averageTime = times.Average();
        var maxTime = times.Max();
        var minTime = times.Min();

        Assert.True(averageTime < 500, $"Average authentication time too high: {averageTime}ms");
        Assert.True(maxTime < 1000, $"Max authentication time too high: {maxTime}ms");

        // Performance should not degrade significantly over time
        var firstHalf = times.Take(iterations / 2).Average();
        var secondHalf = times.Skip(iterations / 2).Average();
        var degradationRatio = secondHalf / firstHalf;

        Assert.True(degradationRatio < 2.0, $"Performance degraded too much: {degradationRatio:F2}x");
    }

    private async Task<bool> PerformGetRequest(string endpoint)
    {
        try
        {
            var response = await _authenticatedClient.GetAsync(endpoint);
            var success = response.StatusCode == HttpStatusCode.OK;
            response.Dispose();
            return success;
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> PerformPostWeatherRequest()
    {
        try
        {
            var weather = new Weather
            {
                Date = DateOnly.FromDateTime(DateTime.Today.AddDays(Random.Shared.Next(1, 30))),
                TemperatureC = Random.Shared.Next(-10, 40),
                Summary = $"Weather-{Guid.NewGuid():N}".Substring(0, 10)
            };

            var response = await _authenticatedClient.PostAsJsonAsync("/weather", weather);
            var success = response.StatusCode == HttpStatusCode.OK;
            response.Dispose();
            return success;
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> PerformPostUserRequest()
    {
        try
        {
            var user = new User(
                $"User-{Guid.NewGuid():N}".Substring(0, 10),
                $"Last-{Guid.NewGuid():N}".Substring(0, 10),
                $"user-{Guid.NewGuid():N}@example.com"
            );

            var response = await _authenticatedClient.PostAsJsonAsync("/users", user);
            var success = response.StatusCode == HttpStatusCode.OK;
            response.Dispose();
            return success;
        }
        catch
        {
            return false;
        }
    }

    private System.Net.Http.HttpClient CreateHmacClient(string clientId, string secret)
    {
        var services = new ServiceCollection();

        services.Configure<HashGate.HttpClient.HmacAuthenticationOptions>(options =>
        {
            options.Client = clientId;
            options.Secret = secret;
        });

        services.AddTransient<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var serviceProvider = services.BuildServiceProvider();
        var handler = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var httpClientHandler = new HttpClientHandler();
        handler.InnerHandler = httpClientHandler;

        return new System.Net.Http.HttpClient(handler)
        {
            BaseAddress = _factory.Server.BaseAddress
        };
    }

    public void Dispose()
    {
        _authenticatedClient?.Dispose();
    }
}
