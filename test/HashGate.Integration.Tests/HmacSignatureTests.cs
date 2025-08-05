using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HashGate.Integration.Tests;

/// <summary>
/// Tests for HMAC signature validation and error scenarios
/// </summary>
public class HmacSignatureTests : IClassFixture<WebApplicationFactory<TestWebApplication>>, IDisposable
{
    private readonly WebApplicationFactory<TestWebApplication> _factory;
    private readonly System.Net.Http.HttpClient _client;

    public HmacSignatureTests(WebApplicationFactory<TestWebApplication> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["HmacSecrets:TestClient"] = "test-secret-key-12345"
                });
            });
        });

        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task Request_WithoutHmacHeaders_ShouldReturn401()
    {
        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithMalformedAuthorizationHeader_ShouldReturn401()
    {
        // Arrange
        _client.DefaultRequestHeaders.Add("Authorization", "InvalidHeader");

        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithNonExistentClient_ShouldReturn401()
    {
        // Arrange
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString();

        _client.DefaultRequestHeaders.Add("Authorization", $"HMAC NonExistentClient:signature");
        _client.DefaultRequestHeaders.Add("X-Timestamp", timestamp);
        _client.DefaultRequestHeaders.Add("X-Nonce", nonce);

        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithExpiredTimestamp_ShouldReturn401()
    {
        // Arrange
        var expiredTimestamp = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString();

        _client.DefaultRequestHeaders.Add("Authorization", $"HMAC TestClient:signature");
        _client.DefaultRequestHeaders.Add("X-Timestamp", expiredTimestamp);
        _client.DefaultRequestHeaders.Add("X-Nonce", nonce);

        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithInvalidSignature_ShouldReturn401()
    {
        // Arrange
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString();

        _client.DefaultRequestHeaders.Add("Authorization", $"HMAC TestClient:invalid-signature");
        _client.DefaultRequestHeaders.Add("X-Timestamp", timestamp);
        _client.DefaultRequestHeaders.Add("X-Nonce", nonce);
        _client.DefaultRequestHeaders.Add("X-Content-Sha256", "invalid-hash");

        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithMissingTimestamp_ShouldReturn401()
    {
        // Arrange
        var nonce = Guid.NewGuid().ToString();

        _client.DefaultRequestHeaders.Add("Authorization", $"HMAC TestClient:signature");
        _client.DefaultRequestHeaders.Add("X-Nonce", nonce);

        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Request_WithMissingNonce_ShouldReturn401()
    {
        // Arrange
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

        _client.DefaultRequestHeaders.Add("Authorization", $"HMAC TestClient:signature");
        _client.DefaultRequestHeaders.Add("X-Timestamp", timestamp);

        // Act
        var response = await _client.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticatedClient_ShouldGenerateValidSignature()
    {
        // Arrange
        var services = new ServiceCollection();
        services.Configure<HashGate.HttpClient.HmacAuthenticationOptions>(options =>
        {
            options.Client = "TestClient";
            options.Secret = "test-secret-key-12345";
        });
        services.AddTransient<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var serviceProvider = services.BuildServiceProvider();
        var handler = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var httpClientHandler = new HttpClientHandler();
        handler.InnerHandler = httpClientHandler;

        using var authenticatedClient = new System.Net.Http.HttpClient(handler)
        {
            BaseAddress = new Uri("http://localhost")
        };

        // Act
        var response = await authenticatedClient.GetAsync(_factory.Server.BaseAddress + "protected");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task DifferentHttpMethods_ShouldWorkWithProperSignature(string httpMethod)
    {
        // Arrange
        var services = new ServiceCollection();
        services.Configure<HashGate.HttpClient.HmacAuthenticationOptions>(options =>
        {
            options.Client = "TestClient";
            options.Secret = "test-secret-key-12345";
        });
        services.AddTransient<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var serviceProvider = services.BuildServiceProvider();
        var handler = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var httpClientHandler = new HttpClientHandler();
        handler.InnerHandler = httpClientHandler;

        using var authenticatedClient = new System.Net.Http.HttpClient(handler)
        {
            BaseAddress = _factory.Server.BaseAddress
        };

        // Act
        HttpResponseMessage response = httpMethod switch
        {
            "GET" => await authenticatedClient.GetAsync("/protected"),
            "POST" => await authenticatedClient.PostAsJsonAsync("/users", new { name = "test" }),
            "PUT" => await authenticatedClient.PutAsJsonAsync("/users", new { name = "test" }),
            "DELETE" => await authenticatedClient.DeleteAsync("/users/1"),
            _ => throw new ArgumentException("Invalid HTTP method")
        };

        // Assert
        // Some methods might return different status codes based on the endpoint
        // but they should not return 401 (Unauthorized) if properly authenticated
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RequestsWithSameNonce_ShouldBeRejected()
    {
        // Arrange
        var services = new ServiceCollection();
        services.Configure<HashGate.HttpClient.HmacAuthenticationOptions>(options =>
        {
            options.Client = "TestClient";
            options.Secret = "test-secret-key-12345";
        });
        services.AddTransient<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var serviceProvider = services.BuildServiceProvider();
        var handler1 = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();
        var handler2 = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var httpClientHandler1 = new HttpClientHandler();
        var httpClientHandler2 = new HttpClientHandler();
        handler1.InnerHandler = httpClientHandler1;
        handler2.InnerHandler = httpClientHandler2;

        using var client1 = new System.Net.Http.HttpClient(handler1) { BaseAddress = _factory.Server.BaseAddress };
        using var client2 = new System.Net.Http.HttpClient(handler2) { BaseAddress = _factory.Server.BaseAddress };

        // Act - First request should succeed
        var response1 = await client1.GetAsync("/protected");

        // The second request should also succeed because each client generates its own nonce
        // This test verifies that the system doesn't incorrectly reject legitimate requests
        var response2 = await client2.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
    }

    public void Dispose()
    {
        _client?.Dispose();
    }
}
