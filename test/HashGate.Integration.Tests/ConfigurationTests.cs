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
/// Tests for different configuration scenarios and client setups
/// </summary>
public class ConfigurationTests : IClassFixture<WebApplicationFactory<TestWebApplication>>, IDisposable
{
    private readonly WebApplicationFactory<TestWebApplication> _factory;

    public ConfigurationTests(WebApplicationFactory<TestWebApplication> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["HmacSecrets:Client1"] = "secret1",
                    ["HmacSecrets:Client2"] = "secret2",
                    ["HmacSecrets:AdminClient"] = "admin-secret"
                });
            });
        });
    }

    [Fact]
    public async Task MultipleClients_WithDifferentSecrets_ShouldAllAuthenticate()
    {
        // Arrange
        var client1 = CreateHmacClient("Client1", "secret1");
        var client2 = CreateHmacClient("Client2", "secret2");
        var adminClient = CreateHmacClient("AdminClient", "admin-secret");

        try
        {
            // Act & Assert
            var response1 = await client1.GetAsync("/protected");
            Assert.Equal(HttpStatusCode.OK, response1.StatusCode);

            var response2 = await client2.GetAsync("/protected");
            Assert.Equal(HttpStatusCode.OK, response2.StatusCode);

            var responseAdmin = await adminClient.GetAsync("/protected");
            Assert.Equal(HttpStatusCode.OK, responseAdmin.StatusCode);
        }
        finally
        {
            client1.Dispose();
            client2.Dispose();
            adminClient.Dispose();
        }
    }

    [Fact]
    public async Task Client_WithWrongSecret_ShouldFailAuthentication()
    {
        // Arrange
        var clientWithWrongSecret = CreateHmacClient("Client1", "wrong-secret");

        try
        {
            // Act
            var response = await clientWithWrongSecret.GetAsync("/protected");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        finally
        {
            clientWithWrongSecret.Dispose();
        }
    }

    [Fact]
    public async Task Client_WithCorrectConfiguration_ShouldAccessMultipleEndpoints()
    {
        // Arrange
        var client = CreateHmacClient("Client1", "secret1");

        try
        {
            // Act & Assert - Test multiple endpoints
            var weatherResponse = await client.GetAsync("/weather");
            Assert.Equal(HttpStatusCode.OK, weatherResponse.StatusCode);

            var usersResponse = await client.GetAsync("/users");
            Assert.Equal(HttpStatusCode.OK, usersResponse.StatusCode);

            var authInfoResponse = await client.GetAsync("/auth-info");
            Assert.Equal(HttpStatusCode.OK, authInfoResponse.StatusCode);

            var protectedResponse = await client.GetAsync("/protected");
            Assert.Equal(HttpStatusCode.OK, protectedResponse.StatusCode);
        }
        finally
        {
            client.Dispose();
        }
    }

    [Fact]
    public async Task PostRequest_WithBody_ShouldBeAuthenticated()
    {
        // Arrange
        var client = CreateHmacClient("Client1", "secret1");
        var testUser = new User("Integration", "Test", "integration@test.com");

        try
        {
            // Act
            var response = await client.PostAsJsonAsync("/users", testUser);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var createdUser = await response.Content.ReadFromJsonAsync<User>();
            Assert.NotNull(createdUser);
            Assert.Equal(testUser.First, createdUser.First);
            Assert.Equal(testUser.Last, createdUser.Last);
            Assert.Equal(testUser.Email, createdUser.Email);
        }
        finally
        {
            client.Dispose();
        }
    }

    [Fact]
    public async Task ConfigurationViaOptions_ShouldWork()
    {
        // Arrange
        var services = new ServiceCollection();

        // Configure via options pattern
        services.Configure<HashGate.HttpClient.HmacAuthenticationOptions>(options =>
        {
            options.Client = "Client2";
            options.Secret = "secret2";
            options.SignedHeaders = new[] { "host", "x-timestamp", "x-nonce", "x-content-sha256" };
        });

        services.AddTransient<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var serviceProvider = services.BuildServiceProvider();
        var handler = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var httpClientHandler = new HttpClientHandler();
        handler.InnerHandler = httpClientHandler;

        var client = new System.Net.Http.HttpClient(handler)
        {
            BaseAddress = _factory.Server.BaseAddress
        };

        try
        {
            // Act
            var response = await client.GetAsync("/protected");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            client.Dispose();
        }
    }

    [Fact]
    public async Task EmptyClient_ShouldFailValidation()
    {
        // Arrange & Act
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            var client = CreateHmacClient("", "secret1");
            await client.GetAsync("/protected");
        });

        // Assert
        Assert.Contains("Client", exception.Message);
    }

    [Fact]
    public async Task EmptySecret_ShouldFailValidation()
    {
        // Arrange & Act
        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            var client = CreateHmacClient("Client1", "");
            await client.GetAsync("/protected");
        });

        // Assert
        Assert.Contains("Secret", exception.Message);
    }

    [Theory]
    [InlineData("Client1", "secret1")]
    [InlineData("Client2", "secret2")]
    [InlineData("AdminClient", "admin-secret")]
    public async Task ParameterizedClientTests_ShouldAllSucceed(string clientId, string secret)
    {
        // Arrange
        var client = CreateHmacClient(clientId, secret);

        try
        {
            // Act
            var response = await client.GetAsync("/protected");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            client.Dispose();
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
        // Cleanup is handled by individual test methods disposing their clients
    }
}
