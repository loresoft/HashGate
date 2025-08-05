using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sample.Shared;

namespace HashGate.Integration.Tests;

/// <summary>
/// Integration tests for HashGate AspNetCore and HttpClient libraries working together
/// </summary>
public class HashGateIntegrationTests : IClassFixture<WebApplicationFactory<TestWebApplication>>, IDisposable
{
    private readonly WebApplicationFactory<TestWebApplication> _factory;
    private readonly System.Net.Http.HttpClient _authenticatedClient;
    private readonly System.Net.Http.HttpClient _unauthenticatedClient;
    private readonly System.Net.Http.HttpClient _invalidClient;

    public HashGateIntegrationTests(WebApplicationFactory<TestWebApplication> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["HmacSecrets:TestClient"] = "test-secret-key-12345",
                    ["HmacSecrets:InvalidClient"] = "invalid-secret-key"
                });
            });
        });

        // Create authenticated client with correct HMAC configuration
        _authenticatedClient = CreateHmacClient("TestClient", "test-secret-key-12345");

        // Create client with invalid credentials
        _invalidClient = CreateHmacClient("InvalidClient", "wrong-secret-key");

        // Create unauthenticated client (no HMAC handler)
        _unauthenticatedClient = _factory.CreateClient();
    }

    private System.Net.Http.HttpClient CreateHmacClient(string clientId, string secret)
    {
        var services = new ServiceCollection();

        // Configure HMAC authentication for the client
        services.Configure<HashGate.HttpClient.HmacAuthenticationOptions>(options =>
        {
            options.Client = clientId;
            options.Secret = secret;
        });

        services.AddTransient<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        var serviceProvider = services.BuildServiceProvider();
        var handler = serviceProvider.GetRequiredService<HashGate.HttpClient.HmacAuthenticationHttpHandler>();

        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("http://localhost")
        }).ConfigureHttpClientWithHandler(handler);
    }

    [Fact]
    public async Task PublicEndpoint_ShouldBeAccessible_WithoutAuthentication()
    {
        // Act
        var response = await _unauthenticatedClient.GetAsync("/public");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Public endpoint", content);
    }

    [Fact]
    public async Task PublicEndpoint_ShouldBeAccessible_WithAuthentication()
    {
        // Act
        var response = await _authenticatedClient.GetAsync("/public");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Public endpoint", content);
    }

    [Fact]
    public async Task ProtectedEndpoint_ShouldRequireAuthentication()
    {
        // Act
        var response = await _unauthenticatedClient.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ProtectedEndpoint_ShouldAllowAccess_WithValidAuthentication()
    {
        // Act
        var response = await _authenticatedClient.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Protected endpoint", content);
    }

    [Fact]
    public async Task ProtectedEndpoint_ShouldDenyAccess_WithInvalidAuthentication()
    {
        // Act
        var response = await _invalidClient.GetAsync("/protected");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetWeather_ShouldReturnWeatherData()
    {
        // Act
        var response = await _authenticatedClient.GetAsync("/weather");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var weather = await response.Content.ReadFromJsonAsync<Weather[]>();
        Assert.NotNull(weather);
        Assert.Equal(3, weather.Length);
        Assert.All(weather, w => Assert.NotEqual(default, w.Date));
    }

    [Fact]
    public async Task PostWeather_ShouldAcceptWeatherData()
    {
        // Arrange
        var newWeather = new Weather
        {
            Date = DateOnly.FromDateTime(DateTime.Today.AddDays(1)),
            TemperatureC = 25,
            Summary = "Sunny"
        };

        // Act
        var response = await _authenticatedClient.PostAsJsonAsync("/weather", newWeather);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var returnedWeather = await response.Content.ReadFromJsonAsync<Weather>();
        Assert.NotNull(returnedWeather);
        Assert.Equal(newWeather.Date, returnedWeather.Date);
        Assert.Equal(newWeather.TemperatureC, returnedWeather.TemperatureC);
        Assert.Equal(newWeather.Summary, returnedWeather.Summary);
    }

    [Fact]
    public async Task GetUsers_ShouldRequireAuthentication()
    {
        // Act - Unauthenticated request
        var unauthResponse = await _unauthenticatedClient.GetAsync("/users");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, unauthResponse.StatusCode);

        // Act - Authenticated request
        var authResponse = await _authenticatedClient.GetAsync("/users");

        // Assert
        Assert.Equal(HttpStatusCode.OK, authResponse.StatusCode);

        var users = await authResponse.Content.ReadFromJsonAsync<User[]>();
        Assert.NotNull(users);
        Assert.Equal(2, users.Length);
        Assert.All(users, u => Assert.NotEmpty(u.First));
    }

    [Fact]
    public async Task PostUsers_ShouldRequireAuthentication()
    {
        // Arrange
        var newUser = new User("John", "Doe", "john.doe@example.com");

        // Act - Unauthenticated request
        var unauthResponse = await _unauthenticatedClient.PostAsJsonAsync("/users", newUser);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, unauthResponse.StatusCode);

        // Act - Authenticated request
        var authResponse = await _authenticatedClient.PostAsJsonAsync("/users", newUser);

        // Assert
        Assert.Equal(HttpStatusCode.OK, authResponse.StatusCode);

        var returnedUser = await authResponse.Content.ReadFromJsonAsync<User>();
        Assert.NotNull(returnedUser);
        Assert.Equal(newUser.First, returnedUser.First);
        Assert.Equal(newUser.Last, returnedUser.Last);
        Assert.Equal(newUser.Email, returnedUser.Email);
    }

    [Fact]
    public async Task AuthInfo_ShouldReturnAuthenticationDetails()
    {
        // Act
        var response = await _authenticatedClient.GetAsync("/auth-info");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var authInfo = await response.Content.ReadFromJsonAsync<dynamic>();
        Assert.NotNull(authInfo);

        var json = authInfo.ToString();
        Assert.Contains("\"IsAuthenticated\":true", json);
        Assert.Contains("TestClient", json);
    }

    [Fact]
    public async Task MultipleSequentialRequests_ShouldAllSucceed()
    {
        // Act & Assert - Multiple requests with the same client
        for (int i = 0; i < 5; i++)
        {
            var response = await _authenticatedClient.GetAsync("/protected");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task ConcurrentRequests_ShouldAllSucceed()
    {
        // Arrange
        const int requestCount = 10;
        var tasks = new List<Task<HttpResponseMessage>>();

        // Act
        for (int i = 0; i < requestCount; i++)
        {
            tasks.Add(_authenticatedClient.GetAsync("/protected"));
        }

        var responses = await Task.WhenAll(tasks);

        // Assert
        Assert.All(responses, response =>
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            response.Dispose();
        });
    }

    [Fact]
    public async Task DifferentHttpMethods_ShouldAllWorkWithAuthentication()
    {
        // Test GET
        var getResponse = await _authenticatedClient.GetAsync("/weather");
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);

        // Test POST
        var weather = new Weather
        {
            Date = DateOnly.FromDateTime(DateTime.Today),
            TemperatureC = 20,
            Summary = "Mild"
        };
        var postResponse = await _authenticatedClient.PostAsJsonAsync("/weather", weather);
        Assert.Equal(HttpStatusCode.OK, postResponse.StatusCode);
    }

    public void Dispose()
    {
        _authenticatedClient?.Dispose();
        _unauthenticatedClient?.Dispose();
        _invalidClient?.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Extension method to configure HttpClient with a message handler
/// </summary>
public static class HttpClientExtensions
{
    public static System.Net.Http.HttpClient ConfigureHttpClientWithHandler(this System.Net.Http.HttpClient client, DelegatingHandler handler)
    {
        // Create a new HttpClient with the handler
        var httpClientHandler = new HttpClientHandler();
        handler.InnerHandler = httpClientHandler;

        var newClient = new System.Net.Http.HttpClient(handler)
        {
            BaseAddress = client.BaseAddress
        };

        // Copy headers from original client
        foreach (var header in client.DefaultRequestHeaders)
        {
            newClient.DefaultRequestHeaders.Add(header.Key, header.Value);
        }

        client.Dispose();
        return newClient;
    }
}
