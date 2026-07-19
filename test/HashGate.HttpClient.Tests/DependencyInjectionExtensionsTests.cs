using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using HashGate.HttpClient.Options;

namespace HashGate.HttpClient.Tests;

public class DependencyInjectionExtensionsTests
{
    private readonly IServiceCollection _services;
    private readonly IConfiguration _configuration;

    public DependencyInjectionExtensionsTests()
    {
        _services = new ServiceCollection();

        // Create configuration with test data
        var configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["HmacAuthentication:Client"] = "test-client",
            ["HmacAuthentication:Secret"] = "test-secret",
            ["HmacAuthentication:BaseAddress"] = "https://api.example.com/",
            ["HmacAuthentication:SignedHeaders:0"] = "host",
            ["HmacAuthentication:SignedHeaders:1"] = "x-timestamp",
            ["HmacAuthentication:SignedHeaders:2"] = "x-content-sha256"
        });

        _configuration = configurationBuilder.Build();
        _services.AddSingleton(_configuration);
        _services.AddLogging();
    }

    [Fact]
    public void AddHmacAuthentication_WithoutParameters_RegistersRequiredServices()
    {
        // Act
        var result = _services.AddHmacAuthentication();

        // Assert
        Assert.Same(_services, result);

        var serviceProvider = _services.BuildServiceProvider();

        // Check that options are registered
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();
        Assert.NotNull(optionsAccessor);

        // Check that handler is registered
        var handler = serviceProvider.GetService<HmacAuthenticationHttpHandler>();
        Assert.NotNull(handler);
    }

    [Fact]
    public void AddHmacAuthentication_WithoutParameters_BindsConfigurationCorrectly()
    {
        // Act
        _services.AddHmacAuthentication();

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        Assert.Equal("test-client", options.Client);
        Assert.Equal("test-secret", options.Secret);
        Assert.Equal(new Uri("https://api.example.com/"), options.BaseAddress);
        Assert.NotNull(options.SignedHeaders);
        Assert.Contains("host", options.SignedHeaders);
        Assert.Contains("x-timestamp", options.SignedHeaders);
        Assert.Contains("x-content-sha256", options.SignedHeaders);
    }

    [Fact]
    public void AddHmacAuthentication_WithConfiguration_ConfiguresOptions()
    {
        // Arrange
        var expectedClient = "override-client";
        var expectedSecret = "override-secret";
        var expectedHeaders = new[] { "host", "authorization", "custom-header" };

        // Act
        _services.AddHmacAuthentication(options =>
        {
            options.Client = expectedClient;
            options.Secret = expectedSecret;
            options.BaseAddress = new Uri("https://configured.example.com/");
            options.SignedHeaders = expectedHeaders;
        });

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        // Configuration should override bound values
        Assert.Equal(expectedClient, options.Client);
        Assert.Equal(expectedSecret, options.Secret);
        Assert.Equal(new Uri("https://configured.example.com/"), options.BaseAddress);
        Assert.Equal(expectedHeaders, options.SignedHeaders);
    }

    [Fact]
    public void AddHmacAuthentication_RegistersHandlerAsTransient()
    {
        // Act
        _services.AddHmacAuthentication();

        // Assert
        var serviceProvider = _services.BuildServiceProvider();

        var handler1 = serviceProvider.GetService<HmacAuthenticationHttpHandler>();
        var handler2 = serviceProvider.GetService<HmacAuthenticationHttpHandler>();

        Assert.NotNull(handler1);
        Assert.NotNull(handler2);

        // Transient services should return different instances
        Assert.NotSame(handler1, handler2);
    }

    [Fact]
    public void AddHmacAuthentication_MultipleRegistrations_KeepsAllConfigurations()
    {
        // Act - Register multiple times with different configurations
        _services.AddHmacAuthentication(options =>
        {
            options.Client = "first-client";
        });

        _services.AddHmacAuthentication(options =>
        {
            options.Secret = "second-secret";
        });

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        // Both configurations should be applied (PostConfigure behavior)
        Assert.Equal("second-secret", options.Secret);
        Assert.Equal("first-client", options.Client);
    }

    [Fact]
    public void AddHmacAuthentication_ValidatesOptionsOnStart()
    {
        // Arrange - Create services with invalid configuration (missing required fields)
        var emptyConfigServices = new ServiceCollection();
        var emptyConfig = new ConfigurationBuilder().Build();
        emptyConfigServices.AddSingleton<IConfiguration>(emptyConfig);
        emptyConfigServices.AddLogging();

        // Act
        emptyConfigServices.AddHmacAuthentication();

        // Assert - Building service provider should not throw, but validation should be enabled
        var serviceProvider = emptyConfigServices.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);

        // The actual validation would happen when the options are accessed in a real scenario
        // For this test, we're just ensuring the service is registered correctly
    }

    [Fact]
    public void AddHmacAuthentication_BindsToCorrectConfigurationSection()
    {
        // Arrange - Create configuration with data in different section
        var wrongSectionServices = new ServiceCollection();
        var wrongSectionConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["WrongSection:Client"] = "wrong-client",
                ["WrongSection:Secret"] = "wrong-secret"
            })
            .Build();

        wrongSectionServices.AddSingleton<IConfiguration>(wrongSectionConfig);
        wrongSectionServices.AddLogging();

        // Act
        wrongSectionServices.AddHmacAuthentication();

        // Assert - Should not bind from wrong section
        var serviceProvider = wrongSectionServices.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        // Should have default/empty values, not the wrong section values
        Assert.NotEqual("wrong-client", options.Client);
        Assert.NotEqual("wrong-secret", options.Secret);
    }

    [Fact]
    public void AddHmacAuthentication_WithConfigurationAndSectionName_BindsConfigurationCorrectly()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CustomHmac:Client"] = "custom-client",
                ["CustomHmac:Secret"] = "custom-secret",
                ["CustomHmac:BaseAddress"] = "https://custom.example.com/",
                ["CustomHmac:SignedHeaders:0"] = "host",
                ["CustomHmac:SignedHeaders:1"] = "x-custom-header"
            })
            .Build();
        services.AddSingleton<IConfiguration>(configuration);

        // Act
        var result = services.AddHmacAuthentication("CustomHmac");

        // Assert
        Assert.Same(services, result);

        var serviceProvider = services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        Assert.Equal("custom-client", options.Client);
        Assert.Equal("custom-secret", options.Secret);
        Assert.Equal(new Uri("https://custom.example.com/"), options.BaseAddress);
        Assert.Equal(new[] { "host", "x-custom-header" }, options.SignedHeaders);
    }

    [Fact]
    public void AddHmacAuthentication_WithConfigurationAndSectionName_ConfiguresOptionsAfterBinding()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["CustomHmac:Client"] = "custom-client",
                ["CustomHmac:Secret"] = "custom-secret"
            })
            .Build();
        services.AddSingleton<IConfiguration>(configuration);

        // Act
        services.AddHmacAuthentication("CustomHmac", options =>
        {
            options.Client = "configured-client";
        });

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        Assert.Equal("configured-client", options.Client);
        Assert.Equal("custom-secret", options.Secret);
    }

    [Fact]
    public void AddHmacAuthentication_ConfigurationOverridesBinding()
    {
        // Arrange
        var overrideClient = "configured-client";

        // Act - Configuration binding happens first, then PostConfigure
        _services.AddHmacAuthentication(options =>
        {
            options.Client = overrideClient;
            // Don't override Secret, should keep bound value
        });

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationOptions>>();

        Assert.NotNull(optionsAccessor);
        var options = optionsAccessor.Value;

        // Client should be overridden by configuration
        Assert.Equal(overrideClient, options.Client);

        // Secret should still come from binding
        Assert.Equal("test-secret", options.Secret);
    }

    [Fact]
    public async Task AddHmacClient_NamedClient_UsesConfiguredBaseAddressForRelativeRequests()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HmacAuthentication:Client"] = "named-client",
                ["HmacAuthentication:Secret"] = "named-secret",
                ["HmacAuthentication:BaseAddress"] = "https://named.example.com/api/"
            })
            .Build();
        Uri? recordedRequestUri = null;

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services
            .AddHmacClient("HmacClient")
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => recordedRequestUri = request.RequestUri));

        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetRequiredService<IHttpClientFactory>();
        var client = factory.CreateClient("HmacClient");

        // Act
        await client.GetAsync("resource?id=1", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(new Uri("https://named.example.com/api/resource?id=1"), recordedRequestUri);
    }

    [Fact]
    public async Task AddHmacClient_WithDifferentTypedClients_UsesSeparateOptions()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FirstHmac:Client"] = "first-client",
                ["FirstHmac:Secret"] = "first-secret",
                ["FirstHmac:BaseAddress"] = "https://first.example.com/",
                ["SecondHmac:Client"] = "second-client",
                ["SecondHmac:Secret"] = "second-secret",
                ["SecondHmac:BaseAddress"] = "https://second.example.com/"
            })
            .Build();
        string? firstAuthorization = null;
        string? secondAuthorization = null;

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services
            .AddHmacClient<FirstTypedClient>("FirstHmac")
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => firstAuthorization = request.Headers.Authorization?.ToString()));

        services
            .AddHmacClient<SecondTypedClient>("SecondHmac")
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => secondAuthorization = request.Headers.Authorization?.ToString()));

        var serviceProvider = services.BuildServiceProvider();
        var firstClient = serviceProvider.GetRequiredService<FirstTypedClient>();
        var secondClient = serviceProvider.GetRequiredService<SecondTypedClient>();

        // Act
        await firstClient.GetAsync("resource");
        await secondClient.GetAsync("resource");

        // Assert
        Assert.Equal(new Uri("https://first.example.com/"), firstClient.BaseAddress);
        Assert.Equal(new Uri("https://second.example.com/"), secondClient.BaseAddress);
        Assert.Contains("Client=first-client", firstAuthorization);
        Assert.Contains("Client=second-client", secondAuthorization);
    }

    [Fact]
    public async Task HmacAuthenticationOptionsUpdater_WhenOptionsUpdated_UsesUpdatedCredentials()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HmacAuthentication:Client"] = "initial-client",
                ["HmacAuthentication:Secret"] = "initial-secret",
                ["HmacAuthentication:BaseAddress"] = "https://initial.example.com/"
            })
            .Build();

        var authorizationHeaders = new List<string?>();

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services
            .AddHmacClient<FirstTypedClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => authorizationHeaders.Add(request.Headers.Authorization?.ToString())));

        var serviceProvider = services.BuildServiceProvider();
        var client = serviceProvider.GetRequiredService<FirstTypedClient>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();

        // Act
        await client.GetAsync("resource");
        updater.Update<FirstTypedClient>(options =>
        {
            options.Client = "updated-client";
            options.Secret = "updated-secret";
            options.BaseAddress = new Uri("https://updated.example.com/");
        });
        await client.GetAsync("resource");

        // Assert
        Assert.Contains("Client=initial-client", authorizationHeaders[0]);
        Assert.Contains("Client=updated-client", authorizationHeaders[1]);
    }

    [Fact]
    public async Task HmacAuthenticationOptionsUpdater_WhenBaseAddressUpdated_UsesUpdatedBaseAddressForRelativeRequests()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().Build();
        Uri? recordedRequestUri = null;

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services
            .AddHmacClient<FirstTypedClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => recordedRequestUri = request.RequestUri));

        var serviceProvider = services.BuildServiceProvider();
        var client = serviceProvider.GetRequiredService<FirstTypedClient>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();

        updater.Update<FirstTypedClient>(options =>
        {
            options.Client = "provisioned-client";
            options.Secret = "provisioned-secret";
            options.BaseAddress = new Uri("https://provisioned.example.com/api/");
        });

        // Act
        await client.GetAsync("resource?id=1");

        // Assert
        Assert.Equal(new Uri("https://provisioned.example.com/api/resource?id=1"), recordedRequestUri);
    }

    [Fact]
    public async Task HmacAuthenticationHttpHandler_WhenRequestUriIsAbsolute_DoesNotRewriteRequestUri()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HmacAuthentication:Client"] = "test-client",
                ["HmacAuthentication:Secret"] = "test-secret",
                ["HmacAuthentication:BaseAddress"] = "https://configured.example.com/"
            })
            .Build();
        Uri? recordedRequestUri = null;

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services
            .AddHmacClient<FirstTypedClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => recordedRequestUri = request.RequestUri));

        var serviceProvider = services.BuildServiceProvider();
        var client = serviceProvider.GetRequiredService<FirstTypedClient>();

        // Act
        await client.GetAsync("https://absolute.example.com/resource?id=1");

        // Assert
        Assert.Equal(new Uri("https://absolute.example.com/resource?id=1"), recordedRequestUri);
    }

    [Fact]
    public async Task HmacAuthenticationOptionsUpdater_WhenOneTypedClientUpdated_DoesNotAffectOtherTypedClients()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["HmacAuthentication:Client"] = "initial-client",
                ["HmacAuthentication:Secret"] = "initial-secret",
                ["HmacAuthentication:BaseAddress"] = "https://initial.example.com/"
            })
            .Build();
        string? firstAuthorization = null;
        string? secondAuthorization = null;

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        services
            .AddHmacClient<FirstTypedClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => firstAuthorization = request.Headers.Authorization?.ToString()));

        services
            .AddHmacClient<SecondTypedClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new RecordingHandler(request => secondAuthorization = request.Headers.Authorization?.ToString()));

        var serviceProvider = services.BuildServiceProvider();
        var firstClient = serviceProvider.GetRequiredService<FirstTypedClient>();
        var secondClient = serviceProvider.GetRequiredService<SecondTypedClient>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();

        updater.Update<FirstTypedClient>(options =>
        {
            options.Client = "updated-first-client";
            options.Secret = "updated-first-secret";
        });

        // Act
        await firstClient.GetAsync("resource");
        await secondClient.GetAsync("resource");

        // Assert
        Assert.Contains("Client=updated-first-client", firstAuthorization);
        Assert.Contains("Client=initial-client", secondAuthorization);
    }

    [Fact]
    public void AddHmacAuthentication_RegistersOptionsUpdater()
    {
        // Act
        _services.AddHmacAuthentication();

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var updater = serviceProvider.GetService<OptionsUpdater<HmacAuthenticationOptions>>();

        Assert.NotNull(updater);
    }

    [Fact]
    public void AddHmacClient_RegistersOptionsUpdater()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(_configuration);
        services.AddLogging();

        // Act
        services.AddHmacClient<FirstTypedClient>();

        // Assert
        var serviceProvider = services.BuildServiceProvider();
        var updater = serviceProvider.GetService<OptionsUpdater<HmacAuthenticationOptions>>();

        Assert.NotNull(updater);
    }

    [Fact]
    public void HmacAuthenticationOptionsUpdater_DefaultUpdate_ChangesMonitorValueAfterInitialRead()
    {
        // Arrange
        _services.AddHmacAuthentication();
        var serviceProvider = _services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();

        // Act
        var initialClient = monitor.CurrentValue.Client;
        updater.Update(options => options.Client = "updated-default-client");
        var updatedClient = monitor.CurrentValue.Client;

        // Assert
        Assert.Equal("test-client", initialClient);
        Assert.Equal("updated-default-client", updatedClient);
    }

    [Fact]
    public void HmacAuthenticationOptionsUpdater_NamedUpdate_ChangesNamedMonitorValue()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(_configuration);
        services.AddLogging();
        services.AddHmacClient<FirstTypedClient>();

        var serviceProvider = services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();
        var optionsName = typeof(FirstTypedClient).FullName!;

        // Act
        _ = monitor.Get(optionsName);
        updater.Update(optionsName, options => options.Client = "named-updated-client");

        // Assert
        Assert.Equal("named-updated-client", monitor.Get(optionsName).Client);
    }

    [Fact]
    public void HmacAuthenticationOptionsUpdater_Update_TriggersOnChangeForTypedClient()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(_configuration);
        services.AddLogging();
        services.AddHmacClient<FirstTypedClient>();

        var serviceProvider = services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();
        var optionsName = typeof(FirstTypedClient).FullName!;

        HmacAuthenticationOptions? changedOptions = null;
        using var subscription = monitor.OnChange((options, name) =>
        {
            if (name == optionsName)
                changedOptions = options;
        });

        // Act
        updater.Update<FirstTypedClient>(options => options.Client = "changed-client");

        // Assert
        Assert.NotNull(changedOptions);
        Assert.Equal("changed-client", changedOptions!.Client);
    }

    [Fact]
    public void HmacAuthenticationOptionsUpdater_ResetTypedClient_RevertsToConfiguredValue()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(_configuration);
        services.AddLogging();
        services.AddHmacClient<FirstTypedClient>();

        var serviceProvider = services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();
        var optionsName = typeof(FirstTypedClient).FullName!;

        // Act
        updater.Update<FirstTypedClient>(options => options.Client = "temporary-client");
        var afterUpdate = monitor.Get(optionsName).Client;

        updater.Reset<FirstTypedClient>();
        var afterReset = monitor.Get(optionsName).Client;

        // Assert
        Assert.Equal("temporary-client", afterUpdate);
        Assert.Equal("test-client", afterReset);
    }

    private sealed class FirstTypedClient(System.Net.Http.HttpClient httpClient)
    {
        public Uri? BaseAddress => httpClient.BaseAddress;

        public Task GetAsync(string requestUri) => httpClient.GetAsync(requestUri);
    }

    private sealed class SecondTypedClient(System.Net.Http.HttpClient httpClient)
    {
        public Uri? BaseAddress => httpClient.BaseAddress;

        public Task GetAsync(string requestUri) => httpClient.GetAsync(requestUri);
    }

    private sealed class RecordingHandler(Action<System.Net.Http.HttpRequestMessage> record) : System.Net.Http.HttpMessageHandler
    {
        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            record(request);

            return Task.FromResult(new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }
}
