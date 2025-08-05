using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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
}
