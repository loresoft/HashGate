#pragma warning disable CS0618 // Type or member is obsolete

using System.Security.Claims;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.Tests;

public class DependencyInjectionExtensionsTests
{
    private readonly IServiceCollection _services;

    public DependencyInjectionExtensionsTests()
    {
        _services = new ServiceCollection();

        // Add required services for testing
        var configuration = new ConfigurationBuilder().Build();
        _services.AddSingleton<IConfiguration>(configuration);
        _services.AddLogging();
    }

    [Fact]
    public void AddHmacAuthentication_WithoutParameters_RegistersDefaultKeyProvider()
    {
        // Act
        var result = _services.AddHmacAuthentication();

        // Assert
        Assert.Same(_services, result);

        var serviceProvider = _services.BuildServiceProvider();
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();

        Assert.NotNull(keyProvider);
        Assert.IsType<HmacKeyProvider>(keyProvider);
    }

    [Fact]
    public void AddHmacAuthentication_WithoutParameters_RegistersOptions()
    {
        // Act
        _services.AddHmacAuthentication();

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationSchemeOptions>>();

        Assert.NotNull(optionsAccessor);
        Assert.NotNull(optionsAccessor.Value);
    }

    [Fact]
    public void AddHmacAuthentication_WithConfiguration_ConfiguresOptions()
    {
        // Arrange
        var expectedToleranceWindow = 10;
        var expectedSecretSectionName = "CustomSecrets";

        // Act
        _services.AddHmacAuthentication(options =>
        {
            options.ToleranceWindow = expectedToleranceWindow;
            options.SecretSectionName = expectedSecretSectionName;
        });

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationSchemeOptions>>();

        Assert.NotNull(optionsAccessor);
        Assert.Equal(expectedToleranceWindow, optionsAccessor.Value.ToleranceWindow);
        Assert.Equal(expectedSecretSectionName, optionsAccessor.Value.SecretSectionName);
    }

    [Fact]
    public void AddHmacAuthentication_WithCustomProvider_RegistersCustomKeyProvider()
    {
        // Act
        var result = _services.AddHmacAuthentication<TestHmacKeyProvider>();

        // Assert
        Assert.Same(_services, result);

        var serviceProvider = _services.BuildServiceProvider();
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();

        Assert.NotNull(keyProvider);
        Assert.IsType<TestHmacKeyProvider>(keyProvider);
    }

    [Fact]
    public void AddHmacAuthentication_WithCustomProviderAndConfiguration_ConfiguresOptionsAndProvider()
    {
        // Arrange
        var expectedToleranceWindow = 15;
        var expectedSecretSectionName = "TestSecrets";

        // Act
        _services.AddHmacAuthentication<TestHmacKeyProvider>(options =>
        {
            options.ToleranceWindow = expectedToleranceWindow;
            options.SecretSectionName = expectedSecretSectionName;
        });

        // Assert
        var serviceProvider = _services.BuildServiceProvider();

        // Check provider registration
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();
        Assert.NotNull(keyProvider);
        Assert.IsType<TestHmacKeyProvider>(keyProvider);

        // Check options configuration
        var optionsAccessor = serviceProvider.GetService<IOptions<HmacAuthenticationSchemeOptions>>();
        Assert.NotNull(optionsAccessor);
        Assert.Equal(expectedToleranceWindow, optionsAccessor.Value.ToleranceWindow);
        Assert.Equal(expectedSecretSectionName, optionsAccessor.Value.SecretSectionName);
    }


    [Fact]
    public void AddHmacAuthentication_MultipleRegistrations_UsesFirstProvider()
    {
        // Act - Register default provider first
        _services.AddHmacAuthentication();

        // Act - Register custom provider second
        _services.AddHmacAuthentication<TestHmacKeyProvider>();

        // Assert - Should use the default provider (first registered) because TryAddScoped only adds if not present
        var serviceProvider = _services.BuildServiceProvider();
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();

        Assert.NotNull(keyProvider);
        Assert.IsType<HmacKeyProvider>(keyProvider);
    }


    [Fact]
    public void AddHmacAuthentication_RegistersAsScopedService()
    {
        // Act
        _services.AddHmacAuthentication();

        // Assert
        var serviceProvider = _services.BuildServiceProvider();

        using var scope1 = serviceProvider.CreateScope();
        using var scope2 = serviceProvider.CreateScope();

        var provider1 = scope1.ServiceProvider.GetService<IHmacKeyProvider>();
        var provider2 = scope1.ServiceProvider.GetService<IHmacKeyProvider>();
        var provider3 = scope2.ServiceProvider.GetService<IHmacKeyProvider>();

        // Same scope should return same instance
        Assert.Same(provider1, provider2);

        // Different scopes should return different instances
        Assert.NotSame(provider1, provider3);
    }

    // Test helper class
    private class TestHmacKeyProvider : IHmacKeyProvider
    {
        public ValueTask<ClaimsIdentity> GenerateClaimsAsync(string client, string? scheme = null, CancellationToken cancellationToken = default)
        {

            Claim[] claims = [new Claim(ClaimTypes.Name, client)];
            var identity = new ClaimsIdentity(claims, scheme);

            return ValueTask.FromResult(identity);
        }

        public ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult<string?>("test-secret");
        }
    }
}
