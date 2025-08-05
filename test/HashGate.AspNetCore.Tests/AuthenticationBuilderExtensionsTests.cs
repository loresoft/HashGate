using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.Tests;

public class AuthenticationBuilderExtensionsTests
{
    private readonly IServiceCollection _services;
    private readonly AuthenticationBuilder _authenticationBuilder;

    public AuthenticationBuilderExtensionsTests()
    {
        _services = new ServiceCollection();

        // Add required services for HmacKeyProvider
        var configuration = new ConfigurationBuilder().Build();
        _services.AddSingleton<IConfiguration>(configuration);
        _services.AddLogging();

        _authenticationBuilder = _services.AddAuthentication();
    }

    [Fact]
    public async Task AddHmacAuthentication_WithoutParameters_RegistersDefaultSchemeAndProvider()
    {
        // Act
        var result = _authenticationBuilder.AddHmacAuthentication();

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();

        // Verify that the scheme is registered
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = await schemeProvider.GetAllSchemesAsync();
        var hmacScheme = schemes.FirstOrDefault(s => s.Name == HmacAuthenticationSchemeOptions.DefaultScheme);

        Assert.NotNull(hmacScheme);
        Assert.Equal(HmacAuthenticationSchemeOptions.DefaultScheme, hmacScheme.Name);
        Assert.Equal(typeof(HmacAuthenticationHandler), hmacScheme.HandlerType);

        // Verify that HmacKeyProvider is registered
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();
        Assert.NotNull(keyProvider);
        Assert.IsType<HmacKeyProvider>(keyProvider);
    }

    [Fact]
    public async Task AddHmacAuthentication_WithCustomScheme_RegistersCustomScheme()
    {
        // Arrange
        const string customScheme = "CustomHMAC";

        // Act
        var result = _authenticationBuilder.AddHmacAuthentication(customScheme);

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = await schemeProvider.GetAllSchemesAsync();
        var hmacScheme = schemes.FirstOrDefault(s => s.Name == customScheme);

        Assert.NotNull(hmacScheme);
        Assert.Equal(customScheme, hmacScheme.Name);
        Assert.Equal(typeof(HmacAuthenticationHandler), hmacScheme.HandlerType);
    }

    [Fact]
    public void AddHmacAuthentication_WithConfigureOptions_ConfiguresOptions()
    {
        // Arrange
        const int customToleranceWindow = 10;
        const string customSecretSectionName = "CustomSecrets";

        // Act
        var result = _authenticationBuilder.AddHmacAuthentication(options =>
        {
            options.ToleranceWindow = customToleranceWindow;
            options.SecretSectionName = customSecretSectionName;
        });

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();

        var options = serviceProvider
            .GetRequiredService<IOptionsSnapshot<HmacAuthenticationSchemeOptions>>()
            .Get(HmacAuthenticationSchemeOptions.DefaultScheme);

        Assert.Equal(customToleranceWindow, options.ToleranceWindow);
        Assert.Equal(customSecretSectionName, options.SecretSectionName);
    }

    [Fact]
    public void AddHmacAuthentication_WithCustomProvider_RegistersCustomProvider()
    {
        // Act
        var result = _authenticationBuilder.AddHmacAuthentication<TestHmacKeyProvider>();

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();

        Assert.NotNull(keyProvider);
        Assert.IsType<TestHmacKeyProvider>(keyProvider);
    }

    [Fact]
    public async Task AddHmacAuthentication_WithCustomProviderAndScheme_RegistersCorrectly()
    {
        // Arrange
        const string customScheme = "CustomProviderScheme";

        // Act
        var result = _authenticationBuilder.AddHmacAuthentication<TestHmacKeyProvider>(customScheme);

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();

        // Verify scheme
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = await schemeProvider.GetAllSchemesAsync();
        var hmacScheme = schemes.FirstOrDefault(s => s.Name == customScheme);

        Assert.NotNull(hmacScheme);
        Assert.Equal(customScheme, hmacScheme.Name);

        // Verify provider
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();
        Assert.NotNull(keyProvider);
        Assert.IsType<TestHmacKeyProvider>(keyProvider);
    }

    [Fact]
    public void AddHmacAuthentication_WithCustomProviderAndOptions_ConfiguresCorrectly()
    {
        // Arrange
        const int customToleranceWindow = 15;

        // Act
        var result = _authenticationBuilder.AddHmacAuthentication<TestHmacKeyProvider>(options =>
        {
            options.ToleranceWindow = customToleranceWindow;
        });

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();

        // Verify provider
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();

        Assert.NotNull(keyProvider);
        Assert.IsType<TestHmacKeyProvider>(keyProvider);

        // Verify options
        var options = serviceProvider
            .GetRequiredService<IOptionsSnapshot<HmacAuthenticationSchemeOptions>>()
            .Get(HmacAuthenticationSchemeOptions.DefaultScheme);

        Assert.Equal(customToleranceWindow, options.ToleranceWindow);
    }

    [Fact]
    public async Task AddHmacAuthentication_WithAllParameters_ConfiguresEverything()
    {
        // Arrange
        const string customScheme = "FullCustomScheme";
        const string displayName = "Full Custom HMAC";
        const int customToleranceWindow = 20;
        const string customSecretSectionName = "FullCustomSecrets";

        // Act
        var result = _authenticationBuilder.AddHmacAuthentication<TestHmacKeyProvider>(
            customScheme,
            displayName,
            options =>
            {
                options.ToleranceWindow = customToleranceWindow;
                options.SecretSectionName = customSecretSectionName;
            });

        // Assert
        Assert.Same(_authenticationBuilder, result);

        var serviceProvider = _services.BuildServiceProvider();

        // Verify scheme
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = await schemeProvider.GetAllSchemesAsync();
        var hmacScheme = schemes.FirstOrDefault(s => s.Name == customScheme);

        Assert.NotNull(hmacScheme);
        Assert.Equal(customScheme, hmacScheme.Name);
        Assert.Equal(displayName, hmacScheme.DisplayName);

        // Verify provider
        var keyProvider = serviceProvider.GetService<IHmacKeyProvider>();

        Assert.NotNull(keyProvider);
        Assert.IsType<TestHmacKeyProvider>(keyProvider);

        // Verify options
        var options = serviceProvider
            .GetRequiredService<IOptionsSnapshot<HmacAuthenticationSchemeOptions>>()
            .Get(customScheme);

        Assert.Equal(customToleranceWindow, options.ToleranceWindow);
        Assert.Equal(customSecretSectionName, options.SecretSectionName);
    }

    [Fact]
    public async Task AddHmacAuthentication_MultipleRegistrations_AllowsMultipleSchemes()
    {
        // Arrange
        const string scheme1 = "HMAC1";
        const string scheme2 = "HMAC2";

        // Act
        _authenticationBuilder.AddHmacAuthentication(scheme1);
        _authenticationBuilder.AddHmacAuthentication<TestHmacKeyProvider>(scheme2);

        // Assert
        var serviceProvider = _services.BuildServiceProvider();
        var schemeProvider = serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        var schemes = await schemeProvider.GetAllSchemesAsync();

        var hmacScheme1 = schemes.FirstOrDefault(s => s.Name == scheme1);
        var hmacScheme2 = schemes.FirstOrDefault(s => s.Name == scheme2);

        Assert.NotNull(hmacScheme1);
        Assert.NotNull(hmacScheme2);
        Assert.Equal(scheme1, hmacScheme1.Name);
        Assert.Equal(scheme2, hmacScheme2.Name);
    }

    [Fact]
    public void AddHmacAuthentication_RegistersRequiredServices()
    {
        // Act
        _authenticationBuilder.AddHmacAuthentication<TestHmacKeyProvider>();

        // Assert
        var serviceProvider = _services.BuildServiceProvider();

        // Verify all required services are registered
        Assert.NotNull(serviceProvider.GetService<IAuthenticationSchemeProvider>());
        Assert.NotNull(serviceProvider.GetService<IAuthenticationHandlerProvider>());
        Assert.NotNull(serviceProvider.GetService<IHmacKeyProvider>());
        Assert.NotNull(serviceProvider.GetService<IOptionsSnapshot<HmacAuthenticationSchemeOptions>>());
    }
}
