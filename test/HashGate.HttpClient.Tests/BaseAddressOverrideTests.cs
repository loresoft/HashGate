using HashGate.HttpClient.Options;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Tests;

public class BaseAddressOverrideTests
{
    [Fact]
    public void BaseAddress_OverriddenByConfigThenProgramThenUpdater_HasExpectedValueAtEachStage()
    {
        // Arrange
        var configBaseAddress = new Uri("https://config.example.com/");
        var programBaseAddress = new Uri("https://program.example.com/");
        var updaterBaseAddress = new Uri("https://updater.example.com/");

        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Stage 1: base address supplied by the configuration file
                ["HmacClient:Client"] = "test-client",
                ["HmacClient:Secret"] = "test-secret",
                ["HmacClient:BaseAddress"] = configBaseAddress.ToString()
            })
            .Build();

        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();

        // The program.cs options delegate runs after configuration binding, so the value entering
        // the delegate is the config-file value (stage 1). Capture it, then override it (stage 2).
        Uri? configStageBaseAddress = null;

        services.AddHmacClient<TestClient>("HmacClient", configureOptions: options =>
        {
            configStageBaseAddress = options.BaseAddress;

            // Stage 2: overridden in program.cs
            options.BaseAddress = programBaseAddress;
        });

        var serviceProvider = services.BuildServiceProvider();

        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>();
        var updater = serviceProvider.GetRequiredService<OptionsUpdater<HmacAuthenticationOptions>>();

        var optionsName = typeof(TestClient).FullName!;

        // Act - materialize options (applies config binding, then the program.cs override)
        var afterProgramOverride = monitor.Get(optionsName).BaseAddress;

        // Stage 3: overridden again by OptionsUpdater
        updater.Update<TestClient>(options => options.BaseAddress = updaterBaseAddress);

        var afterUpdaterOverride = monitor.Get(optionsName).BaseAddress;

        // Assert - verify the value at each stage
        Assert.Equal(configBaseAddress, configStageBaseAddress);  // Stage 1: from config file
        Assert.Equal(programBaseAddress, afterProgramOverride);   // Stage 2: overridden in program.cs
        Assert.Equal(updaterBaseAddress, afterUpdaterOverride);   // Stage 3: overridden by OptionsUpdater
    }

    private sealed class TestClient(System.Net.Http.HttpClient httpClient)
    {
        public Uri? BaseAddress => httpClient.BaseAddress;
    }
}
