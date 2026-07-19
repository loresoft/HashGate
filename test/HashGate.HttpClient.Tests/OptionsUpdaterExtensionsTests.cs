using HashGate.HttpClient.Options;

using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Tests;

public class OptionsUpdaterExtensionsTests
{
    private static OptionsUpdater<HmacAuthenticationOptions> CreateUpdater()
        => new(new OptionsCache<HmacAuthenticationOptions>());

    [Fact]
    public void Update_WhenUpdaterIsNull_ThrowsArgumentNullException()
    {
        OptionsUpdater<HmacAuthenticationOptions> updater = null!;

        Assert.Throws<ArgumentNullException>(
            () => updater.Update<TestClient>(options => options.Client = "value"));
    }

    [Fact]
    public void Update_WhenApplyIsNull_ThrowsArgumentNullException()
    {
        var updater = CreateUpdater();

        Assert.Throws<ArgumentNullException>(
            () => updater.Update<TestClient>(null!));
    }

    [Fact]
    public void Update_AppliesMutationToTypedClientOptionsName()
    {
        var updater = CreateUpdater();

        updater.Update<TestClient>(options => options.Client = "typed-client");

        var options = Configure(updater, typeof(TestClient).FullName!, new HmacAuthenticationOptions());
        Assert.Equal("typed-client", options.Client);
    }

    [Fact]
    public void Reset_WhenUpdaterIsNull_ThrowsArgumentNullException()
    {
        OptionsUpdater<HmacAuthenticationOptions> updater = null!;

        Assert.Throws<ArgumentNullException>(() => updater.Reset<TestClient>());
    }

    [Fact]
    public void Reset_RemovesMutationForTypedClientOptionsName()
    {
        var updater = CreateUpdater();
        updater.Update<TestClient>(options => options.Client = "temporary");

        updater.Reset<TestClient>();

        var options = Configure(updater, typeof(TestClient).FullName!, new HmacAuthenticationOptions { Client = "original" });
        Assert.Equal("original", options.Client);
    }

    // Mutations are observed through the public OptionsUpdaterConfigure surface,
    // which applies any mutation the updater stored for a given options name.
    private static HmacAuthenticationOptions Configure(
        OptionsUpdater<HmacAuthenticationOptions> updater,
        string name,
        HmacAuthenticationOptions options)
    {
        new OptionsUpdaterConfigure<HmacAuthenticationOptions>(updater).PostConfigure(name, options);
        return options;
    }

    private sealed class TestClient
    {
    }
}
