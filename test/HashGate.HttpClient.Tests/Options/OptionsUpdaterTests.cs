using HashGate.HttpClient.Options;

using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Tests.Options;

public class OptionsUpdaterTests
{
    private static OptionsUpdater<TestOptions> CreateUpdater(out OptionsCache<TestOptions> cache)
    {
        cache = new OptionsCache<TestOptions>();
        return new OptionsUpdater<TestOptions>(cache);
    }

    // Mutations are observed through the public OptionsUpdaterConfigure surface,
    // which applies any mutation the updater stored for a given options name.
    private static TestOptions Configure(OptionsUpdater<TestOptions> updater, string? name, TestOptions options)
    {
        new OptionsUpdaterConfigure<TestOptions>(updater).PostConfigure(name, options);
        return options;
    }

    [Fact]
    public void Update_Default_StoresMutationForDefaultName()
    {
        var updater = CreateUpdater(out _);

        updater.Update(options => options.Value = "mutated");

        var result = Configure(updater, Microsoft.Extensions.Options.Options.DefaultName, new TestOptions { Value = "original" });
        Assert.Equal("mutated", result.Value);
    }

    [Fact]
    public void Update_WithNullName_StoresMutationForDefaultName()
    {
        var updater = CreateUpdater(out _);

        updater.Update(name: null, apply: options => options.Value = "default-mutated");

        var result = Configure(updater, Microsoft.Extensions.Options.Options.DefaultName, new TestOptions());
        Assert.Equal("default-mutated", result.Value);
    }

    [Fact]
    public void Update_WithNamedInstance_DoesNotAffectDefaultInstance()
    {
        var updater = CreateUpdater(out _);

        updater.Update("named", options => options.Value = "named-value");

        var result = Configure(updater, Microsoft.Extensions.Options.Options.DefaultName, new TestOptions { Value = "default" });
        Assert.Equal("default", result.Value);
    }

    [Fact]
    public void Update_EvictsCachedInstanceSoItIsRebuilt()
    {
        var updater = CreateUpdater(out var cache);
        cache.GetOrAdd(Microsoft.Extensions.Options.Options.DefaultName, static () => new TestOptions { Value = "cached" });

        updater.Update(options => options.Value = "updated");

        var rebuilt = cache.GetOrAdd(Microsoft.Extensions.Options.Options.DefaultName, static () => new TestOptions { Value = "fresh" });
        Assert.Equal("fresh", rebuilt.Value);
    }

    [Fact]
    public void Reset_WithName_RemovesStoredMutation()
    {
        var updater = CreateUpdater(out _);
        updater.Update("named", options => options.Value = "temporary");

        updater.Reset("named");

        var result = Configure(updater, "named", new TestOptions { Value = "original" });
        Assert.Equal("original", result.Value);
    }

    [Fact]
    public void Reset_WithNullName_RemovesDefaultMutation()
    {
        var updater = CreateUpdater(out _);
        updater.Update(options => options.Value = "temporary");

        updater.Reset();

        var result = Configure(updater, Microsoft.Extensions.Options.Options.DefaultName, new TestOptions { Value = "original" });
        Assert.Equal("original", result.Value);
    }

    [Fact]
    public void Reset_WhenNoMutationStored_DoesNotThrow()
    {
        var updater = CreateUpdater(out _);

        var exception = Record.Exception(() => updater.Reset("unknown"));

        Assert.Null(exception);
    }

    private sealed class TestOptions
    {
        public string Value { get; set; } = string.Empty;
    }
}
