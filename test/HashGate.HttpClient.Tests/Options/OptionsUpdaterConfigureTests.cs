using HashGate.HttpClient.Options;

using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Tests.Options;

public class OptionsUpdaterConfigureTests
{
    private static OptionsUpdaterConfigure<TestOptions> CreateConfigure(out OptionsUpdater<TestOptions> updater)
    {
        updater = new OptionsUpdater<TestOptions>(new OptionsCache<TestOptions>());
        return new OptionsUpdaterConfigure<TestOptions>(updater);
    }

    [Fact]
    public void PostConfigure_Default_AppliesDefaultMutation()
    {
        var configure = CreateConfigure(out var updater);
        updater.Update(options => options.Value = "mutated");
        var options = new TestOptions { Value = "original" };

        configure.PostConfigure(Microsoft.Extensions.Options.Options.DefaultName, options);

        Assert.Equal("mutated", options.Value);
    }

    [Fact]
    public void PostConfigure_Default_WhenNoMutation_LeavesOptionsUnchanged()
    {
        var configure = CreateConfigure(out _);
        var options = new TestOptions { Value = "original" };

        configure.PostConfigure(Microsoft.Extensions.Options.Options.DefaultName, options);

        Assert.Equal("original", options.Value);
    }

    [Fact]
    public void PostConfigure_Named_AppliesNamedMutation()
    {
        var configure = CreateConfigure(out var updater);
        updater.Update("named", options => options.Value = "named-mutated");
        var options = new TestOptions { Value = "original" };

        configure.PostConfigure("named", options);

        Assert.Equal("named-mutated", options.Value);
    }

    [Fact]
    public void PostConfigure_WithNullName_AppliesDefaultMutation()
    {
        var configure = CreateConfigure(out var updater);
        updater.Update(options => options.Value = "default-mutated");
        var options = new TestOptions { Value = "original" };

        configure.PostConfigure(null, options);

        Assert.Equal("default-mutated", options.Value);
    }

    private sealed class TestOptions
    {
        public string Value { get; set; } = string.Empty;
    }
}
