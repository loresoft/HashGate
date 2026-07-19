using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Options;

/// <summary>
/// Configures instances of <typeparamref name="TOptions"/> by applying any pending
/// mutations registered with the associated <see cref="OptionsUpdater{TOptions}"/>.
/// </summary>
/// <typeparam name="TOptions">The type of options being configured.</typeparam>
/// <param name="updater">The updater that holds the mutations to apply to the options instance.</param>
public sealed class OptionsUpdaterConfigure<TOptions>(OptionsUpdater<TOptions> updater)
    : IPostConfigureOptions<TOptions> where TOptions : class
{
    /// <summary>
    /// Post-configures the default named options instance.
    /// </summary>
    /// <param name="name">The name of the options instance to configure. If null, the default name is used.</param>
    /// <param name="options">The options instance to configure.</param>
    public void PostConfigure(string? name, TOptions options)
        => updater.Apply(name ?? Microsoft.Extensions.Options.Options.DefaultName, options);
}
