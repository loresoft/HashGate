using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace HashGate.HttpClient.Options;

/// <summary>
/// Provides a change token source for <typeparamref name="TOptions"/> that signals
/// consumers when the associated named options should be reloaded.
/// </summary>
/// <typeparam name="TOptions">The type of options this token source is associated with.</typeparam>
/// <param name="name">The name of the options instance this token source tracks.</param>
public sealed class OptionsUpdateTokenSource<TOptions>(string name)
    : IOptionsChangeTokenSource<TOptions>
{
    private ConfigurationReloadToken _token = new();

    /// <summary>
    /// Gets the name of the options instance this token source tracks.
    /// </summary>
    public string Name { get; } = name;

    /// <summary>
    /// Gets the current <see cref="IChangeToken"/> used to signal an options reload.
    /// </summary>
    /// <returns>The active change token.</returns>
    public IChangeToken GetChangeToken() => _token;

    /// <summary>
    /// Signals a change by swapping in a new change token and triggering the reload
    /// callbacks registered on the previous token.
    /// </summary>
    internal void Trigger()
    {
        ConfigurationReloadToken token = new();
        Interlocked.Exchange(ref _token, token).OnReload();
    }
}
