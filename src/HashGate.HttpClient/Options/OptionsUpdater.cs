using System.Collections.Concurrent;

using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Options;

/// <summary>
/// Applies runtime mutations to named <typeparamref name="TOptions"/> instances and
/// notifies <see cref="IOptionsMonitor{TOptions}"/> consumers that the options have changed.
/// </summary>
/// <typeparam name="TOptions">The type of options being updated.</typeparam>
/// <param name="cache">The options monitor cache used to invalidate cached options instances.</param>
/// <remarks>
/// <para>
/// This type enables imperative, in-process updates to strongly typed options without
/// re-reading configuration sources. It coordinates three pieces of the options system:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///     A registry of mutation delegates (<c>_mutations</c>), keyed by option name, that describe
///     how a freshly constructed <typeparamref name="TOptions"/> instance should be modified.
///     These delegates are consumed by <see cref="OptionsUpdaterConfigure{TOptions}"/> during
///     configuration of new instances.
///     </description>
///   </item>
///   <item>
///     <description>
///     A registry of <see cref="OptionsUpdateTokenSource{TOptions}"/> instances (<c>_sources</c>),
///     keyed by option name, that supply the change tokens used to signal reloads to
///     <see cref="IOptionsMonitor{TOptions}"/> subscribers.
///     </description>
///   </item>
///   <item>
///     <description>
///     The shared <see cref="IOptionsMonitorCache{TOptions}"/>, which is invalidated so the next
///     resolution rebuilds and re-configures the options instance.
///     </description>
///   </item>
/// </list>
/// <para>
/// The typical flow for <see cref="Update(string?, Action{TOptions})"/> is: store the mutation,
/// remove the stale cached instance so it will be rebuilt on next access, then trigger the change
/// token so active monitors re-resolve the options. When the options are next requested, the
/// options infrastructure creates a new instance and <see cref="OptionsUpdaterConfigure{TOptions}"/>
/// applies the stored mutation, yielding the updated values.
/// </para>
/// <para>
/// Both dictionaries use <see cref="StringComparer.Ordinal"/> and are backed by
/// <see cref="ConcurrentDictionary{TKey, TValue}"/>, making the updater safe for concurrent use.
/// </para>
/// </remarks>
public sealed class OptionsUpdater<TOptions>(IOptionsMonitorCache<TOptions> cache)
    where TOptions : class
{
    private readonly ConcurrentDictionary<string, Action<TOptions>> _mutations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, OptionsUpdateTokenSource<TOptions>> _sources = new(StringComparer.Ordinal);
    private readonly IOptionsMonitorCache<TOptions> _cache = cache;

    /// <summary>
    /// Applies a mutation to the default named options instance and signals the change.
    /// </summary>
    /// <param name="apply">The delegate that mutates a newly constructed options instance.</param>
    public void Update(Action<TOptions> apply)
        => Update(Microsoft.Extensions.Options.Options.DefaultName, apply);

    /// <summary>
    /// Applies a mutation to the specified named options instance and signals the change.
    /// </summary>
    /// <param name="name">The name of the options instance to update, or <see langword="null"/> for the default instance.</param>
    /// <param name="apply">The delegate that mutates a newly constructed options instance.</param>
    /// <remarks>
    /// The mutation is stored for future re-configuration, the cached instance is evicted so it is
    /// rebuilt on next access, and the associated change token is triggered to notify monitors.
    /// </remarks>
    public void Update(string? name, Action<TOptions> apply)
    {
        name ??= Microsoft.Extensions.Options.Options.DefaultName;

        _mutations[name] = apply;
        _cache.TryRemove(name);

        Source(name).Trigger();
    }

    /// <summary>
    /// Removes any stored mutation for the specified named options instance and signals the change,
    /// reverting the options to their originally configured values.
    /// </summary>
    /// <param name="name">The name of the options instance to reset, or <see langword="null"/> for the default instance.</param>
    public void Reset(string? name = null)
    {
        name ??= Microsoft.Extensions.Options.Options.DefaultName;

        _mutations.TryRemove(name, out _);
        _cache.TryRemove(name);

        Source(name).Trigger();
    }

    /// <summary>
    /// Gets or creates the <see cref="OptionsUpdateTokenSource{TOptions}"/> for the specified name.
    /// </summary>
    /// <param name="name">The name of the options instance.</param>
    /// <returns>The change token source associated with <paramref name="name"/>.</returns>
    internal OptionsUpdateTokenSource<TOptions> Source(string name) =>
        _sources.GetOrAdd(name, static n => new OptionsUpdateTokenSource<TOptions>(n));

    /// <summary>
    /// Applies the stored mutation, if any, to the given options instance during configuration.
    /// </summary>
    /// <param name="name">The name of the options instance being configured.</param>
    /// <param name="options">The options instance to mutate.</param>
    internal void Apply(string name, TOptions options)
    {
        if (_mutations.TryGetValue(name, out var apply))
            apply(options);
    }
}
