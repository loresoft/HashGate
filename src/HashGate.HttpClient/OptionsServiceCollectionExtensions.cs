using HashGate.HttpClient.Options;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace HashGate.HttpClient;

/// <summary>
/// Provides extension methods for registering the <see cref="OptionsUpdater{TOptions}"/> infrastructure
/// that enables imperative, in-process updates to named options instances.
/// </summary>
internal static class OptionsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the services required to apply runtime updates to the specified named
    /// <typeparamref name="TOptions"/> instance via <see cref="OptionsUpdater{TOptions}"/>.
    /// </summary>
    /// <typeparam name="TOptions">The type of options to enable runtime updates for.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="name">
    /// The name of the options instance to enable updates for, or <see cref="Microsoft.Extensions.Options.Options.DefaultName"/> for the default instance.
    /// </param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    /// <remarks>
    /// <para>
    /// This method wires up three cooperating pieces of the options system:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>A singleton <see cref="OptionsUpdater{TOptions}"/> that stores runtime mutations and invalidates the cache.</description></item>
    ///   <item><description>An <see cref="IPostConfigureOptions{TOptions}"/> (<see cref="OptionsUpdaterConfigure{TOptions}"/>) that reapplies stored mutations when instances are rebuilt, running after all configure and user post-configure delegates.</description></item>
    ///   <item><description>An <see cref="IOptionsChangeTokenSource{TOptions}"/> for <paramref name="name"/>, resolved from the same updater instance, so <see cref="IOptionsMonitor{TOptions}"/> subscribers are notified of changes.</description></item>
    /// </list>
    /// <para>
    /// The singleton and configure registrations are idempotent, so this method can be called multiple times safely.
    /// A distinct change token source is registered per named options instance.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddOptionsUpdater<TOptions>(this IServiceCollection services, string name)
        where TOptions : class
    {
        if (services is null)
            throw new ArgumentNullException(nameof(services), "Services cannot be null.");

        services.TryAddSingleton<OptionsUpdater<TOptions>>();

        var descriptor = ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, OptionsUpdaterConfigure<TOptions>>();
        services.TryAddEnumerable(descriptor);

        services.AddSingleton<IOptionsChangeTokenSource<TOptions>>(sp =>
            sp.GetRequiredService<OptionsUpdater<TOptions>>().Source(name)
        );

        return services;
    }
}
