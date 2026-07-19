using HashGate.HttpClient.Options;

namespace HashGate.HttpClient;

/// <summary>
/// Provides typed convenience methods for applying runtime updates to the named
/// <see cref="HmacAuthenticationOptions"/> instance associated with a typed client.
/// </summary>
public static class OptionsUpdaterExtensions
{
    /// <summary>
    /// Applies a runtime mutation to the <see cref="HmacAuthenticationOptions"/> associated with the
    /// typed client <typeparamref name="TClient"/> and signals the change so the next request uses the updated values.
    /// </summary>
    /// <typeparam name="TClient">The typed client whose options should be updated.</typeparam>
    /// <param name="updater">The updater used to apply the mutation.</param>
    /// <param name="apply">The delegate that mutates the options instance.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="updater"/> or <paramref name="apply"/> is <c>null</c>.
    /// </exception>
    /// <remarks>
    /// The options name is resolved using the same convention as
    /// <see cref="DependencyInjectionExtensions.AddHmacClient{TClient}(Microsoft.Extensions.DependencyInjection.IServiceCollection, string, Action{IServiceProvider, System.Net.Http.HttpClient}, Action{HmacAuthenticationOptions})"/>,
    /// namely <c>typeof(TClient).FullName ?? typeof(TClient).Name</c>.
    /// </remarks>
    public static void Update<TClient>(
        this OptionsUpdater<HmacAuthenticationOptions> updater,
        Action<HmacAuthenticationOptions> apply)
        where TClient : class
    {
        if (updater is null)
            throw new ArgumentNullException(nameof(updater));

        if (apply is null)
            throw new ArgumentNullException(nameof(apply));

        var name = ResolveName<TClient>();
        updater.Update(name, apply);
    }

    /// <summary>
    /// Removes any runtime mutation for the <see cref="HmacAuthenticationOptions"/> associated with the typed client
    /// <typeparamref name="TClient"/>, reverting it to its originally configured values, and signals the change.
    /// </summary>
    /// <typeparam name="TClient">The typed client whose options should be reset.</typeparam>
    /// <param name="updater">The updater used to reset the mutation.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="updater"/> is <c>null</c>.</exception>
    public static void Reset<TClient>(this OptionsUpdater<HmacAuthenticationOptions> updater)
        where TClient : class
    {
        if (updater is null)
            throw new ArgumentNullException(nameof(updater));

        var name = ResolveName<TClient>();
        updater.Reset(name);
    }

    private static string ResolveName<TClient>()
        where TClient : class
        => typeof(TClient).FullName ?? typeof(TClient).Name;
}
