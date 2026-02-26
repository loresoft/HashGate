using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HashGate.AspNetCore;

/// <summary>
/// Extension methods for registering HMAC authentication services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Adds HMAC authentication services to the specified <see cref="IServiceCollection"/> using the default <see cref="HmacKeyProvider"/>.
    /// </summary>
    /// <param name="services">The service collection to add the authentication services to.</param>
    /// <param name="configure">An optional delegate to configure <see cref="HmacAuthenticationSchemeOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> instance so that additional calls can be chained.</returns>
    [Obsolete("Use AuthenticationBuilder.AddHmacAuthentication<TProvider> instead.")]
    public static IServiceCollection AddHmacAuthentication(this IServiceCollection services, Action<HmacAuthenticationSchemeOptions>? configure = null)
        => AddHmacAuthentication<HmacKeyProvider>(services, configure);

    /// <summary>
    /// Adds HMAC authentication services to the specified <see cref="IServiceCollection"/> using a custom <see cref="IHmacKeyProvider"/>.
    /// </summary>
    /// <typeparam name="TProvider">The type of the <see cref="IHmacKeyProvider"/> to use for key management.</typeparam>
    /// <param name="services">The service collection to add the authentication services to.</param>
    /// <param name="configure">An optional delegate to configure <see cref="HmacAuthenticationSchemeOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> instance so that additional calls can be chained.</returns>
    [Obsolete("Use AuthenticationBuilder.AddHmacAuthentication<TProvider> instead.")]
    public static IServiceCollection AddHmacAuthentication<TProvider>(this IServiceCollection services, Action<HmacAuthenticationSchemeOptions>? configure = null)
        where TProvider : class, IHmacKeyProvider
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<HmacAuthenticationSchemeOptions>();
        if (configure != null)
            services.Configure(configure);

        services.TryAddScoped<IHmacKeyProvider, TProvider>();

        return services;
    }
}
