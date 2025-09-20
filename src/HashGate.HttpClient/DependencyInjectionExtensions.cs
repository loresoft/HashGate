using Microsoft.Extensions.DependencyInjection;

namespace HashGate.HttpClient;

/// <summary>
/// Provides extension methods for configuring HMAC authentication services in the dependency injection container.
/// </summary>
public static class DependencyInjectionExtensions
{
    /// <summary>
    /// Adds HMAC authentication services to the specified <see cref="IServiceCollection"/>.
    /// This method configures the required services for HTTP client-side HMAC authentication,
    /// including options binding from configuration and the HTTP message handler.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configure">
    /// An optional action to configure the <see cref="HmacAuthenticationOptions"/>.
    /// This allows for programmatic configuration in addition to configuration binding.
    /// If provided, this configuration will be applied after the configuration binding.
    /// </param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    /// <remarks>
    /// <para>
    /// This method performs the following registrations:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Configures <see cref="HmacAuthenticationOptions"/> with automatic binding to the "HmacAuthentication" configuration section</description></item>
    /// <item><description>Enables validation of options on application startup</description></item>
    /// <item><description>Registers the <see cref="HmacAuthenticationHttpHandler"/> as a transient service for HTTP message processing</description></item>
    /// </list>
    /// <para>
    /// The configuration is automatically bound from the "HmacAuthentication" section in your application configuration.
    /// Ensure your appsettings.json includes the required Client and Secret values:
    /// </para>
    /// <code>
    /// {
    ///   "HmacAuthentication": {
    ///     "Client": "your-client-id",
    ///     "Secret": "your-secret-key",
    ///     "SignedHeaders": ["host", "x-timestamp", "x-content-sha256"]
    ///   }
    /// }
    /// </code>
    /// </remarks>
    /// <example>
    /// <para>Basic usage with configuration binding:</para>
    /// <code>
    /// services.AddHmacAuthentication();
    /// </code>
    /// <para>Usage with additional programmatic configuration:</para>
    /// <code>
    /// services.AddHmacAuthentication(options =>
    /// {
    ///     options.Client = "override-client-id";
    ///     options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256", "content-type"];
    /// });
    /// </code>
    /// <para>Usage with HttpClient factory:</para>
    /// <code>
    /// services.AddHmacAuthentication();
    /// services.AddHttpClient("ApiClient")
    ///     .AddHttpMessageHandler&lt;HmacAuthenticationHttpHandler&gt;();
    /// </code>
    /// </example>
    public static IServiceCollection AddHmacAuthentication(
        this IServiceCollection services,
        Action<HmacAuthenticationOptions>? configure = null)
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        services
            .AddOptions<HmacAuthenticationOptions>()
            .BindConfiguration(HmacAuthenticationOptions.ConfigurationName)
            .ValidateOnStart();

        if (configure != null)
            services.PostConfigure(configure);

        services.AddTransient<HmacAuthenticationHttpHandler>();

        return services;
    }
}
