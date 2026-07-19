using HashGate.HttpClient.Options;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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
    /// <param name="configureOptions">
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
    /// <item><description>Registers the <see cref="HmacAuthenticationHttpHandler"/> as a transient service for HTTP message processing</description></item>
    /// <item><description>Registers the runtime options updater so provisioned settings can be applied after startup</description></item>
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
    ///     "BaseAddress": "https://api.example.com",
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
        Action<HmacAuthenticationOptions>? configureOptions = null)
        => services.AddHmacAuthentication(HmacAuthenticationOptions.ConfigurationName, configureOptions);

    /// <summary>
    /// Adds HMAC authentication services to the specified <see cref="IServiceCollection"/> using the specified configuration section.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configurationSection">The name of the configuration section to bind to <see cref="HmacAuthenticationOptions"/>.</param>
    /// <param name="configureOptions">
    /// An optional action to configure the <see cref="HmacAuthenticationOptions"/> after configuration binding.
    /// </param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> or <paramref name="configurationSection"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="configurationSection"/> is empty or whitespace.</exception>
    public static IServiceCollection AddHmacAuthentication(
        this IServiceCollection services,
        string configurationSection,
        Action<HmacAuthenticationOptions>? configureOptions = null)
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        if (string.IsNullOrWhiteSpace(configurationSection))
            throw new ArgumentException("The configuration section name cannot be empty.", nameof(configurationSection));

        var optionsBuilder = services
            .AddOptions<HmacAuthenticationOptions>()
            .BindConfiguration(configurationSection);

        if (configureOptions != null)
            services.PostConfigure(configureOptions);

        services.AddOptionsUpdater<HmacAuthenticationOptions>(Microsoft.Extensions.Options.Options.DefaultName);

        services.AddTransient(sp => new HmacAuthenticationHttpHandler(sp.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>()));

        return services;
    }


    /// <summary>
    /// Adds the default (unnamed) HTTP client that signs outgoing requests with HMAC authentication.
    /// This is the HMAC-enabled equivalent of <c>AddHttpClient()</c>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configureClient">An optional action to configure the default <see cref="System.Net.Http.HttpClient"/>.</param>
    /// <param name="configureOptions">An optional action to configure the default <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to further configure the default client.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    /// <remarks>
    /// The client is registered using <see cref="Microsoft.Extensions.Options.Options.DefaultName"/> and binds its
    /// <see cref="HmacAuthenticationOptions"/> from the default "HmacAuthentication" configuration section.
    /// </remarks>
    /// <example>
    /// <code>
    /// services.AddHmacClient((sp, client) =&gt; client.BaseAddress = new Uri("https://api.example.com"));
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddHmacClient(
        this IServiceCollection services,
        Action<IServiceProvider, System.Net.Http.HttpClient>? configureClient = null,
        Action<HmacAuthenticationOptions>? configureOptions = null)
        => services.AddHmacClient(Microsoft.Extensions.Options.Options.DefaultName, HmacAuthenticationOptions.ConfigurationName, configureClient, configureOptions);

    /// <summary>
    /// Adds a named HTTP client that signs outgoing requests with HMAC authentication.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="name">The name of the HTTP client to register.</param>
    /// <param name="configureClient">An optional action to configure the named <see cref="System.Net.Http.HttpClient"/>.</param>
    /// <param name="configureOptions">An optional action to configure the named <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to further configure the named client.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="name"/> is empty or whitespace.</exception>
    public static IHttpClientBuilder AddHmacClient(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, System.Net.Http.HttpClient>? configureClient = null,
        Action<HmacAuthenticationOptions>? configureOptions = null)
        => services.AddHmacClient(name, HmacAuthenticationOptions.ConfigurationName, configureClient, configureOptions);

    /// <summary>
    /// Adds a named HTTP client that signs outgoing requests with HMAC authentication using the specified configuration section.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="name">The name of the HTTP client to register.</param>
    /// <param name="configurationSection">The name of the configuration section to bind to <see cref="HmacAuthenticationOptions"/>.</param>
    /// <param name="configureClient">An optional action to configure the named <see cref="System.Net.Http.HttpClient"/>.</param>
    /// <param name="configureOptions">An optional action to configure the named <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to further configure the named client.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="name"/> or <paramref name="configurationSection"/> is empty or whitespace.</exception>
    public static IHttpClientBuilder AddHmacClient(
        this IServiceCollection services,
        string name,
        string configurationSection,
        Action<IServiceProvider, System.Net.Http.HttpClient>? configureClient = null,
        Action<HmacAuthenticationOptions>? configureOptions = null)
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("The HTTP client name cannot be empty.", nameof(name));

        if (string.IsNullOrWhiteSpace(configurationSection))
            throw new ArgumentException("The configuration section name cannot be empty.", nameof(configurationSection));

        var optionsBuilder = services
            .AddOptions<HmacAuthenticationOptions>(name)
            .BindConfiguration(configurationSection);

        if (configureOptions != null)
            services.PostConfigure(name, configureOptions);

        services.AddOptionsUpdater<HmacAuthenticationOptions>(name);

        return services
            .AddHttpClient(name, (sp, httpClient) =>
            {
                var options = sp.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>().Get(name);

                // Always assign a base address so relative request URIs are accepted. When the base address
                // is provisioned after startup, fall back to the deferred placeholder, which HmacAuthenticationHttpHandler
                // rewrites using the current options at request time.
                httpClient.BaseAddress = options.BaseAddress ?? HmacAuthenticationHttpHandler.DeferredBaseAddress;

                configureClient?.Invoke(sp, httpClient);
            })
            .AddHttpMessageHandler(sp =>
                new HmacAuthenticationHttpHandler(
                    optionsMonitor: sp.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>(),
                    optionsName: name
                )
            );
    }

    /// <summary>
    /// Adds a typed HTTP client that signs outgoing requests with HMAC authentication.
    /// </summary>
    /// <typeparam name="TClient">The typed client to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configureClient">An optional action to configure the typed <see cref="System.Net.Http.HttpClient"/>.</param>
    /// <param name="configureOptions">An optional action to configure the named <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to further configure the typed client.</returns>
    /// <remarks>
    /// For runtime provisioning, register the client during startup, then load the provisioned settings and apply them
    /// by resolving <see cref="OptionsUpdater{TOptions}"/> for
    /// <see cref="HmacAuthenticationOptions"/> and calling
    /// <see cref="OptionsUpdaterExtensions.Update{TClient}(OptionsUpdater{HmacAuthenticationOptions}, Action{HmacAuthenticationOptions})"/>
    /// before sending requests with the typed client.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    public static IHttpClientBuilder AddHmacClient<TClient>(
        this IServiceCollection services,
        Action<IServiceProvider, System.Net.Http.HttpClient>? configureClient = null,
        Action<HmacAuthenticationOptions>? configureOptions = null)
        where TClient : class
        => services.AddHmacClient<TClient>(HmacAuthenticationOptions.ConfigurationName, configureClient, configureOptions);

    /// <summary>
    /// Adds a typed HTTP client that signs outgoing requests with HMAC authentication using the specified configuration section.
    /// </summary>
    /// <typeparam name="TClient">The typed client to register.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="configurationSection">The name of the configuration section to bind to <see cref="HmacAuthenticationOptions"/>.</param>
    /// <param name="configureClient">An optional action to configure the typed <see cref="System.Net.Http.HttpClient"/>.</param>
    /// <param name="configureOptions">An optional action to configure the named <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>An <see cref="IHttpClientBuilder"/> that can be used to further configure the typed client.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <c>null</c>.</exception>
    /// <remarks>
    /// The typed client is registered using the full name of <typeparamref name="TClient"/> as the options name,
    /// binding its <see cref="HmacAuthenticationOptions"/> from the specified <paramref name="configurationSection"/>.
    /// </remarks>
    public static IHttpClientBuilder AddHmacClient<TClient>(
        this IServiceCollection services,
        string configurationSection,
        Action<IServiceProvider, System.Net.Http.HttpClient>? configureClient = null,
        Action<HmacAuthenticationOptions>? configureOptions = null)
        where TClient : class
    {
        if (services == null)
            throw new ArgumentNullException(nameof(services));

        if (string.IsNullOrWhiteSpace(configurationSection))
            throw new ArgumentException("The configuration section name cannot be empty.", nameof(configurationSection));

        var optionsName = typeof(TClient).FullName ?? typeof(TClient).Name;

        services
            .AddOptions<HmacAuthenticationOptions>(optionsName)
            .BindConfiguration(configurationSection);

        if (configureOptions != null)
            services.PostConfigure(optionsName, configureOptions);

        services.AddOptionsUpdater<HmacAuthenticationOptions>(optionsName);

        return services
            .AddHttpClient<TClient>(optionsName, (sp, httpClient) =>
            {
                var options = sp.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>().Get(optionsName);

                // Always assign a base address so relative request URIs are accepted. When the base address
                // is provisioned after startup, fall back to the deferred placeholder, which HmacAuthenticationHttpHandler
                // rewrites using the current options at request time.
                httpClient.BaseAddress = options.BaseAddress ?? HmacAuthenticationHttpHandler.DeferredBaseAddress;

                configureClient?.Invoke(sp, httpClient);
            })
            .AddHttpMessageHandler(sp =>
                new HmacAuthenticationHttpHandler(
                    optionsMonitor: sp.GetRequiredService<IOptionsMonitor<HmacAuthenticationOptions>>(),
                    optionsName: optionsName
                )
            );
    }
}
