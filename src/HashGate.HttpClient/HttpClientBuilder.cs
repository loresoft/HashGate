using System.Net.Http;

using Microsoft.Extensions.Options;

namespace HashGate.HttpClient;

/// <summary>
/// Provides a fluent API for building and configuring <see cref="System.Net.Http.HttpClient"/> instances
/// with custom message handlers and HMAC authentication.
/// </summary>
/// <example>
/// <code>
/// var httpClient = new HttpClientBuilder()
///     .AddHmacAuthentication("myClientId", "mySecretKey")
///     .Configure(client =>
///     {
///         client.BaseAddress = new Uri("https://api.example.com");
///         client.Timeout = TimeSpan.FromSeconds(30);
///     })
///     .Build();
/// 
/// var response = await httpClient.GetAsync("/api/endpoint");
/// </code>
/// </example>
public class HttpClientBuilder
{
    private readonly List<DelegatingHandler> _handlers = [];
    private Action<System.Net.Http.HttpClient>? _clientConfigurator;

    /// <summary>
    /// Adds a custom <see cref="DelegatingHandler"/> to the HTTP client pipeline.
    /// </summary>
    /// <param name="handler">The delegating handler to add to the pipeline.</param>
    /// <returns>The current <see cref="HttpClientBuilder"/> instance for method chaining.</returns>
    public HttpClientBuilder AddHandler(DelegatingHandler handler)
    {
        _handlers.Add(handler);
        return this;
    }

    /// <summary>
    /// Adds HMAC authentication to the HTTP client pipeline using the specified client ID and secret.
    /// </summary>
    /// <param name="client">The client identifier used for HMAC authentication.</param>
    /// <param name="secret">The secret key used for HMAC signature generation.</param>
    /// <param name="signedHeaders">Optional list of HTTP headers to include in the HMAC signature. 
    /// If not specified, default headers will be used.</param>
    /// <returns>The current <see cref="HttpClientBuilder"/> instance for method chaining.</returns>
    public HttpClientBuilder AddHmacAuthentication(string client, string secret, IReadOnlyList<string>? signedHeaders = null)
    {
        var options = new HmacAuthenticationOptions
        {
            Client = client,
            Secret = secret,
            SignedHeaders = signedHeaders ?? HmacAuthenticationShared.DefaultSignedHeaders
        };

        var wrapper = new OptionsWrapper<HmacAuthenticationOptions>(options);
        var handler = new HmacAuthenticationHttpHandler(wrapper);

        _handlers.Add(handler);

        return this;
    }

    /// <summary>
    /// Configures the <see cref="System.Net.Http.HttpClient"/> instance with additional settings.
    /// </summary>
    /// <param name="configure">An action to configure the HTTP client (e.g., setting base address, timeout, default headers).</param>
    /// <returns>The current <see cref="HttpClientBuilder"/> instance for method chaining.</returns>
    public HttpClientBuilder Configure(Action<System.Net.Http.HttpClient> configure)
    {
        _clientConfigurator = configure;
        return this;
    }

    /// <summary>
    /// Builds and returns a configured <see cref="System.Net.Http.HttpClient"/> instance
    /// with all registered handlers and configurations applied.
    /// </summary>
    /// <returns>A fully configured <see cref="System.Net.Http.HttpClient"/> instance.</returns>
    public System.Net.Http.HttpClient Build()
    {
        HttpMessageHandler pipeline = new HttpClientHandler();

        // Chain handlers in reverse order
        for (int i = _handlers.Count - 1; i >= 0; i--)
        {
            _handlers[i].InnerHandler = pipeline;
            pipeline = _handlers[i];
        }

        var client = new System.Net.Http.HttpClient(pipeline);

        _clientConfigurator?.Invoke(client);

        return client;
    }
}
