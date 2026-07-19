using System.Net.Http;

using Microsoft.Extensions.Options;

namespace HashGate.HttpClient;

/// <summary>
/// An HTTP message handler that automatically adds HMAC authentication headers to outgoing HTTP requests.
/// This handler integrates with the .NET HTTP client pipeline to transparently sign requests using HMAC-SHA256.
/// </summary>
/// <remarks>
/// <para>
/// The handler automatically adds the following headers to requests that don't already have an Authorization header:
/// </para>
/// <list type="bullet">
/// <item><description><c>x-timestamp</c> - Current Unix timestamp</description></item>
/// <item><description><c>x-content-sha256</c> - Base64-encoded SHA256 hash of the request body</description></item>
/// <item><description><c>Authorization</c> - HMAC authentication header with client ID, signed headers, and signature</description></item>
/// </list>
/// <para>
/// This handler should be registered in the dependency injection container and used with HttpClient instances
/// that need to authenticate using HMAC. It respects existing Authorization headers and will not overwrite them.
/// </para>
/// </remarks>
/// <example>
/// <para>Register and use with HttpClient:</para>
/// <code>
/// // Register the handler
/// services.AddHmacAuthentication(options =>
/// {
///     options.Client = "my-client-id";
///     options.Secret = "my-secret-key";
/// });
///
/// // Use with HttpClient
/// services.AddHttpClient("ApiClient")
///     .AddHttpMessageHandler&lt;HmacAuthenticationHttpHandler&gt;();
///
/// // The handler will automatically sign all requests made through this client
/// var client = httpClientFactory.CreateClient("ApiClient");
/// var response = await client.GetAsync("https://api.example.com/data");
/// </code>
/// </example>
public class HmacAuthenticationHttpHandler : DelegatingHandler
{
    /// <summary>
    /// A placeholder base address used to indicate that the actual base address should be applied later.
    /// </summary>
    internal static readonly Uri DeferredBaseAddress = new("http://hashgate.invalid/");

    private readonly IOptionsMonitor<HmacAuthenticationOptions> _optionsMonitor;
    private readonly string _optionsName;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacAuthenticationHttpHandler"/> class.
    /// </summary>
    /// <param name="optionsMonitor">The monitored HMAC authentication options containing client credentials and configuration.</param>
    /// <param name="optionsName">The named options instance to use, or <c>null</c> to use the default options instance.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="optionsMonitor"/> is <c>null</c>.</exception>
    public HmacAuthenticationHttpHandler(IOptionsMonitor<HmacAuthenticationOptions> optionsMonitor, string? optionsName = null)
    {
        if (optionsMonitor is null)
            throw new ArgumentNullException(nameof(optionsMonitor));

        // CurrentValue is equivalent to Get(Options.DefaultName), so the default and named
        // cases collapse into a single Get(...) call at request time.
        _optionsMonitor = optionsMonitor;
        _optionsName = optionsName ?? Microsoft.Extensions.Options.Options.DefaultName;
    }

    /// <summary>
    /// Sends an HTTP request to the inner handler to send to the server as an asynchronous operation.
    /// If the request does not already contain an Authorization header, HMAC authentication headers are automatically added.
    /// </summary>
    /// <param name="request">The HTTP request message to send to the server.</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains the HTTP response message.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method checks if the request already has an Authorization header. If not, it calls the
    /// <see cref="HttpRequestMessageExtensions.AddHmacAuthentication(HttpRequestMessage, HmacAuthenticationOptions, CancellationToken)"/>
    /// extension method to add the required HMAC authentication headers including:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Timestamp header for request timing validation</description></item>
    /// <item><description>Content hash header for request body integrity</description></item>
    /// <item><description>Authorization header with HMAC signature</description></item>
    /// </list>
    /// <para>
    /// The handler preserves any existing Authorization header to allow for manual authentication control
    /// or to prevent double-signing of requests.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="request"/> is <c>null</c>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when HMAC authentication options are invalid or incomplete.</exception>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var options = _optionsMonitor.Get(_optionsName);
        ApplyBaseAddress(request, options);

        // If the request does not already have an Authorization header, add HMAC headers
        if (request.Headers.Authorization == null)
            await request.AddHmacAuthentication(options, cancellationToken).ConfigureAwait(false);

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static void ApplyBaseAddress(HttpRequestMessage request, HmacAuthenticationOptions options)
    {
        if (request.RequestUri == null)
            return;

        if (options.BaseAddress == null)
        {
            // A null options base address is valid when the HttpClient supplies its own base address
            // (or the caller uses absolute request URIs); those requests already carry a usable absolute URI.
            // Only fail when there is nothing to resolve against: a relative URI, or the unresolved deferred
            // placeholder, either of which would otherwise be sent to the invalid placeholder host.
            if (!request.RequestUri.IsAbsoluteUri || IsDeferredBaseAddress(request.RequestUri))
            {
                throw new InvalidOperationException(
                    "The HMAC authentication base address has not been configured. " +
                    "Set HmacAuthenticationOptions.BaseAddress, configure the HttpClient base address, or provide an absolute request URI.");
            }

            return;
        }

        if (!request.RequestUri.IsAbsoluteUri)
        {
            request.RequestUri = new Uri(options.BaseAddress, request.RequestUri);
            return;
        }

        if (IsDeferredBaseAddress(request.RequestUri))
        {
            var relativeUri = request.RequestUri.PathAndQuery.TrimStart('/');
            request.RequestUri = new Uri(options.BaseAddress, relativeUri);
        }
    }

    private static bool IsDeferredBaseAddress(Uri requestUri)
        => string.Equals(requestUri.Scheme, DeferredBaseAddress.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(requestUri.Host, DeferredBaseAddress.Host, StringComparison.OrdinalIgnoreCase)
            && requestUri.Port == DeferredBaseAddress.Port;
}
