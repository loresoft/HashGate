using Microsoft.Extensions.Options;

namespace AspNetCore.HmacAuthentication.Client;

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
    private readonly IOptions<HmacAuthenticationOptions> _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacAuthenticationHttpHandler"/> class.
    /// </summary>
    /// <param name="options">The HMAC authentication options containing client credentials and configuration.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is <c>null</c>.</exception>
    public HmacAuthenticationHttpHandler(IOptions<HmacAuthenticationOptions> options)
    {
        _options = options;
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
    /// <see cref="HttpRequestMessageExtensions.AddHmacAuthentication(HttpRequestMessage, HmacAuthenticationOptions)"/>
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
        // If the request does not already have an Authorization header, add HMAC headers
        if (request.Headers.Authorization == null)
            await request.AddHmacAuthentication(_options.Value);

        return await base.SendAsync(request, cancellationToken);
    }
}
