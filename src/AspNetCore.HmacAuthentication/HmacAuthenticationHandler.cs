// Ignore Spelling: timestamp Hmac

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Handles HMAC authentication for incoming HTTP requests.
/// </summary>
/// <remarks>
/// This handler validates the HMAC signature in the Authorization header, checks the timestamp for replay protection,
/// retrieves the client secret using <see cref="IHmacKeyProvider"/>, and authenticates the request if all checks pass.
/// </remarks>
/// <example>
/// <para>
/// The expected Authorization header format is:
/// </para>
/// <code language="text">
/// Authorization: HMAC &lt;clientId&gt;:&lt;timestamp&gt;:&lt;signedHeaders&gt;:&lt;signature&gt;
/// </code>
/// <list type="bullet">
///   <item><description><c>&lt;clientId&gt;</c>: The client identifier (required, non-empty).</description></item>
///   <item><description><c>&lt;timestamp&gt;</c>: The Unix timestamp (in seconds) when the request was signed (required, non-empty, must be a valid integer).</description></item>
///   <item><description><c>&lt;signedHeaders&gt;</c>: Semicolon-separated list of HTTP headers included in the signature (may be empty).</description></item>
///   <item><description><c>&lt;signature&gt;</c>: The Base64-encoded HMAC SHA256 signature (required, non-empty).</description></item>
/// </list>
/// <para>
/// Example:
/// </para>
/// <code language="text">
/// Authorization: HMAC myClient:1722450000:host;date;content-type:Q2hhbmdlVGhpcyBUb1lvdXJTZWN1cmVTZWNyZXQ=
/// </code>
/// </example>
public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationOptions>
{
    private readonly IHmacKeyProvider _keyProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor for <see cref="HmacAuthenticationOptions"/>.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="keyProvider">The HMAC key provider used to retrieve client secrets.</param>
    public HmacAuthenticationHandler(
        IOptionsMonitor<HmacAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IHmacKeyProvider keyProvider)
        : base(options, logger, encoder)
    {
        _keyProvider = keyProvider;
    }

    /// <summary>
    /// Handles the authentication process for HMAC authentication.
    /// </summary>
    /// <returns>
    /// A <see cref="Task{AuthenticateResult}"/> representing the asynchronous authentication operation.
    /// </returns>
    /// <remarks>
    /// This method performs the following steps:
    /// <list type="number">
    /// <item>Checks for the Authorization header.</item>
    /// <item>Parses and validates the HMAC header.</item>
    /// <item>Validates the request timestamp against the configured tolerance window.</item>
    /// <item>Retrieves the client secret using the key provider.</item>
    /// <item>Reads the request body and canonicalizes headers.</item>
    /// <item>Builds the string to sign and verifies the HMAC signature.</item>
    /// <item>Creates claims and returns a successful authentication ticket if valid.</item>
    /// </list>
    /// </remarks>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            // 1. Authorization header check
            var authorizationHeader = Request.Headers.Authorization.ToString();
            if (string.IsNullOrEmpty(authorizationHeader))
                return AuthenticateResult.Fail("Invalid Authorization header");

            // 2. Parse Authorization header
            var headerData = HmacHeaderParser.TryParse(authorizationHeader);
            if (!headerData.IsSuccess)
                return AuthenticateResult.Fail($"Invalid Authorization header: {headerData.Error}");

            // 3. Timestamp validation
            if (!ValidateTimestamp(headerData.Timestamp))
                return AuthenticateResult.Fail("Request timestamp is invalid or expired");

            // 4. Retrieve client secret
            var clientSecret = await _keyProvider.GetSecretAsync(headerData.ClientId);
            if (string.IsNullOrEmpty(clientSecret))
                return AuthenticateResult.Fail("Invalid client ID");

            // 5. Read request body only if all previous checks pass
            var requestBody = await GetRequestBody();

            // 6. Canonical headers
            var canonicalHeaders = GetCanonicalHeaders(headerData.SignedHeaders);

            // 7. Build string to sign
            var stringToSign = CreateStringToSign(
                method: Request.Method,
                path: Request.Path,
                queryString: Request.QueryString,
                timestamp: headerData.Timestamp,
                canonicalHeaders: canonicalHeaders,
                signedHeaders: headerData.SignedHeaders,
                body: requestBody);

            // 8. Generate and compare signature
            var expectedSignature = GenerateHmacSignature(stringToSign, clientSecret);
            if (!headerData.Signature.Equals(expectedSignature, StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.Fail("Invalid signature");

            // 9. Build claims and principal
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, headerData.ClientId),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during HMAC authentication");
            return AuthenticateResult.Fail("Authentication error");
        }
    }

    /// <summary>
    /// Validates the request timestamp against the configured tolerance window to prevent replay attacks.
    /// </summary>
    /// <param name="timestamp">The Unix timestamp (in seconds) from the request.</param>
    /// <returns><c>true</c> if the timestamp is within the allowed window; otherwise, <c>false</c>.</returns>
    private bool ValidateTimestamp(long timestamp)
    {
        var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        var now = DateTimeOffset.UtcNow;
        var timeDifference = Math.Abs((now - requestTime).TotalMinutes);

        // Use configured tolerance from options
        return timeDifference <= Options.ToleranceWindow;
    }

    /// <summary>
    /// Reads and returns the request body as a string, enabling buffering to allow multiple reads.
    /// </summary>
    /// <returns>The request body as a string, or an empty string if not present.</returns>
    private async Task<string> GetRequestBody()
    {
        if (Request.ContentLength == 0 || !Request.Body.CanRead)
            return string.Empty;

        // Enable buffering to allow reading the request body multiple times
        Request.EnableBuffering();

        // Use a reasonable buffer size (e.g., 4 KB)
        const int bufferSize = 4096;
        string body;

        // Leave Body stream open after reading
        using var reader = new StreamReader(
            stream: Request.Body,
            encoding: Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: bufferSize, leaveOpen: true);

        body = await reader.ReadToEndAsync();

        // Reset the stream position if possible
        if (Request.Body.CanSeek)
            Request.Body.Position = 0;

        return body ?? string.Empty;
    }

    /// <summary>
    /// Builds a canonical string representation of the specified signed headers from the request.
    /// </summary>
    /// <param name="signedHeaders">The collection of header names to include in the canonical string.</param>
    /// <returns>A canonical string of headers, or an empty string if none are present.</returns>
    private string GetCanonicalHeaders(IReadOnlyCollection<string> signedHeaders)
    {
        if (signedHeaders == null)
            return string.Empty;

        var headersToSign = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var headerName in signedHeaders)
        {
            if (string.IsNullOrWhiteSpace(headerName))
                continue;

            // Normalize header name to lowercase and trim whitespace
            var lower = headerName.Trim().ToLowerInvariant();

            // Get the header value from the request
            var headerValue = GetHeaderValue(lower);
            if (!string.IsNullOrEmpty(headerValue))
                headersToSign[lower] = headerValue;
        }

        if (headersToSign.Count == 0)
            return string.Empty;

        bool first = true;

        var sb = StringBuilderCache.Acquire();
        foreach (var kvp in headersToSign)
        {
            if (!first)
                sb.Append('\n');

            sb.Append(kvp.Key).Append(':').Append(kvp.Value);

            first = false;
        }

        return StringBuilderCache.ToString(sb);
    }

    /// <summary>
    /// Retrieves the value of a specific header from the request, handling common headers specially.
    /// </summary>
    /// <param name="headerName">The name of the header to retrieve.</param>
    /// <returns>The header value as a string, or <c>null</c> if not found.</returns>
    private string? GetHeaderValue(string headerName)
    {
        if (headerName.Equals("host", StringComparison.InvariantCultureIgnoreCase))
        {
            if (Request.Headers.TryGetValue("Host", out var hostValue))
                return hostValue.ToString().ToLowerInvariant();

            return Request.Host.Value?.ToLowerInvariant();
        }

        if (headerName.Equals("content-type", StringComparison.InvariantCultureIgnoreCase))
            return Request.ContentType?.ToString();

        if (headerName.Equals("content-length", StringComparison.InvariantCultureIgnoreCase))
            return Request.ContentLength?.ToString();

        if (headerName.Equals("user-agent", StringComparison.InvariantCultureIgnoreCase))
            return Request.Headers.UserAgent.ToString();

        if (Request.Headers.TryGetValue(headerName, out var value))
            return value.ToString();

        return null;
    }

    /// <summary>
    /// Creates the canonical string to sign for HMAC authentication.
    /// </summary>
    /// <param name="method">The HTTP method (e.g., GET, POST).</param>
    /// <param name="path">The request path.</param>
    /// <param name="queryString">The request query string.</param>
    /// <param name="timestamp">The Unix timestamp (in seconds).</param>
    /// <param name="canonicalHeaders">The canonicalized headers string.</param>
    /// <param name="signedHeaders">The collection of signed header names.</param>
    /// <param name="body">The request body as a string.</param>
    /// <returns>The canonical string to sign.</returns>
    public static string CreateStringToSign(
        string method,
        PathString path,
        QueryString queryString,
        long timestamp,
        string canonicalHeaders,
        IEnumerable<string> signedHeaders,
        string body)
    {
        // Use a pooled StringBuilder for efficiency
        var sb = StringBuilderCache.Acquire();

        // format the string to sign
        sb.Append(method).Append('\n');
        sb.Append(path).Append(queryString).Append('\n');
        sb.Append(timestamp).Append('\n');
        sb.Append(canonicalHeaders).Append('\n');
        sb.AppendJoin(';', signedHeaders).Append('\n');
        sb.Append(body);

        return StringBuilderCache.ToString(sb);
    }

    /// <summary>
    /// Generates the HMAC SHA256 signature for the specified string using the provided secret key.
    /// </summary>
    /// <param name="stringToSign">The canonical string to sign.</param>
    /// <param name="secretKey">The secret key used for HMAC computation.</param>
    /// <returns>The Base64-encoded HMAC SHA256 signature.</returns>
    public static string GenerateHmacSignature(string stringToSign, string secretKey)
    {
        // Convert secret and stringToSign to byte arrays
        var secretBytes = Encoding.UTF8.GetBytes(secretKey);
        var dataBytes = Encoding.UTF8.GetBytes(stringToSign);

        // Compute HMACSHA256
        Span<byte> hash = stackalloc byte[32];
        using var hmac = new HMACSHA256(secretBytes);

        // Try to compute the hash using stackalloc for performance
        if (!hmac.TryComputeHash(dataBytes, hash, out _))
        {
            // Fallback if stackalloc is not large enough (should not happen for SHA256)
            hash = hmac.ComputeHash(dataBytes);
        }

        // 32 bytes SHA256 -> 44 chars base64
        Span<char> base64 = stackalloc char[44];
        if (Convert.TryToBase64Chars(hash, base64, out int charsWritten))
            return new string(base64[..charsWritten]);

        return Convert.ToBase64String(hash);
    }
}
