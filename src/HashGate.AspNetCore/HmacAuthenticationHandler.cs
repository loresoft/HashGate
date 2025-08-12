// Ignore Spelling: timestamp Hmac

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore;

/// <summary>
/// Handles HMAC authentication for incoming HTTP requests.
/// </summary>
/// <remarks>
/// This handler validates the HMAC signature in the Authorization header, checks the timestamp for replay protection,
/// retrieves the client secret using <see cref="IHmacKeyProvider"/>, and authenticates the request if all checks pass.
/// </remarks>
public class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
{
    private static readonly AuthenticateResult InvalidTimestampHeader = AuthenticateResult.Fail("Invalid timestamp header");
    private static readonly AuthenticateResult InvalidContentHashHeader = AuthenticateResult.Fail("Invalid content hash header");
    private static readonly AuthenticateResult InvalidClientName = AuthenticateResult.Fail("Invalid client name");
    private static readonly AuthenticateResult InvalidSignature = AuthenticateResult.Fail("Invalid signature");
    private static readonly AuthenticateResult AuthenticationError = AuthenticateResult.Fail("Authentication error");

    private readonly IHmacKeyProvider _keyProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor for <see cref="HmacAuthenticationSchemeOptions"/>.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="keyProvider">The HMAC key provider used to retrieve client secrets.</param>
    public HmacAuthenticationHandler(
        IOptionsMonitor<HmacAuthenticationSchemeOptions> options,
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
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var authorizationHeader = Request.Headers.Authorization.ToString();

            // If no Authorization header is present, return no result
            if (string.IsNullOrEmpty(authorizationHeader))
                return AuthenticateResult.NoResult();

            var result = HmacHeaderParser.TryParse(authorizationHeader, true, out var hmacHeader);

            // not an HMAC Authorization header, return no result
            if (result == HmacHeaderError.InvalidSchema)
                return AuthenticateResult.NoResult();

            // invalid HMAC Authorization header format
            if (result != HmacHeaderError.None)
                return AuthenticateResult.Fail($"Invalid Authorization header: {result}");

            if (!ValidateTimestamp())
                return InvalidTimestampHeader;

            if (!await ValidateContentHash())
                return InvalidContentHashHeader;

            var clientSecret = await _keyProvider
                .GetSecretAsync(hmacHeader.Client, Context.RequestAborted)
                .ConfigureAwait(false);

            if (string.IsNullOrEmpty(clientSecret))
                return InvalidClientName;

            var headerValues = GetHeaderValues(hmacHeader.SignedHeaders);

            var stringToSign = HmacAuthenticationShared.CreateStringToSign(
                method: Request.Method,
                pathAndQuery: Request.Path + Request.QueryString,
                headerValues: headerValues);

            var expectedSignature = HmacAuthenticationShared.GenerateSignature(stringToSign, clientSecret);
            if (!HmacAuthenticationShared.FixedTimeEquals(expectedSignature, hmacHeader.Signature))
                return InvalidSignature;

            var identity = await _keyProvider
                .GenerateClaimsAsync(hmacHeader.Client, Scheme.Name, Context.RequestAborted)
                .ConfigureAwait(false);

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during HMAC authentication");
            return AuthenticationError;
        }
    }


    private async Task<bool> ValidateContentHash()
    {
        if (!Request.Headers.TryGetValue(HmacAuthenticationShared.ContentHashHeaderName, out var contentHashHeader))
            return false;

        var contentHash = contentHashHeader.ToString();
        if (string.IsNullOrEmpty(contentHash))
            return false;

        var computedHash = await GenerateContentHash().ConfigureAwait(false);

        return HmacAuthenticationShared.FixedTimeEquals(computedHash, contentHash);
    }

    private bool ValidateTimestamp()
    {
        var timestampHeader = GetHeaderValue(HmacAuthenticationShared.TimeStampHeaderName);
        if (!long.TryParse(timestampHeader, out var timestamp))
            return false;

        var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        var now = DateTimeOffset.UtcNow;
        var timeDifference = Math.Abs((now - requestTime).TotalMinutes);

        // Use configured tolerance from options
        return timeDifference <= Options.ToleranceWindow;
    }


    private async Task<string> GenerateContentHash()
    {
        // Ensure the request body can be read multiple times
        Request.EnableBuffering();

        // Return empty content hash if there is no body
        if (Request.ContentLength == 0 || Request.Body == Stream.Null)
            return HmacAuthenticationShared.EmptyContentHash;

        await using var memoryStream = new MemoryStream();
        await Request.BodyReader.CopyToAsync(memoryStream).ConfigureAwait(false);

        // Reset position after reading
        Request.Body.Position = 0;

        // If the body is empty after reading, return empty content hash
        if (memoryStream.Length == 0)
            return HmacAuthenticationShared.EmptyContentHash;

        var hashBytes = SHA256.HashData(memoryStream.ToArray());

        // 32 bytes SHA256 -> 44 chars base64
        Span<char> base64 = stackalloc char[44];
        if (Convert.TryToBase64Chars(hashBytes, base64, out int charsWritten))
            return new string(base64[..charsWritten]);

        // if stackalloc is not large enough (should not happen for SHA256)
        return Convert.ToBase64String(hashBytes);
    }

    private string[] GetHeaderValues(IReadOnlyList<string> signedHeaders)
    {
        var headerValues = new string[signedHeaders.Count];

        for (var i = 0; i < signedHeaders.Count; i++)
            headerValues[i] = GetHeaderValue(signedHeaders[i]) ?? string.Empty;

        return headerValues;
    }

    private string? GetHeaderValue(string headerName)
    {
        if (headerName.Equals(HmacAuthenticationShared.HostHeaderName, StringComparison.InvariantCultureIgnoreCase))
        {
            if (Request.Headers.TryGetValue(HmacAuthenticationShared.HostHeaderName, out var hostValue))
                return hostValue.ToString();

            return Request.Host.Value;
        }

        // Handle date headers specifically
        if (headerName.Equals(HmacAuthenticationShared.DateHeaderName, StringComparison.InvariantCultureIgnoreCase)
            || headerName.Equals(HmacAuthenticationShared.DateOverrideHeaderName, StringComparison.InvariantCultureIgnoreCase))
        {
            if (Request.Headers.TryGetValue(HmacAuthenticationShared.DateOverrideHeaderName, out var xDateValue))
                return xDateValue.ToString();

            if (Request.Headers.TryGetValue(HmacAuthenticationShared.DateHeaderName, out var dateValue))
                return dateValue.ToString();

            return Request.Headers.Date.ToString();
        }

        // Handle content-type and content-length headers specifically
        if (headerName.Equals(HmacAuthenticationShared.ContentTypeHeaderName, StringComparison.InvariantCultureIgnoreCase))
            return Request.ContentType?.ToString();

        if (headerName.Equals(HmacAuthenticationShared.ContentLengthHeaderName, StringComparison.InvariantCultureIgnoreCase))
            return Request.ContentLength?.ToString();

        // For all other headers, try to get the value directly
        if (Request.Headers.TryGetValue(headerName, out var value))
            return value.ToString();

        return null;
    }
}
