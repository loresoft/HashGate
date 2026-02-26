// Ignore Spelling: timestamp Hmac

using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
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
public partial class HmacAuthenticationHandler : AuthenticationHandler<HmacAuthenticationSchemeOptions>
{
    private static readonly AuthenticateResult InvalidTimestampHeader = AuthenticateResult.Fail("Invalid timestamp header");
    private static readonly AuthenticateResult InvalidContentHashHeader = AuthenticateResult.Fail("Invalid content hash header");
    private static readonly AuthenticateResult InvalidClientName = AuthenticateResult.Fail("Invalid client name");
    private static readonly AuthenticateResult InvalidSignature = AuthenticateResult.Fail("Invalid signature");
    private static readonly AuthenticateResult AuthenticationError = AuthenticateResult.Fail("Authentication error");

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
        UrlEncoder encoder)
        : base(options, logger, encoder)
    { }

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

            // Try to parse the HMAC Authorization header
            var result = HmacHeaderParser.TryParse(authorizationHeader, true, out var hmacHeader);

            // not an HMAC Authorization header, return no result
            if (result == HmacHeaderError.InvalidSchema)
                return AuthenticateResult.NoResult();

            // invalid HMAC Authorization header format
            if (result != HmacHeaderError.None)
            {
                LogInvalidAuthorizationHeader(Logger, result);
                return AuthenticateResult.Fail($"Invalid Authorization header: {result}");
            }

            if (!ValidateTimestamp(out var requestTime))
            {
                // Reject stale/future requests outside the allowed replay-protection window.
                LogInvalidTimestamp(Logger, requestTime);
                return InvalidTimestampHeader;
            }

            if (!await ValidateContentHash())
            {
                // Ensure the request body hash matches what the client signed.
                LogInvalidContentHash(Logger);
                return InvalidContentHashHeader;
            }

            // Resolve keyed provider when configured; otherwise use the default registration.
            var keyProvider = string.IsNullOrEmpty(Options.ProviderServiceKey)
                ? Context.RequestServices.GetRequiredService<IHmacKeyProvider>()
                : Context.RequestServices.GetRequiredKeyedService<IHmacKeyProvider>(Options.ProviderServiceKey);

            // Retrieve the client secret for the given client ID to verify the signature.
            var clientSecret = await keyProvider
                .GetSecretAsync(hmacHeader.Client, Context.RequestAborted)
                .ConfigureAwait(false);

            if (string.IsNullOrEmpty(clientSecret))
            {
                // Unknown client IDs are treated as authentication failures.
                LogInvalidClientName(Logger, hmacHeader.Client);
                return InvalidClientName;
            }

            var headerValues = GetHeaderValues(hmacHeader.SignedHeaders);

            // Recreate the canonical payload exactly as the client signed it before signature verification.
            var stringToSign = HmacAuthenticationShared.CreateStringToSign(
                method: Request.Method,
                pathAndQuery: Request.Path + Request.QueryString,
                headerValues: headerValues);

            // Generate the expected signature using the client secret and compare it to the signature provided by the client.
            var expectedSignature = HmacAuthenticationShared.GenerateSignature(stringToSign, clientSecret);
            if (!HmacAuthenticationShared.FixedTimeEquals(expectedSignature, hmacHeader.Signature))
            {
                // Use constant-time comparison to avoid timing side-channel leakage.
                LogInvalidSignature(Logger, hmacHeader.Client);
                return InvalidSignature;
            }

            // At this point, the request is authenticated successfully. Create a claims identity and principal for authorization.
            var identity = await keyProvider
                .GenerateClaimsAsync(hmacHeader.Client, Scheme.Name, Context.RequestAborted)
                .ConfigureAwait(false);

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            // Return a successful authentication ticket so authorization can evaluate policies.
            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            LogAuthenticationError(Logger, ex, ex.Message);
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

    private bool ValidateTimestamp(out DateTimeOffset? requestTime)
    {
        var timestampHeader = GetHeaderValue(HmacAuthenticationShared.TimeStampHeaderName);
        if (!long.TryParse(timestampHeader, NumberStyles.Integer, CultureInfo.InvariantCulture, out var timestamp))
        {
            requestTime = default;
            return false;
        }

        requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        var now = DateTimeOffset.UtcNow;

        var timeDifference = Math.Abs((now - requestTime.Value).TotalMinutes);

        // Use configured tolerance from options
        return timeDifference <= Options.ToleranceWindow;
    }


    private async Task<string> GenerateContentHash()
    {
        Request.EnableBuffering();

        if (Request.ContentLength == 0 || Request.Body == Stream.Null)
            return HmacAuthenticationShared.EmptyContentHash;

        using var sha = SHA256.Create();

        int read;
        var buffer = new byte[81920]; // default Stream.CopyTo buffer size

        // Read the request body in chunks to compute the hash without loading the entire body into memory.
        while ((read = await Request.Body.ReadAsync(buffer, Context.RequestAborted)) > 0)
            sha.TransformBlock(buffer, 0, read, null, 0);

        // Finalize the hash computation. Since TransformBlock was used, we need to call TransformFinalBlock with an empty array.
        sha.TransformFinalBlock([], 0, 0);

        // Reset the request body stream position so it can be read again by the application after authentication.
        Request.Body.Position = 0;

        // Convert the hash to a Base64 string. Use TryToBase64Chars for better performance and less memory allocation.
        Span<char> base64 = stackalloc char[44];
        return Convert.TryToBase64Chars(sha.Hash!, base64, out int written)
            ? new string(base64[..written])
            : Convert.ToBase64String(sha.Hash!);
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
        if (headerName.Equals(HmacAuthenticationShared.HostHeaderName, StringComparison.OrdinalIgnoreCase ))
        {
            if (Request.Headers.TryGetValue(HmacAuthenticationShared.HostHeaderName, out var hostValue))
                return hostValue.ToString();

            return Request.Host.Value;
        }

        // Handle date headers specifically
        if (headerName.Equals(HmacAuthenticationShared.DateHeaderName, StringComparison.OrdinalIgnoreCase )
            || headerName.Equals(HmacAuthenticationShared.DateOverrideHeaderName, StringComparison.OrdinalIgnoreCase ))
        {
            if (Request.Headers.TryGetValue(HmacAuthenticationShared.DateOverrideHeaderName, out var xDateValue))
                return xDateValue.ToString();

            if (Request.Headers.TryGetValue(HmacAuthenticationShared.DateHeaderName, out var dateValue))
                return dateValue.ToString();

            return Request.Headers.Date.ToString();
        }

        // Handle content-type and content-length headers specifically
        if (headerName.Equals(HmacAuthenticationShared.ContentTypeHeaderName, StringComparison.OrdinalIgnoreCase ))
            return Request.ContentType?.ToString();

        if (headerName.Equals(HmacAuthenticationShared.ContentLengthHeaderName, StringComparison.OrdinalIgnoreCase ))
            return Request.ContentLength?.ToString(CultureInfo.InvariantCulture);

        // For all other headers, try to get the value directly
        if (Request.Headers.TryGetValue(headerName, out var value))
            return value.ToString();

        return null;
    }


    [LoggerMessage(Level = LogLevel.Warning, Message = "Invalid Authorization header: {HeaderError}")]
    private static partial void LogInvalidAuthorizationHeader(ILogger logger, HmacHeaderError headerError);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Invalid or expired timestamp: {RequestTime}")]
    private static partial void LogInvalidTimestamp(ILogger logger, DateTimeOffset? requestTime);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Invalid body content hash")]
    private static partial void LogInvalidContentHash(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Invalid client name: {Client}")]
    private static partial void LogInvalidClientName(ILogger logger, string client);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Invalid signature for client: {Client}")]
    private static partial void LogInvalidSignature(ILogger logger, string client);

    [LoggerMessage(Level = LogLevel.Error, Message = "Error during HMAC authentication: {ErrorMessage}")]
    private static partial void LogAuthenticationError(ILogger logger, Exception exception, string errorMessage);
}
