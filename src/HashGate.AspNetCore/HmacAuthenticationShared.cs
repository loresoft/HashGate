using System.Security.Cryptography;
using System.Text;

namespace HashGate;

/// <summary>
/// Provides shared utilities and constants for HMAC authentication implementation.
/// Contains methods for creating string-to-sign, generating signatures, and creating authorization headers.
/// </summary>
public static class HmacAuthenticationShared
{
    /// <summary>
    /// The default authentication scheme name used for HMAC authentication.
    /// </summary>
    public const string DefaultSchemeName = "HMAC";

    /// <summary>
    /// The name of the Authorization HTTP header.
    /// </summary>
    public const string AuthorizationHeaderName = "Authorization";

    /// <summary>
    /// The name of the Host HTTP header.
    /// </summary>
    public const string HostHeaderName = "Host";

    /// <summary>
    /// The name of the Content-Type HTTP header.
    /// </summary>
    public const string ContentTypeHeaderName = "Content-Type";

    /// <summary>
    /// The name of the Content-Length HTTP header.
    /// </summary>
    public const string ContentLengthHeaderName = "Content-Length";

    /// <summary>
    /// The name of the User-Agent HTTP header.
    /// </summary>
    public const string UserAgentHeaderName = "User-Agent";

    /// <summary>
    /// The name of the Date HTTP header.
    /// </summary>
    public const string DateHeaderName = "Date";

    /// <summary>
    /// The name of the custom x-date header used to override the Date header.
    /// </summary>
    public const string DateOverrideHeaderName = "x-date";

    /// <summary>
    /// The name of the custom x-timestamp header used for request timestamping.
    /// </summary>
    public const string TimeStampHeaderName = "x-timestamp";

    /// <summary>
    /// The name of the custom x-content-sha256 header containing the SHA256 hash of the request body.
    /// </summary>
    public const string ContentHashHeaderName = "x-content-sha256";

    /// <summary>
    /// Base64-encoded SHA256 hash of an empty string, used for requests with no body content.
    /// </summary>
    public const string EmptyContentHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    /// <summary>
    /// The default set of headers that are included in the signature calculation.
    /// Includes host, x-timestamp, and x-content-sha256 headers.
    /// </summary>
    public static readonly string[] DefaultSignedHeaders = ["host", TimeStampHeaderName, ContentHashHeaderName];

    /// <summary>
    /// Creates a canonical string representation for signing based on the HTTP method, path with query string, and header values.
    /// The format is: METHOD\nPATH_AND_QUERY\nHEADER_VALUES (semicolon-separated).
    /// </summary>
    /// <param name="method">The HTTP method (GET, POST, etc.) that will be converted to uppercase.</param>
    /// <param name="pathAndQuery">The request path including query string parameters.</param>
    /// <param name="headerValues">The collection of header values to include in the signature, in the order they should appear.</param>
    /// <returns>A canonical string representation suitable for HMAC signature calculation.</returns>
    public static string CreateStringToSign(
        string method,
        string pathAndQuery,
        IReadOnlyList<string> headerValues)
    {
        // Measure lengths
        int methodLength = method.Length;
        int pathAndQueryLength = pathAndQuery.Length;
        int headerCount = 0;
        int headerValuesLength = 0;

        // Materialize headerValues to avoid multiple enumeration
        headerCount = headerValues.Count;
        for (int i = 0; i < headerValues.Count; i++)
            headerValuesLength += headerValues[i].Length;

        // Each header after the first gets a semicolon separator
        int separatorLength = headerCount > 1 ? headerCount - 1 : 0;

        // 2 for the two '\n' literals
        int totalLength = methodLength + pathAndQueryLength + headerValuesLength + separatorLength + 2;

        return string.Create(totalLength, (method, pathAndQuery, headerValues), (span, state) =>
        {
            int pos = 0;

            // Write method in uppercase
            state.method.AsSpan().ToUpperInvariant(span.Slice(pos, state.method.Length));
            pos += state.method.Length;

            // Write first newline
            span[pos++] = '\n';

            // Write pathAndQuery
            state.pathAndQuery.AsSpan().CopyTo(span.Slice(pos, state.pathAndQuery.Length));
            pos += state.pathAndQuery.Length;

            // Write second newline
            span[pos++] = '\n';

            // Write header values with semicolons
            for (int i = 0; i < state.headerValues.Count; i++)
            {
                if (i > 0)
                    span[pos++] = ';';

                var header = state.headerValues[i];
                header.AsSpan().CopyTo(span.Slice(pos, header.Length));
                pos += header.Length;
            }
        });
    }

    /// <summary>
    /// Generates an HMAC-SHA256 signature for the provided string using the specified secret key.
    /// The signature is returned as a Base64-encoded string.
    /// </summary>
    /// <param name="stringToSign">The canonical string representation to be signed.</param>
    /// <param name="secretKey">The secret key used for HMAC-SHA256 calculation.</param>
    /// <returns>A Base64-encoded HMAC-SHA256 signature.</returns>
    public static string GenerateSignature(
        string stringToSign,
        string secretKey)
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

    /// <summary>
    /// Generates a complete Authorization header value in the format:
    /// "HMAC Client={client}&amp;SignedHeaders={headers}&amp;Signature={signature}".
    /// </summary>
    /// <param name="client">The client identifier used in the authorization header.</param>
    /// <param name="signedHeaders">The collection of header names that were included in the signature calculation.</param>
    /// <param name="signature">The Base64-encoded HMAC signature.</param>
    /// <returns>A complete Authorization header value ready for use in HTTP requests.</returns>
    public static string GenerateAuthorizationHeader(
        string client,
        IReadOnlyList<string> signedHeaders,
        string signature)
    {
        const string scheme = DefaultSchemeName;
        const string clientPrefix = " Client=";
        const string signedHeadersPrefix = "&SignedHeaders=";
        const string signaturePrefix = "&Signature=";

        // Calculate signedHeaders string and its length
        int signedHeadersCount = signedHeaders.Count;
        int signedHeadersLength = 0;

        for (int i = 0; i < signedHeadersCount; i++)
            signedHeadersLength += signedHeaders[i].Length;

        int signedHeadersSeparatorLength = signedHeadersCount > 1 ? signedHeadersCount - 1 : 0;

        int totalLength =
            scheme.Length +
            clientPrefix.Length +
            client.Length +
            signedHeadersPrefix.Length +
            signedHeadersLength +
            signedHeadersSeparatorLength +
            signaturePrefix.Length +
            signature.Length;

        return string.Create(totalLength, (client, signedHeaders, signature), (span, state) =>
        {
            int pos = 0;

            // Write scheme
            scheme.AsSpan().CopyTo(span.Slice(pos, scheme.Length));
            pos += scheme.Length;

            // Write client prefix
            clientPrefix.AsSpan().CopyTo(span.Slice(pos, clientPrefix.Length));
            pos += clientPrefix.Length;

            // Write client
            state.client.AsSpan().CopyTo(span.Slice(pos, state.client.Length));
            pos += state.client.Length;

            // Write signedHeaders prefix
            signedHeadersPrefix.AsSpan().CopyTo(span.Slice(pos, signedHeadersPrefix.Length));
            pos += signedHeadersPrefix.Length;

            // Write signedHeaders (semicolon separated)
            for (int i = 0; i < state.signedHeaders.Count; i++)
            {
                if (i > 0)
                    span[pos++] = ';';

                var header = state.signedHeaders[i];
                header.AsSpan().CopyTo(span.Slice(pos, header.Length));
                pos += header.Length;
            }

            // Write signature prefix
            signaturePrefix.AsSpan().CopyTo(span.Slice(pos, signaturePrefix.Length));
            pos += signaturePrefix.Length;

            // Write signature
            state.signature.AsSpan().CopyTo(span.Slice(pos, state.signature.Length));
            pos += state.signature.Length;
        });
    }

    /// <summary>
    /// Performs a constant-time comparison of two strings to prevent timing attacks.
    /// Both strings are converted to UTF-8 byte arrays before comparison.
    /// </summary>
    /// <param name="left">The first string to compare.</param>
    /// <param name="right">The second string to compare.</param>
    /// <returns><c>true</c> if the strings are equal; otherwise, <c>false</c>.</returns>
    public static bool FixedTimeEquals(
        string left,
        string right)
    {
        // Convert strings to byte arrays using UTF8 encoding
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);

        // If lengths differ, return false immediately
        if (leftBytes.Length != rightBytes.Length)
            return false;

        // Use FixedTimeEquals for constant-time comparison
        return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}
