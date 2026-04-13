using System.Security.Cryptography;
using System.Text;

#if HTTP_CLIENT
namespace HashGate.HttpClient;
#else
namespace HashGate.AspNetCore;
#endif

/// <summary>
/// Shared utilities and constants for the HMAC authentication implementation.
/// </summary>
/// <remarks>
/// Contains helpers for creating the canonical string-to-sign, computing HMAC-SHA256
/// signatures, building the <c>Authorization</c> header, and performing constant-time
/// string comparison.
/// </remarks>
public static class HmacAuthenticationShared
{
    /// <summary>
    /// Default authentication scheme name (<c>"HMAC"</c>).
    /// </summary>
    public const string DefaultSchemeName = "HMAC";

    /// <summary>
    /// Name of the <c>Authorization</c> HTTP header.
    /// </summary>
    public const string AuthorizationHeaderName = "Authorization";

    /// <summary>
    /// Name of the <c>Host</c> HTTP header.
    /// </summary>
    public const string HostHeaderName = "Host";

    /// <summary>
    /// Name of the <c>Content-Type</c> HTTP header.
    /// </summary>
    public const string ContentTypeHeaderName = "Content-Type";

    /// <summary>
    /// Name of the <c>Content-Length</c> HTTP header.
    /// </summary>
    public const string ContentLengthHeaderName = "Content-Length";

    /// <summary>
    /// Name of the <c>User-Agent</c> HTTP header.
    /// </summary>
    public const string UserAgentHeaderName = "User-Agent";

    /// <summary>
    /// Name of the <c>Date</c> HTTP header.
    /// </summary>
    public const string DateHeaderName = "Date";

    /// <summary>
    /// Name of the custom <c>x-date</c> header used to override the <c>Date</c> header.
    /// </summary>
    public const string DateOverrideHeaderName = "x-date";

    /// <summary>
    /// Name of the custom <c>x-timestamp</c> header used for request timestamping.
    /// </summary>
    public const string TimeStampHeaderName = "x-timestamp";

    /// <summary>
    /// Name of the custom <c>x-content-sha256</c> header containing the SHA-256 hash of the request body.
    /// </summary>
    public const string ContentHashHeaderName = "x-content-sha256";

    /// <summary>
    /// Name of the custom <c>x-nonce</c> header containing a unique per-request value.
    /// </summary>
    /// <remarks>
    /// Including this header in the signed headers makes every signature cryptographically
    /// unique, which is required for reliable replay protection when
    /// <c>EnableReplayProtection</c> is enabled.
    /// </remarks>
    public const string NonceHeaderName = "x-nonce";

    /// <summary>
    /// Base64-encoded SHA-256 hash of an empty string, used for requests with no body content.
    /// </summary>
    public const string EmptyContentHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    /// <summary>
    /// Default set of headers included in the signature calculation:
    /// <c>host</c>, <c>x-timestamp</c>, <c>x-content-sha256</c>, and <c>x-nonce</c>.
    /// </summary>
    public static readonly string[] DefaultSignedHeaders = ["host", TimeStampHeaderName, ContentHashHeaderName, NonceHeaderName];

    /// <summary>
    /// Creates a canonical string-to-sign from the HTTP method, path with query string,
    /// and signed header values.
    /// </summary>
    /// <param name="method">The HTTP method (e.g. <c>GET</c>, <c>POST</c>), converted to uppercase.</param>
    /// <param name="pathAndQuery">The request path including query string parameters.</param>
    /// <param name="headerValues">Ordered header values to include in the signature.</param>
    /// <returns>
    /// A canonical string in the format
    /// <c>METHOD\nPATH_AND_QUERY\nHEADER_VALUES</c> (values semicolon-separated).
    /// </returns>
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

#if NETSTANDARD2_0 || NETFRAMEWORK
        var stringBuilder = new StringBuilder(totalLength);

        stringBuilder
            .Append(method.ToUpperInvariant())
            .Append('\n')
            .Append(pathAndQuery)
            .Append('\n');

        // Write header values with semicolons
        for (int i = 0; i < headerValues.Count; i++)
        {
            if (i > 0)
                stringBuilder.Append(';');

            stringBuilder.Append(headerValues[i]);
        }

        return stringBuilder.ToString();
#else
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
#endif
    }

    /// <summary>
    /// Computes an HMAC-SHA256 signature for the specified canonical string.
    /// </summary>
    /// <param name="stringToSign">The canonical string produced by <see cref="CreateStringToSign"/>.</param>
    /// <param name="secretKey">The secret key used for HMAC-SHA256 computation.</param>
    /// <returns>A Base64-encoded HMAC-SHA256 signature string.</returns>
    public static string GenerateSignature(
        string stringToSign,
        string secretKey)
    {
        // Convert secret and stringToSign to byte arrays
        var secretBytes = Encoding.UTF8.GetBytes(secretKey);
        var dataBytes = Encoding.UTF8.GetBytes(stringToSign);

#if NETSTANDARD2_0 || NETFRAMEWORK
        // Use traditional approach for .NET Standard 2.0 and .NET Framework
        using var hmac = new HMACSHA256(secretBytes);
        var hash = hmac.ComputeHash(dataBytes);
        return Convert.ToBase64String(hash);
#else
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
#endif
    }

    /// <summary>
    /// Builds a complete <c>Authorization</c> header value for the HMAC scheme.
    /// </summary>
    /// <param name="client">The client identifier.</param>
    /// <param name="signedHeaders">Header names that were included in the signature calculation.</param>
    /// <param name="signature">The Base64-encoded HMAC signature produced by <see cref="GenerateSignature"/>.</param>
    /// <returns>
    /// A header value in the format
    /// <c>HMAC Client={client}&amp;SignedHeaders={headers}&amp;Signature={signature}</c>.
    /// </returns>
    public static string GenerateAuthorizationHeader(
        string client,
        IReadOnlyList<string> signedHeaders,
        string signature)
    {
        const string scheme = DefaultSchemeName;
        const string clientPrefix = " Client=";
        const string signedHeadersPrefix = "&SignedHeaders=";
        const string signaturePrefix = "&Signature=";

#if NETSTANDARD2_0 || NETFRAMEWORK
        var stringBuilder = new StringBuilder();

        // Write scheme
        stringBuilder.Append(scheme);

        // Write client prefix and client
        stringBuilder.Append(clientPrefix);
        stringBuilder.Append(client);

        // Write signedHeaders prefix
        stringBuilder.Append(signedHeadersPrefix);

        // Write signedHeaders (semicolon separated)
        for (int i = 0; i < signedHeaders.Count; i++)
        {
            if (i > 0)
                stringBuilder.Append(';');

            stringBuilder.Append(signedHeaders[i]);
        }

        // Write signature prefix and signature
        stringBuilder.Append(signaturePrefix);
        stringBuilder.Append(signature);

        return stringBuilder.ToString();
#else
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
#endif
    }

    /// <summary>
    /// Performs a constant-time comparison of two strings to prevent timing-based side-channel attacks.
    /// </summary>
    /// <remarks>
    /// Both strings are converted to UTF-8 byte arrays before comparison so the
    /// operation time does not vary with the position of the first differing character.
    /// </remarks>
    /// <param name="left">The first string to compare.</param>
    /// <param name="right">The second string to compare.</param>
    /// <returns><see langword="true"/> if the strings are equal; otherwise, <see langword="false"/>.</returns>
    public static bool FixedTimeEquals(
        string left,
        string right)
    {
        // Convert strings to byte arrays using UTF8 encoding
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);

#if NETSTANDARD2_0 || NETFRAMEWORK
        // Constant-time comparison that does not leak length information.
        // XOR the lengths and accumulate into the result so a length mismatch
        // does not cause an early return (which would be a timing side-channel).
        int result = leftBytes.Length ^ rightBytes.Length;
        int minLength = Math.Min(leftBytes.Length, rightBytes.Length);

        for (int i = 0; i < minLength; i++)
            result |= leftBytes[i] ^ rightBytes[i];

        return result == 0;
#else
        // CryptographicOperations.FixedTimeEquals already handles length
        // differences in constant time by returning false without leaking
        // which bytes differ, but it does reveal differing lengths via timing.
        // For HMAC/SHA256 comparisons the outputs are always the same length,
        // so this is acceptable. Guard with a length check that folds into
        // the result to keep the public API safe for variable-length callers.
        if (leftBytes.Length != rightBytes.Length)
        {
            // Compare left against itself so we still spend time proportional
            // to the input length, then return false.
            CryptographicOperations.FixedTimeEquals(leftBytes, leftBytes);
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
#endif
    }
}
