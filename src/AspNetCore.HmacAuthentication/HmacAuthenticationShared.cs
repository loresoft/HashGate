using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace AspNetCore.HmacAuthentication;

public static class HmacAuthenticationShared
{
    public const string DefaultSchemeName = "HMAC";

    public const string AuthorizationHeaderName = "Authorization";
    public const string HostHeaderName = "Host";
    public const string ContentTypeHeaderName = "Content-Type";
    public const string ContentLengthHeaderName = "Content-Length";
    public const string UserAgentHeaderName = "User-Agent";
    public const string DateHeaderName = "Date";
    public const string XDateHeaderName = "x-date";


    public const string TimeStampHeaderName = "x-timestamp";
    public const string ContentHashHeaderName = "x-content-sha256";

    // Base64 for SHA256 of empty string
    public const string EmptyContentHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    public static readonly string[] DefaultSignedHeaders = ["host", TimeStampHeaderName, ContentHashHeaderName];

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
