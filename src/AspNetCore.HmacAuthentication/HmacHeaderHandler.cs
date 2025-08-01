using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;

namespace AspNetCore.HmacAuthentication;

public class HmacAuthenticationHttpHandler : DelegatingHandler
{
    // These should be provided/configured externally in a real scenario
    private readonly string _clientId = "myClient";
    private readonly string _clientSecret = "superSecret";
    private readonly string[] _signedHeaders = ["host"];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // If the request does not already have an Authorization header, add HMAC headers
        if (request.Headers.Authorization == null)
            await AddHmacHeaders(request);

        return await base.SendAsync(request, cancellationToken);
    }

    private async Task AddHmacHeaders(HttpRequestMessage request)
    {
        // 1. Timestamp
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // 2. Canonical headers
        var canonicalHeaders = GetCanonicalHeaders(request, _signedHeaders);

        // 3. Read body
        string body = await GetRequestBody(request);

        // 4. Build string to sign
        var stringToSign = CreateStringToSign(
            request.Method.Method,
            request.RequestUri?.AbsolutePath,
            request.RequestUri?.Query,
            timestamp,
            canonicalHeaders,
            _signedHeaders,
            body
        );

        // 5. Generate signature
        var signature = GenerateHmacSignature(stringToSign, _clientSecret);

        // 6. Build Authorization header
        var authHeader = $"HMAC {_clientId}:{timestamp}:{string.Join(";", _signedHeaders)}:{signature}";
        request.Headers.Authorization = new AuthenticationHeaderValue("HMAC", authHeader);
    }

    private static async Task<string> GetRequestBody(HttpRequestMessage request)
    {
        if (request.Content == null || request.Content.Headers.ContentLength == 0)
            return string.Empty;

        return await request.Content.ReadAsStringAsync();
    }

    private static string GetCanonicalHeaders(
        HttpRequestMessage request,
        IReadOnlyCollection<string> signedHeaders)
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
            var headerValue = GetHeaderValue(request, lower);
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

    private static string? GetHeaderValue(
        HttpRequestMessage request,
        string headerName)
    {
        if (headerName.Equals("host", StringComparison.InvariantCultureIgnoreCase))
        {
            if (request.Headers.Host != null)
                return request.Headers.Host.ToLowerInvariant();

            if (request.Headers.TryGetValues("Host", out var hostValue))
                return hostValue.FirstOrDefault()?.ToString().ToLowerInvariant();

            return request.RequestUri?.Host.ToLowerInvariant();
        }

        if (headerName.Equals("content-type", StringComparison.InvariantCultureIgnoreCase))
            return request.Content?.Headers.ContentType?.ToString();

        if (headerName.Equals("content-length", StringComparison.InvariantCultureIgnoreCase))
            return request.Content?.Headers.ContentLength?.ToString();

        if (headerName.Equals("user-agent", StringComparison.InvariantCultureIgnoreCase))
            return request.Headers.UserAgent.ToString();

        if (request.Headers.TryGetValues(headerName, out var values))
            return values != null ? string.Join(",", values) : null;

        if (request.Content != null && request.Content.Headers.TryGetValues(headerName, out var contentValues))
            return contentValues != null ? string.Join(",", contentValues) : null;

        return null;
    }

    private static string CreateStringToSign(
        string method,
        string? path,
        string? queryString,
        long timestamp,
        string canonicalHeaders,
        IEnumerable<string> signedHeaders,
        string body)
    {
        // Use a pooled StringBuilder for efficiency
        var sb = StringBuilderCache.Acquire();

        // format the string to sign
        sb.Append(method).Append('\n');
        sb.Append(path ?? string.Empty).Append(queryString ?? string.Empty).Append('\n');
        sb.Append(timestamp).Append('\n');
        sb.Append(canonicalHeaders).Append('\n');
        sb.AppendJoin(';', signedHeaders).Append('\n');
        sb.Append(body);

        return StringBuilderCache.ToString(sb);
    }

    private static string GenerateHmacSignature(
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
}
