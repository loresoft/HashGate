using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCore.HmacAuthentication.Client;

public static class HttpRequestMessageExtensions
{
    public static async Task AddHmacAuthentication(
        this HttpRequestMessage request,
        string client,
        string secret,
        IReadOnlyList<string>? signedHeaders = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        // ensure required headers are present
        if (signedHeaders == null)
            signedHeaders = HmacAuthenticationShared.DefaultSignedHeaders;
        else
            signedHeaders = [.. HmacAuthenticationShared.DefaultSignedHeaders.Union(signedHeaders)];

        // add timestamp header
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        request.Headers.Add(HmacAuthenticationShared.TimeStampHeaderName, timestamp.ToString());

        // compute content hash
        var contentHash = await GenerateContentHash(request);
        request.Headers.Add(HmacAuthenticationShared.ContentHashHeaderName, contentHash);

        // get header values
        var headerValues = GetHeaderValues(request, signedHeaders);

        // create string to sign
        var stringToSign = HmacAuthenticationShared.CreateStringToSign(
            method: request.Method.Method,
            pathAndQuery: request.RequestUri?.PathAndQuery ?? string.Empty,
            headerValues: headerValues);

        // compute signature
        var signature = HmacAuthenticationShared.GenerateSignature(stringToSign, secret);

        // Build Authorization header
        var authorizationHeader = HmacAuthenticationShared.GenerateAuthorizationHeader(
            client: client,
            signedHeaders: signedHeaders,
            signature: signature);

        // Add Authorization header to request
        request.Headers.Add(HmacAuthenticationShared.AuthorizationHeaderName, authorizationHeader);
    }


    public static Task AddHmacAuthentication(
        this HttpRequestMessage request,
        HmacAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);

        return request.AddHmacAuthentication(
            client: options.Client,
            secret: options.Secret,
            signedHeaders: options.SignedHeaders);
    }


    public static async Task<string> GenerateContentHash(this HttpRequestMessage request)
    {
        if (request.Content == null)
            return HmacAuthenticationShared.EmptyContentHash;

        byte[] bodyBytes = await request.Content.ReadAsByteArrayAsync();
        var hashBytes = SHA256.HashData(bodyBytes);

        // consume the content stream, need to recreate it
        var originalContent = new ByteArrayContent(bodyBytes);
        foreach (var header in request.Content.Headers)
            originalContent.Headers.TryAddWithoutValidation(header.Key, header.Value);

        // Restore content with headers
        request.Content = originalContent;

        // 32 bytes SHA256 -> 44 chars base64
        Span<char> base64 = stackalloc char[44];
        if (Convert.TryToBase64Chars(hashBytes, base64, out int charsWritten))
            return new string(base64[..charsWritten]);

        // if stackalloc is not large enough (should not happen for SHA256)
        return Convert.ToBase64String(hashBytes);
    }


    private static string[] GetHeaderValues(
        HttpRequestMessage request,
        IReadOnlyList<string> signedHeaders)
    {
        var headerValues = new string[signedHeaders.Count];

        for (var i = 0; i < signedHeaders.Count; i++)
            headerValues[i] = GetHeaderValue(request, signedHeaders[i]) ?? string.Empty;

        return headerValues;
    }

    private static string? GetHeaderValue(
        HttpRequestMessage request,
        string headerName)
    {
        if (headerName.Equals("host", StringComparison.InvariantCultureIgnoreCase))
            return request.RequestUri?.Authority.ToLowerInvariant();

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
}
