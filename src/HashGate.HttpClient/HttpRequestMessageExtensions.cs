using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCore.HmacAuthentication.Client;

/// <summary>
/// Provides extension methods for <see cref="HttpRequestMessage"/> to add HMAC authentication headers.
/// These methods enable automatic signing of HTTP requests using HMAC-SHA256 authentication.
/// </summary>
public static class HttpRequestMessageExtensions
{
    /// <summary>
    /// Adds HMAC authentication headers to an HTTP request message using the specified client credentials and signed headers.
    /// This method automatically generates the required authentication headers including timestamp, content hash, and authorization signature.
    /// </summary>
    /// <param name="request">The HTTP request message to add HMAC authentication headers to.</param>
    /// <param name="client">The client identifier (access key ID) used for authentication.</param>
    /// <param name="secret">The secret key used for HMAC-SHA256 signature generation.</param>
    /// <param name="signedHeaders">
    /// An optional list of header names to include in the signature calculation.
    /// If <c>null</c>, the default signed headers (host, x-timestamp, x-content-sha256) will be used.
    /// If provided, the default headers will be merged with the specified headers.
    /// </param>
    /// <returns>A task that represents the asynchronous operation of adding HMAC authentication headers.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="request"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="client"/> or <paramref name="secret"/> is <c>null</c>, empty, or whitespace.</exception>
    /// <remarks>
    /// <para>
    /// This method performs the following operations:
    /// </para>
    /// <list type="number">
    /// <item><description>Adds an x-timestamp header with the current Unix timestamp</description></item>
    /// <item><description>Computes and adds an x-content-sha256 header with the SHA256 hash of the request body</description></item>
    /// <item><description>Creates a canonical string representation of the request</description></item>
    /// <item><description>Generates an HMAC-SHA256 signature of the canonical string</description></item>
    /// <item><description>Adds an Authorization header with the HMAC authentication information</description></item>
    /// </list>
    /// <para>
    /// The method ensures that required headers are always included in the signature, even if not explicitly specified in the signedHeaders parameter.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/data");
    /// await request.AddHmacAuthentication("my-client-id", "my-secret-key");
    ///
    /// // Add custom signed headers
    /// await request.AddHmacAuthentication(
    ///     "my-client-id",
    ///     "my-secret-key",
    ///     ["host", "x-timestamp", "x-content-sha256", "content-type"]
    /// );
    /// </code>
    /// </example>
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

    /// <summary>
    /// Adds HMAC authentication headers to an HTTP request message using the specified authentication options.
    /// This is a convenience method that extracts the client credentials and signed headers from the options object.
    /// </summary>
    /// <param name="request">The HTTP request message to add HMAC authentication headers to.</param>
    /// <param name="options">The HMAC authentication options containing client credentials and configuration.</param>
    /// <returns>A task that represents the asynchronous operation of adding HMAC authentication headers.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="request"/> or <paramref name="options"/> is <c>null</c>.</exception>
    /// <remarks>
    /// This method delegates to the main <see cref="AddHmacAuthentication(HttpRequestMessage, string, string, IReadOnlyList{string}?)"/>
    /// method using the client, secret, and signed headers from the provided options.
    /// </remarks>
    /// <example>
    /// <code>
    /// var options = new HmacAuthenticationOptions
    /// {
    ///     Client = "my-client-id",
    ///     Secret = "my-secret-key",
    ///     SignedHeaders = ["host", "x-timestamp", "x-content-sha256"]
    /// };
    ///
    /// var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/users");
    /// await request.AddHmacAuthentication(options);
    /// </code>
    /// </example>
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

    /// <summary>
    /// Generates a Base64-encoded SHA256 hash of the HTTP request content.
    /// If the request has no content, returns the hash of an empty string.
    /// </summary>
    /// <param name="request">The HTTP request message to generate the content hash for.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains a Base64-encoded SHA256 hash of the request content.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method handles the following scenarios:
    /// </para>
    /// <list type="bullet">
    /// <item><description>If the request has no content, returns <see cref="HmacAuthenticationShared.EmptyContentHash"/></description></item>
    /// <item><description>If the request has content, reads the content as bytes, computes SHA256 hash, and recreates the content stream</description></item>
    /// <item><description>Preserves all original content headers when recreating the content stream</description></item>
    /// </list>
    /// <para>
    /// The method consumes the original content stream and recreates it to ensure the request can still be sent normally.
    /// This is necessary because HTTP content streams can typically only be read once.
    /// </para>
    /// <para>
    /// Uses stack allocation for Base64 conversion when possible for improved performance.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/users");
    /// request.Content = new StringContent("{\"name\":\"John\"}", Encoding.UTF8, "application/json");
    ///
    /// var contentHash = await request.GenerateContentHash();
    /// // contentHash will contain the Base64-encoded SHA256 hash of the JSON content
    /// </code>
    /// </example>
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

    /// <summary>
    /// Retrieves the values of the specified headers from an HTTP request message.
    /// Returns an array of header values in the same order as the provided header names.
    /// </summary>
    /// <param name="request">The HTTP request message to extract header values from.</param>
    /// <param name="signedHeaders">The list of header names whose values should be retrieved.</param>
    /// <returns>
    /// An array of header values corresponding to the signed headers.
    /// If a header is not found, an empty string is returned for that position.
    /// </returns>
    /// <remarks>
    /// This method calls <see cref="GetHeaderValue(HttpRequestMessage, string)"/> for each header name
    /// and collects the results into an array. The order of values matches the order of header names.
    /// </remarks>
    private static string[] GetHeaderValues(
        HttpRequestMessage request,
        IReadOnlyList<string> signedHeaders)
    {
        var headerValues = new string[signedHeaders.Count];

        for (var i = 0; i < signedHeaders.Count; i++)
            headerValues[i] = GetHeaderValue(request, signedHeaders[i]) ?? string.Empty;

        return headerValues;
    }

    /// <summary>
    /// Retrieves the value of a specific header from an HTTP request message.
    /// Handles special cases for standard HTTP headers and searches both request headers and content headers.
    /// </summary>
    /// <param name="request">The HTTP request message to extract the header value from.</param>
    /// <param name="headerName">The name of the header to retrieve (case-insensitive).</param>
    /// <returns>
    /// The header value as a string, or <c>null</c> if the header is not found.
    /// For headers with multiple values, returns a comma-separated string.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method handles the following special cases:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>host</c> - Returns the authority part of the request URI in lowercase</description></item>
    /// <item><description><c>content-type</c> - Returns the content type from content headers</description></item>
    /// <item><description><c>content-length</c> - Returns the content length from content headers</description></item>
    /// <item><description><c>user-agent</c> - Returns the user agent header as a string</description></item>
    /// </list>
    /// <para>
    /// For other headers, searches first in request headers, then in content headers.
    /// Multiple header values are joined with commas as per HTTP specification.
    /// </para>
    /// </remarks>
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
