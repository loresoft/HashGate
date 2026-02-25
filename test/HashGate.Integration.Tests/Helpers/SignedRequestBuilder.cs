namespace HashGate.Integration.Tests.Helpers;

// Builds signed HttpRequestMessage instances for integration tests.
// The returned message has Authorization, x-timestamp, and x-content-sha256 headers
// already set. Callers may tamper with headers or content after calling
// BuildSignedRequest to simulate MITM attacks.
public sealed class SignedRequestBuilder
{
    private readonly string _clientId;
    private readonly string _secretKey;
    private readonly string _host;

    public SignedRequestBuilder(
        string clientId,
        string secretKey,
        string host = "localhost")
    {
        _clientId = clientId;
        _secretKey = secretKey;
        _host = host;
    }

    // Creates a fully signed HttpRequestMessage.
    public HttpRequestMessage BuildSignedRequest(
        HttpMethod method,
        string pathAndQuery,
        string? body = null,
        string? contentType = null,
        long? timestampOverride = null,
        string[]? signedHeaders = null)
    {
        // --- 1. Timestamp ---
        var timestamp = (timestampOverride ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()).ToString();

        // --- 2. Content hash ---
        byte[]? bodyBytes = null;
        string contentHash;
        if (!string.IsNullOrEmpty(body))
        {
            bodyBytes = Encoding.UTF8.GetBytes(body);
            contentHash = Convert.ToBase64String(SHA256.HashData(bodyBytes));
        }
        else
        {
            // README Content Hash: empty body → well-known constant SHA256("") base64
            contentHash = HmacAuthenticationShared.EmptyContentHash;
        }

        // --- 3. Signed header list ---
        var headersToSign = signedHeaders ?? HmacAuthenticationShared.DefaultSignedHeaders;

        // --- 4. Header values in signedHeaders order (must match server-side lookup) ---
        var headerValues = BuildHeaderValues(headersToSign, _host, timestamp, contentHash, contentType);

        // --- 5. String-to-sign: METHOD\npathAndQuery\nhdrVal1;hdrVal2;... ---
        var stringToSign = HmacAuthenticationShared.CreateStringToSign(
            method.Method,
            pathAndQuery,
            headerValues);

        // --- 6. HMAC-SHA256 signature ---
        var signature = HmacAuthenticationShared.GenerateSignature(stringToSign, _secretKey);

        // --- 7. Authorization header ---
        var authorization = HmacAuthenticationShared.GenerateAuthorizationHeader(
            _clientId, headersToSign, signature);

        // --- 8. Assemble HttpRequestMessage ---
        var request = new HttpRequestMessage(method, pathAndQuery);

        request.Headers.TryAddWithoutValidation(HmacAuthenticationShared.AuthorizationHeaderName, authorization);
        request.Headers.TryAddWithoutValidation(HmacAuthenticationShared.TimeStampHeaderName, timestamp);
        request.Headers.TryAddWithoutValidation(HmacAuthenticationShared.ContentHashHeaderName, contentHash);

        if (bodyBytes != null)
        {
            request.Content = new ByteArrayContent(bodyBytes);
            if (contentType != null)
                request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        }

        return request;
    }


    // Returns header values in the exact order dictated by headersToSign.
    // The server performs the same lookup in HmacAuthenticationHandler.GetHeaderValues().
    private static string[] BuildHeaderValues(
        string[] headersToSign,
        string host,
        string timestamp,
        string contentHash,
        string? contentType)
    {
        var values = new string[headersToSign.Length];

        for (int i = 0; i < headersToSign.Length; i++)
        {
            var header = headersToSign[i].ToLowerInvariant();

            if (header == "host")
                values[i] = host;
            else if (header == HmacAuthenticationShared.TimeStampHeaderName)
                values[i] = timestamp;
            else if (header == HmacAuthenticationShared.ContentHashHeaderName)
                values[i] = contentHash;
            else if (header.Equals(HmacAuthenticationShared.ContentTypeHeaderName, StringComparison.InvariantCultureIgnoreCase))
                values[i] = contentType ?? string.Empty;
            else
                values[i] = string.Empty;
        }

        return values;
    }
}
