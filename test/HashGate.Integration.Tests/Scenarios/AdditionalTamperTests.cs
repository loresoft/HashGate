// AdditionalTamperTests — structural and boundary attack scenarios.
//
// Covers:
//   1.  Query-string tampering           — /api/echo?page=1 signed, ?page=99 sent
//   2.  HTTP method tampering            — POST signed, GET sent
//   3.  Path tampering                   — /api/echo signed, /api/echo/extended sent
//   4.  Non-default signed-header order  — server uses order from Authorization header → 2xx
//   5.  Missing x-content-sha256         — header removed after signing → 401
//   6.  Missing x-timestamp              — header removed after signing → 401
//   7.  Missing Authorization            — header removed after signing → 401
//   8.  Bodyless GET correctly signed    → 2xx (uses EmptyContentHash)
//   9.  Bodyless DELETE correctly signed → 2xx (uses EmptyContentHash)
//   10. Content-Type NOT in signed headers — tampered → still 2xx (not protected by default)
//   11. Content-Type IN signed headers    — tampered → 401 (signature mismatch)
//
// Server string-to-sign = METHOD\npathAndQuery\nhdrVal1;hdrVal2;...
// Any change to method, path, query string, or signed header values invalidates the signature.
//
// How to run:
//   dotnet test test/HashGate.Integration.Tests/ --filter "FullyQualifiedName~AdditionalTamperTests"

namespace HashGate.Integration.Tests.Scenarios;

// Additional tamper scenarios covering query strings, HTTP methods, path changes,
// header canonicalization, missing required headers, bodyless requests, and
// Content-Type tamper behaviour (when signed vs. not signed).
public class AdditionalTamperTests : IClassFixture<TestApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly SignedRequestBuilder _builder;

    public AdditionalTamperTests(TestApplicationFactory factory)
    {
        _client = factory.CreateClient();
        _builder = new SignedRequestBuilder(
            TestApplicationFactory.TestClientId,
            TestApplicationFactory.TestClientSecret);
    }

    // -----------------------------------------------------------------------
    // 1. Query-string tampering
    // -----------------------------------------------------------------------

    // Sign /api/echo?page=1, then send the same headers against /api/echo?page=99.
    // String-to-sign includes the full path+query; mismatch → signature check fails → 401.
    [Fact]
    public async Task Given_QueryStringSigned_When_QueryStringTampered_Then_Returns401()
    {
        // Arrange — sign against ?page=1
        var original = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo?page=1");

        // Tamper: same headers, different query string
        var tampered = new HttpRequestMessage(HttpMethod.Get, "/api/echo?page=99");
        CopyRequestHeaders(original, tampered);

        // Act
        var response = await _client.SendAsync(tampered, TestContext.Current.CancellationToken);

        // Assert — 401: server recomputes string-to-sign with ?page=99, signature mismatch
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 2. HTTP method tampering
    // -----------------------------------------------------------------------

    // Sign a POST request, then send the same Authorization headers as a GET.
    // String-to-sign includes the method; POST→GET mismatch → signature check fails → 401.
    [Fact]
    public async Task Given_PostSigned_When_MethodChangedToGet_Then_Returns401()
    {
        // Arrange — sign as POST (body = null → EmptyContentHash)
        var original = _builder.BuildSignedRequest(HttpMethod.Post, "/api/echo");

        // Tamper: change method to GET, keep all signed headers
        var tampered = new HttpRequestMessage(HttpMethod.Get, "/api/echo");
        CopyRequestHeaders(original, tampered);

        // Act
        var response = await _client.SendAsync(tampered, TestContext.Current.CancellationToken);

        // Assert — 401: server builds string-to-sign with GET, original sig used POST → mismatch
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 3. Path tampering
    // -----------------------------------------------------------------------

    // Sign GET /api/echo, then send the same headers to GET /api/echo/extended.
    // The path component differs in string-to-sign → 401.
    [Fact]
    public async Task Given_PathSigned_When_PathChanged_Then_Returns401()
    {
        // Arrange — sign against /api/echo
        var original = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Tamper: different route, same headers
        var tampered = new HttpRequestMessage(HttpMethod.Get, "/api/echo/extended");
        CopyRequestHeaders(original, tampered);

        // Act
        var response = await _client.SendAsync(tampered, TestContext.Current.CancellationToken);

        // Assert — 401: path mismatch in string-to-sign → signature check fails
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 4. Non-default signed-header order → still 2xx
    // -----------------------------------------------------------------------

    // Sign with header order ["x-timestamp", "host", "x-content-sha256"] instead of the
    // default ["host", "x-timestamp", "x-content-sha256"].
    //
    // The server uses the SignedHeaders order from the Authorization header
    // (HmacAuthenticationHandler.GetHeaderValues reads hmacHeader.SignedHeaders in order),
    // so any consistent ordering must be accepted as long as the signature matches.
    [Fact]
    public async Task Given_NonDefaultSignedHeaderOrder_When_ValidRequest_Then_Returns2xx()
    {
        // Arrange — custom order: timestamp first, then host, then content-hash
        string[] customOrder =
        [
            HmacAuthenticationShared.TimeStampHeaderName,   // "x-timestamp"
            "host",
            HmacAuthenticationShared.ContentHashHeaderName  // "x-content-sha256"
        ];

        var request = _builder.BuildSignedRequest(
            HttpMethod.Get, "/api/echo", signedHeaders: customOrder);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 2xx: server respects the order declared in SignedHeaders parameter
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 5. Missing x-content-sha256 → 401
    // -----------------------------------------------------------------------

    // Remove x-content-sha256 after signing.
    // HmacAuthenticationHandler.ValidateContentHash():
    //   Request.Headers.TryGetValue("x-content-sha256", ...) → false → returns false → 401.
    [Fact]
    public async Task Given_MissingContentHashHeader_When_RequestSent_Then_Returns401()
    {
        // Arrange
        var request = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Tamper: strip x-content-sha256
        request.Headers.Remove(HmacAuthenticationShared.ContentHashHeaderName);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 6. Missing x-timestamp → 401
    // -----------------------------------------------------------------------

    // Remove x-timestamp after signing.
    // HmacAuthenticationHandler.ValidateTimestamp():
    //   GetHeaderValue("x-timestamp") → null/empty → long.TryParse fails → returns false → 401.
    [Fact]
    public async Task Given_MissingTimestampHeader_When_RequestSent_Then_Returns401()
    {
        // Arrange
        var request = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Tamper: strip x-timestamp
        request.Headers.Remove(HmacAuthenticationShared.TimeStampHeaderName);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 7. Missing Authorization → 401
    // -----------------------------------------------------------------------

    // Remove the Authorization header entirely.
    // HmacAuthenticationHandler.HandleAuthenticateAsync():
    //   string.IsNullOrEmpty(authorizationHeader) → AuthenticateResult.NoResult()
    //   RequireAuthorization() policy then returns 401 (no authenticated user).
    [Fact]
    public async Task Given_MissingAuthorizationHeader_When_RequestSent_Then_Returns401()
    {
        // Arrange
        var request = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Tamper: strip Authorization
        request.Headers.Remove(HmacAuthenticationShared.AuthorizationHeaderName);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — handler returns NoResult() → authorization policy → 401
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 8. Bodyless GET with correct signing → 2xx
    // -----------------------------------------------------------------------

    // A GET with no body must use EmptyContentHash ("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=").
    // Verifies that the empty-body path through GenerateContentHash() works end-to-end.
    //
    // Server source: GenerateContentHash() returns EmptyContentHash when
    //   Request.ContentLength == 0 || Request.Body == Stream.Null
    [Fact]
    public async Task Given_BodylessGet_When_CorrectlySigned_Then_Returns2xx()
    {
        // Arrange — no body: builder uses EmptyContentHash automatically
        var request = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Assert x-content-sha256 header is the well-known empty hash
        Assert.Contains(
            request.Headers.GetValues(HmacAuthenticationShared.ContentHashHeaderName),
            v => v == HmacAuthenticationShared.EmptyContentHash);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 9. Bodyless DELETE with correct signing → 2xx
    // -----------------------------------------------------------------------

    // A DELETE with no body must also use EmptyContentHash.
    // Ensures the handler works correctly for all idempotent bodyless methods.
    [Fact]
    public async Task Given_BodylessDelete_When_CorrectlySigned_Then_Returns2xx()
    {
        // Arrange
        var request = _builder.BuildSignedRequest(HttpMethod.Delete, "/api/echo");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 10. Content-Type NOT in signed headers — tampered → still 2xx
    // -----------------------------------------------------------------------

    // Default signed headers = ["host", "x-timestamp", "x-content-sha256"].
    // Content-Type is NOT in the default set, so changing it does not affect the signature.
    //
    // This documents the expected (and acceptable) behavior: if a field is not included
    // in SignedHeaders, altering it alone cannot be detected by the HMAC check.
    // Callers requiring Content-Type protection must explicitly add it to SignedHeaders.
    [Fact]
    public async Task Given_ContentTypeNotInSignedHeaders_When_ContentTypeTampered_Then_Returns2xx()
    {
        // Arrange — sign with default headers (content-type excluded)
        const string body = """{"orderId":1}""";
        var request = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", body, "application/json");

        // Tamper: change Content-Type (NOT part of signature)
        request.Content!.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 2xx: content-type is not signed → auth still passes
        // NOTE: This is documented behavior. To protect content-type, include it in signedHeaders.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 11. Content-Type IN signed headers — tampered → 401
    // -----------------------------------------------------------------------

    // When content-type is explicitly included in SignedHeaders, changing it after signing
    // invalidates the HMAC signature.
    //
    // Server lookup: HmacAuthenticationHandler.GetHeaderValue("content-type")
    //   → Request.ContentType?.ToString()
    //   The tampered Content-Type is read, the server's recomputed string-to-sign differs
    //   from the one used to produce the signature → 401.
    [Fact]
    public async Task Given_ContentTypeInSignedHeaders_When_ContentTypeTampered_Then_Returns401()
    {
        // Arrange — explicit signedHeaders that includes content-type
        string[] headersWithContentType =
        [
            "host",
            HmacAuthenticationShared.TimeStampHeaderName,
            HmacAuthenticationShared.ContentHashHeaderName,
            HmacAuthenticationShared.ContentTypeHeaderName   // "Content-Type"
        ];

        const string body = """{"orderId":1}""";
        var request = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", body, "application/json",
            signedHeaders: headersWithContentType);

        // Tamper: change Content-Type; Authorization still signed with "application/json"
        request.Content!.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 401: server reads "text/plain", expected sig used "application/json" → mismatch
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    // Copies all request headers from source to destination
    // using TryAddWithoutValidation to avoid header restriction exceptions.
    // Content headers are not transferred (content tamper tests handle those separately).
    private static void CopyRequestHeaders(
        HttpRequestMessage source,
        HttpRequestMessage destination)
    {
        foreach (var header in source.Headers)
            destination.Headers.TryAddWithoutValidation(header.Key, header.Value);
    }
}
