// BodyTamperTests — validates protection against MITM body substitution.
//
// Attack model:
//   An attacker intercepts a valid signed POST request and replaces the body
//   with malicious content without updating x-content-sha256 or the Authorization
//   signature. The handler detects the mismatch in ValidateContentHash().
//
// Server validation chain (HmacAuthenticationHandler.HandleAuthenticateAsync):
//   1. Parse Authorization header
//   2. ValidateTimestamp()        → checks x-timestamp within ±5 min of UtcNow
//   3. ValidateContentHash()      → computes SHA256(body), compares with x-content-sha256
//   4. Retrieve client secret
//   5. Verify HMAC-SHA256 signature
//
// In a body-tamper attack, step 3 fails because SHA256(tampered_body) ≠ x-content-sha256.
//
// How to run:
//   dotnet test test/HashGate.Integration.Tests/ --filter "FullyQualifiedName~BodyTamperTests"

namespace HashGate.Integration.Tests.Scenarios;

// Tests that body tampering (replacing body content after signing) is detected
// by the x-content-sha256 header validation in HmacAuthenticationHandler.
public class BodyTamperTests : IClassFixture<TestApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly SignedRequestBuilder _builder;

    public BodyTamperTests(TestApplicationFactory factory)
    {
        _client = factory.CreateClient();
        _builder = new SignedRequestBuilder(
            TestApplicationFactory.TestClientId,
            TestApplicationFactory.TestClientSecret);
    }

    // -----------------------------------------------------------------------
    // Control: valid request must succeed
    // -----------------------------------------------------------------------

    // Control case: a correctly signed POST with JSON body returns 2xx.
    // Confirms the test infrastructure is working before testing tamper scenarios.
    [Fact]
    public async Task Given_ValidSignedPost_When_BodyNotTampered_Then_Returns2xx()
    {
        // Arrange
        const string body = """{"orderId":1,"item":"Widget"}""";
        var request = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", body, "application/json");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 200 OK expected
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Attack 1: swap body after signing, keep original x-content-sha256
    // -----------------------------------------------------------------------

    // MITM attack: sign with body A, replace body with body B before sending.
    // x-content-sha256 still reflects body A, so server detects mismatch → 401.
    //
    // ValidateContentHash():
    //   computedHash = SHA256(body_B)
    //   headerHash   = SHA256(body_A)   ← stale
    //   FixedTimeEquals(computedHash, headerHash) → false → Fail("Invalid content hash header") → 401
    [Fact]
    public async Task Given_ValidSignedPost_When_BodyTamperedAfterSigning_Then_Returns401()
    {
        // Arrange — sign with original body
        const string originalBody = """{"orderId":1,"item":"Widget"}""";
        var request = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", originalBody, "application/json");

        // Tamper: replace body content; x-content-sha256 and Authorization are NOT updated
        const string tamperedBody = """{"orderId":999,"item":"TAMPERED_PAYLOAD"}""";
        request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(tamperedBody));
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 401 Unauthorized: content hash mismatch
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Attack 2: replace body with empty content, keep hash for original body
    // -----------------------------------------------------------------------

    // Edge-case body tamper: attacker strips the body (sets it to empty) but leaves
    // the original non-empty x-content-sha256 in place.
    //
    // ValidateContentHash():
    //   computedHash = EmptyContentHash ("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
    //   headerHash   = SHA256(originalBody)  ← stale
    //   mismatch → 401
    //
    // Note: HmacAuthenticationHandler.GenerateContentHash() returns EmptyContentHash when
    //   Request.ContentLength == 0 || Request.Body == Stream.Null  (verified in source).
    [Fact]
    public async Task Given_ValidSignedPost_When_BodyReplacedWithEmpty_Then_Returns401()
    {
        // Arrange — sign with non-empty body
        const string originalBody = """{"orderId":1,"item":"Widget"}""";
        var request = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", originalBody, "application/json");

        // Tamper: strip body content entirely
        request.Content = new ByteArrayContent(Array.Empty<byte>());
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 401 Unauthorized: empty-body hash ≠ original body hash
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
