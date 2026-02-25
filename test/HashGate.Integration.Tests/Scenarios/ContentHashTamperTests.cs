// ContentHashTamperTests — validates that recomputing x-content-sha256 alone is insufficient.
//
// Attack model (sophisticated replay):
//   An attacker intercepts a valid signed POST. They modify the body AND recompute a fresh
//   x-content-sha256 for the new body, but they cannot recompute the Authorization signature
//   (they don't know the shared secret). The old Authorization signature was computed using
//   the OLD content hash. The server catches the discrepancy in step 5 (signature check).
//
// Server validation chain (HmacAuthenticationHandler.HandleAuthenticateAsync):
//   1. Parse Authorization header
//   2. ValidateTimestamp()        → OK (attacker reuses fresh-enough timestamp)
//   3. ValidateContentHash()      → OK (attacker recomputed x-content-sha256 for new body)
//   4. Retrieve client secret     → OK
//   5. Verify HMAC-SHA256 signature:
//       server string-to-sign uses x-content-sha256 = new_hash (from header)
//       expected_sig = HMAC(server_string_to_sign, secret)
//       provided_sig = old Authorization signature (was HMAC'd with old_hash)
//       expected_sig ≠ provided_sig  → Fail("Invalid signature") → 401
//
// This proves that x-content-sha256 is part of the signed payload, so both it and the
// Authorization must be regenerated together for any modification to pass.
//
// How to run:
//   dotnet test test/HashGate.Integration.Tests/ --filter "FullyQualifiedName~ContentHashTamperTests"

namespace HashGate.Integration.Tests.Scenarios;

// Tests that an attacker who recomputes x-content-sha256 for a modified body
// but cannot regenerate the Authorization signature is rejected.
public class ContentHashTamperTests : IClassFixture<TestApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly SignedRequestBuilder _builder;

    public ContentHashTamperTests(TestApplicationFactory factory)
    {
        _client = factory.CreateClient();
        _builder = new SignedRequestBuilder(
            TestApplicationFactory.TestClientId,
            TestApplicationFactory.TestClientSecret);
    }

    // -----------------------------------------------------------------------
    // Control: valid signed request must succeed
    // -----------------------------------------------------------------------

    // Control case: a correctly signed POST returns 2xx.
    [Fact]
    public async Task Given_ValidSignedPost_When_NoTampering_Then_Returns2xx()
    {
        // Arrange
        const string body = """{"orderId":1,"item":"Widget"}""";
        var request = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", body, "application/json");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Attack: modify body + recompute hash, but keep old Authorization
    // -----------------------------------------------------------------------

    // Sophisticated MITM: attacker replaces body AND freshly recomputes x-content-sha256,
    // but cannot recompute the Authorization signature without the shared secret.
    //
    // Step-by-step:
    //   Original signed request: body=A, hash_A=SHA256(A), sig_A=HMAC(host;ts;hash_A, secret)
    //   Attacker builds:          body=B, hash_B=SHA256(B), Authorization still carries sig_A
    //
    //   Server:
    //     ValidateContentHash() → hash_B matches body B → PASSES
    //     GetHeaderValues()     → reads x-content-sha256 = hash_B (attacker's recomputed value)
    //     BuildStringToSign()   → uses hash_B
    //     expectedSig = HMAC(host;ts;hash_B, secret)   ← uses hash_B
    //     providedSig = sig_A = HMAC(host;ts;hash_A, secret)  ← uses hash_A
    //     expectedSig ≠ providedSig → 401
    //
    // This demonstrates that x-content-sha256 is bound to the Authorization signature;
    // an attacker must know the secret to regenerate both.
    [Fact]
    public async Task Given_ValidSignedPost_When_BodyChangedAndHashRecomputed_ButAuthorizationUnchanged_Then_Returns401()
    {
        // Arrange: build a valid signed request for body A
        const string originalBody = """{"orderId":1,"item":"Widget"}""";
        var original = _builder.BuildSignedRequest(
            HttpMethod.Post, "/api/echo", originalBody, "application/json");

        // Capture the original Authorization (sig_A) and x-timestamp from the signed request
        var originalAuthorization = original.Headers.GetValues(
            HmacAuthenticationShared.AuthorizationHeaderName).First();
        var originalTimestamp = original.Headers.GetValues(
            HmacAuthenticationShared.TimeStampHeaderName).First();

        // Attacker prepares body B and freshly computes its SHA256
        const string tamperedBody = """{"orderId":999,"item":"INJECTED_PAYLOAD"}""";
        var tamperedBodyBytes = Encoding.UTF8.GetBytes(tamperedBody);
        var recomputedHash = Convert.ToBase64String(SHA256.HashData(tamperedBodyBytes));

        // Attacker assembles a new request:
        //   body=B, x-content-sha256=hash_B (fresh), x-timestamp=original, Authorization=sig_A (stale)
        var attackRequest = new HttpRequestMessage(HttpMethod.Post, "/api/echo");
        attackRequest.Content = new ByteArrayContent(tamperedBodyBytes);
        attackRequest.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

        attackRequest.Headers.TryAddWithoutValidation(
            HmacAuthenticationShared.ContentHashHeaderName, recomputedHash);
        attackRequest.Headers.TryAddWithoutValidation(
            HmacAuthenticationShared.TimeStampHeaderName, originalTimestamp);
        attackRequest.Headers.TryAddWithoutValidation(
            HmacAuthenticationShared.AuthorizationHeaderName, originalAuthorization); // sig_A — stale

        // Act
        var response = await _client.SendAsync(attackRequest, TestContext.Current.CancellationToken);

        // Assert — 401: ValidateContentHash passes but signature check fails
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
