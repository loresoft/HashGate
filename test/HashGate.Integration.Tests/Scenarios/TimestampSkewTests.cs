// TimestampSkewTests — validates replay-attack prevention via timestamp validation.
//
// Tolerance window: 5 minutes (HmacAuthenticationSchemeOptions.ToleranceWindow default).
// Handler code (HmacAuthenticationHandler.ValidateTimestamp):
//   var requestTime  = DateTimeOffset.FromUnixTimeSeconds(timestamp);
//   var now          = DateTimeOffset.UtcNow;               // direct call, no abstraction
//   var timeDifference = Math.Abs((now - requestTime).TotalMinutes);
//   return timeDifference <= Options.ToleranceWindow;        // inclusive: <= 5 minutes
//
// CLOCK NOTE: The library has NO ISystemClock or TimeProvider abstraction.
//   DateTimeOffset.UtcNow is called directly at authentication time.
//   Tests control timing by passing timestampOverride to SignedRequestBuilder, which
//   sets x-timestamp to a specific Unix-seconds value. When the entire request is signed
//   with an offset timestamp, the Authorization signature reflects that timestamp value,
//   so the signature check still passes — only the tolerance gate determines the result.
//
// TOLERANCE_SECONDS = 300  (5 min × 60)
// Boundary is inclusive at exactly 5 minutes (timeDifference <= 5.0 → passes).
//
// How to run:
//   dotnet test test/HashGate.Integration.Tests/ --filter "FullyQualifiedName~TimestampSkewTests"

namespace HashGate.Integration.Tests.Scenarios;

// Tests timestamp validation, anti-replay enforcement, and clock-skew boundaries.
public class TimestampSkewTests : IClassFixture<TestApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly SignedRequestBuilder _builder;

    public TimestampSkewTests(TestApplicationFactory factory)
    {
        _client = factory.CreateClient();
        _builder = new SignedRequestBuilder(
            TestApplicationFactory.TestClientId,
            TestApplicationFactory.TestClientSecret);
    }

    // -----------------------------------------------------------------------
    // Control: current timestamp is within tolerance
    // -----------------------------------------------------------------------

    // Control case: signing with the current timestamp (0 minutes skew) succeeds.
    // Confirms the baseline scenario works before testing failure paths.
    [Fact]
    public async Task Given_CurrentTimestamp_When_ValidRequest_Then_Returns2xx()
    {
        // Arrange — timestampOverride = null → DateTimeOffset.UtcNow used by builder
        var request = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 0-min skew is well within the 5-min tolerance window
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Attack: replace x-timestamp after signing (replay attack)
    // -----------------------------------------------------------------------

    // Replay attack simulation: build a valid signed request, then overwrite x-timestamp
    // with a stale value (60 minutes in the past) WITHOUT re-signing.
    //
    // The Authorization signature was computed with the ORIGINAL (fresh) timestamp.
    // After replacement the x-timestamp is 60 minutes old → 60 > 5 → ValidateTimestamp() fails.
    // The timestamp check fires BEFORE the signature check, proving replay protection
    // does not depend on the attacker lacking the secret key.
    [Fact]
    public async Task Given_FreshSignedRequest_When_TimestampReplacedWithStaleValue_Then_Returns401()
    {
        // Arrange: build a valid signed request with current timestamp
        var request = _builder.BuildSignedRequest(HttpMethod.Get, "/api/echo");

        // Replay attack: overwrite x-timestamp to 60 minutes ago without re-signing
        var staleTimestamp = DateTimeOffset.UtcNow.AddMinutes(-60).ToUnixTimeSeconds().ToString();
        request.Headers.Remove(HmacAuthenticationShared.TimeStampHeaderName);
        request.Headers.TryAddWithoutValidation(HmacAuthenticationShared.TimeStampHeaderName, staleTimestamp);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 401: ValidateTimestamp rejects the 60-min-old timestamp
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Clock-skew boundary: just inside tolerance (4 minutes) → must pass
    // -----------------------------------------------------------------------

    // Boundary test: timestamp 4 minutes in the past.
    // timeDifference ≈ 4.0 minutes; 4.0 <= 5 → ValidateTimestamp() → true → 2xx.
    //
    // The entire request (including Authorization) is signed with the 4-min-old timestamp,
    // so the signature check passes independently of the tolerance gate.
    [Fact]
    public async Task Given_TimestampJustInsideTolerance_When_SignedAndSent_Then_Returns2xx()
    {
        // Arrange — TOLERANCE_SECONDS = 300; 4 min (240 s) is inside the 5-min window
        var timestamp = DateTimeOffset.UtcNow.AddMinutes(-4).ToUnixTimeSeconds();
        var request = _builder.BuildSignedRequest(
            HttpMethod.Get, "/api/echo", timestampOverride: timestamp);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 4 min < 5 min tolerance: accepted
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Clock-skew boundary: just outside tolerance (6 minutes) → must fail
    // -----------------------------------------------------------------------

    // Boundary test: timestamp 6 minutes in the past.
    // timeDifference ≈ 6.0 minutes; 6.0 > 5 → ValidateTimestamp() → false → 401.
    //
    // The request is fully signed with the 6-min-old timestamp. The tolerance gate
    // fires before the signature check, so 401 is returned regardless of key knowledge.
    [Fact]
    public async Task Given_TimestampJustOutsideTolerance_When_SignedAndSent_Then_Returns401()
    {
        // Arrange — 6 min (360 s) is outside the 5-min tolerance window
        var timestamp = DateTimeOffset.UtcNow.AddMinutes(-6).ToUnixTimeSeconds();
        var request = _builder.BuildSignedRequest(
            HttpMethod.Get, "/api/echo", timestampOverride: timestamp);

        // Act
        var response = await _client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert — 6 min > 5 min tolerance: rejected
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
