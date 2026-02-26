namespace HashGate.Integration.Tests.Scenarios;

// Tests token-bucket rate limiting: limit enforcement, per-endpoint independence,
// burst factor, and 429 response shape.
public class RateLimitTests
{
    // -----------------------------------------------------------------------
    // 1. Control: request within limit → 200
    // -----------------------------------------------------------------------

    // Baseline: a single signed request to a rate-limited endpoint with high limits (100 RPP)
    // passes the per-endpoint policy, then passes auth → 200 OK.
    [Fact]
    public async Task Given_RequestWithinLimit_When_Sent_Then_Returns200()
    {
        // Arrange — TokenLimit = 100 × 1 = 100; one request is well within limit
        using var factory = new RateLimitedApplicationFactory(requestsPerPeriod: 100, burstFactor: 1);
        var client = factory.CreateClient();
        var builder = new SignedRequestBuilder(
            RateLimitedApplicationFactory.ClientId,
            RateLimitedApplicationFactory.ClientSecret);

        // Act
        var response = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // 2. Limit enforced: exceeding token limit → 429
    // -----------------------------------------------------------------------

    // TokenLimit = 2 × 1 = 2.
    // Requests 1 and 2 consume both tokens. Request 3 is rejected.
    [Fact]
    public async Task Given_LimitExhausted_When_AdditionalRequestSent_Then_Returns429()
    {
        // Arrange — TokenLimit = 2 × 1 = 2
        using var factory = new RateLimitedApplicationFactory(requestsPerPeriod: 2, burstFactor: 1);
        var client = factory.CreateClient();
        var builder = new SignedRequestBuilder(
            RateLimitedApplicationFactory.ClientId,
            RateLimitedApplicationFactory.ClientSecret);

        // Act — consume both tokens, then send one more
        var response1 = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        var response2 = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // 3rd request — bucket empty
        var response3 = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response1.StatusCode);   // token 1 consumed
        Assert.Equal(HttpStatusCode.OK, response2.StatusCode);   // token 2 consumed
        Assert.Equal(HttpStatusCode.TooManyRequests, response3.StatusCode); // no tokens left
    }

    // -----------------------------------------------------------------------
    // 3. 429 response shape: status code, Retry-After header, body
    // -----------------------------------------------------------------------

    // Verifies the complete rejection response from RequestLimitExtensions.OnRejectedAsync:
    //   • HTTP 429 TooManyRequests
    //   • Retry-After: 5  (= Math.Max(1, (int)Math.Min(5, 60)) for 1-minute period)
    //   • Body: "Rate limit exceeded. Retry shortly."
    //
    // TokenLimit = 1 × 1 = 1. The 2nd request triggers the rejection.
    [Fact]
    public async Task Given_LimitExceeded_When_Rejected_Then_ResponseHas429AndRetryAfterAndBody()
    {
        // Arrange — TokenLimit = 1 × 1 = 1
        using var factory = new RateLimitedApplicationFactory(requestsPerPeriod: 1, burstFactor: 1);
        var client = factory.CreateClient();
        var builder = new SignedRequestBuilder(
            RateLimitedApplicationFactory.ClientId,
            RateLimitedApplicationFactory.ClientSecret);

        // Consume the 1 available token
        await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // Act — 2nd request: bucket empty → 429
        var rejected = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // Assert — status
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);

        // Assert — Retry-After header present and value = 5
        // Period = 1 min = 60 s → Math.Max(1, (int)Math.Min(5, 60.0)) = 5
        Assert.True(rejected.Headers.Contains("Retry-After"),
            "Expected Retry-After header in 429 response");
        Assert.Equal(
            RateLimitedApplicationFactory.ExpectedRetryAfter,
            rejected.Headers.GetValues("Retry-After").First());

        // Assert — response body from OnRejectedAsync
        var body = await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(RateLimitedApplicationFactory.ExpectedRejectionBody, body);
    }

    // -----------------------------------------------------------------------
    // 4. Per-endpoint limits are independent across routes
    // -----------------------------------------------------------------------

    // The policy partitions by client + endpoint display name, so /api/rl/items
    // and /api/rl/users maintain INDEPENDENT token buckets.
    //
    // TokenLimit = 1 × 1 = 1 per endpoint bucket.
    //
    // Scenario:
    //   items#1 → endpoint-items (1→0)                → 200
    //   items#2 → endpoint-items (0) → rejects         → 429
    //   users#1 → endpoint-users (1→0) — fresh bucket  → 200
    [Fact]
    public async Task Given_EndpointLimitExhausted_When_RequestSentToDifferentEndpoint_Then_Returns200()
    {
        // Arrange — TokenLimit = 1 × 1 = 1 per endpoint
        using var factory = new RateLimitedApplicationFactory(requestsPerPeriod: 1, burstFactor: 1);
        var client = factory.CreateClient();
        var builder = new SignedRequestBuilder(
            RateLimitedApplicationFactory.ClientId,
            RateLimitedApplicationFactory.ClientSecret);

        // Act
        // 1st request to /api/rl/items — consumes the items endpoint token
        var itemsResponse1 = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // 2nd request to /api/rl/items — endpoint-items bucket empty → 429
        var itemsResponse2 = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // Request to /api/rl/users — independent endpoint bucket; still has 1 token → 200
        var usersResponse = await client.SendAsync(
            builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/users"),
            TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, itemsResponse1.StatusCode);               // token consumed
        Assert.Equal(HttpStatusCode.TooManyRequests, itemsResponse2.StatusCode);  // bucket empty
        Assert.Equal(HttpStatusCode.OK, usersResponse.StatusCode);                // independent bucket
    }

    // -----------------------------------------------------------------------
    // 5. Burst factor multiplies the available token supply
    // -----------------------------------------------------------------------

    // RPP=2, BF=2 → TokenLimit = 2 × 2 = 4.
    // Requests 1–4 succeed (all burst tokens consumed). Request 5 is rejected.
    //
    // This validates the formula: TokenLimit = RequestsPerPeriod × BurstFactor.
    [Fact]
    public async Task Given_BurstFactorConfigured_When_BurstRequestsSent_Then_ExactTokenLimitEnforced()
    {
        // Arrange — TokenLimit = 2 × 2 = 4
        using var factory = new RateLimitedApplicationFactory(requestsPerPeriod: 2, burstFactor: 2);
        var client = factory.CreateClient();
        var builder = new SignedRequestBuilder(
            RateLimitedApplicationFactory.ClientId,
            RateLimitedApplicationFactory.ClientSecret);

        // Act — send 5 requests; only the first 4 should succeed (4 burst tokens total)
        var responses = new HttpResponseMessage[5];
        for (var i = 0; i < 5; i++)
        {
            responses[i] = await client.SendAsync(
                builder.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
                TestContext.Current.CancellationToken);
        }

        // Assert — first 4 succeed (BurstFactor=2 doubles the token supply beyond RPP)
        Assert.Equal(HttpStatusCode.OK, responses[0].StatusCode);
        Assert.Equal(HttpStatusCode.OK, responses[1].StatusCode);
        Assert.Equal(HttpStatusCode.OK, responses[2].StatusCode);
        Assert.Equal(HttpStatusCode.OK, responses[3].StatusCode);
        // 5th request: all 4 burst tokens consumed → policy rejects
        Assert.Equal(HttpStatusCode.TooManyRequests, responses[4].StatusCode);
    }

    // -----------------------------------------------------------------------
    // 6. Per-client limits via IRequestLimitProvider
    // -----------------------------------------------------------------------

    // Two clients registered in IConfiguration with different RequestsPerPeriod.
    //   client-a: RPP=2 (in HmacRateLimits config) → TokenLimit = 2
    //   client-b: not in config → falls back to options default (RPP=100) → TokenLimit = 100
    //
    // Exhausting client-a's bucket does NOT affect client-b's independent bucket.
    [Fact]
    public async Task Given_PerClientLimitsConfigured_When_ClientALimitExhausted_Then_ClientBUnaffected()
    {
        // Arrange — shared options default RPP=100; client-a is overridden to RPP=2 via config
        const string clientAId     = "rl-per-client-a";
        const string clientASecret = "rl-per-client-a-secret";
        const string clientBId     = "rl-per-client-b";
        const string clientBSecret = "rl-per-client-b-secret";

        using var host = new HostBuilder()
            .ConfigureWebHost(builder =>
            {
                builder
                    .UseTestServer()
                    .UseContentRoot(AppContext.BaseDirectory)
                    .ConfigureAppConfiguration((_, config) =>
                        config.AddInMemoryCollection(new Dictionary<string, string?>
                        {
                            // HMAC secrets for both clients
                            [$"HmacSecrets:{clientAId}"] = clientASecret,
                            [$"HmacSecrets:{clientBId}"] = clientBSecret,
                            // Per-client rate limit: client-a capped at RPP=2, BF=1 → TokenLimit=2
                            [$"HmacRateLimits:{clientAId}:RequestsPerPeriod"] = "2",
                            [$"HmacRateLimits:{clientAId}:BurstFactor"]       = "1",
                            // client-b has no entry → uses options defaults (RPP=100)
                        }))
                    .ConfigureServices(services =>
                    {
                        services.AddAuthentication().AddHmacAuthentication();
                        // Generic overload registers RequestLimitProvider as IRequestLimitProvider.
                        // Options defaults (RPP=100, BF=1) are used for any client not in config.
                        services.AddHmacRateLimiter<RequestLimitProvider>(configure: opts =>
                        {
                            opts.RequestsPerPeriod = 100;
                            opts.BurstFactor = 1;
                        });
                        services.AddAuthorization();
                        services.AddRouting();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseRateLimiter();
                        app.UseAuthentication();
                        app.UseAuthorization();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/api/rl/items", () => Results.Ok())
                                .RequireAuthorization()
                                .RequireHmacRateLimiting();
                        });
                    });
            })
            .Build();

        host.Start();
        var httpClient = host.GetTestServer().CreateClient();

        var builderA = new SignedRequestBuilder(clientAId, clientASecret);
        var builderB = new SignedRequestBuilder(clientBId, clientBSecret);

        // Act — exhaust client-a's budget (RPP=2, BF=1 → TokenLimit=2)
        var aResp1 = await httpClient.SendAsync(
            builderA.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);
        var aResp2 = await httpClient.SendAsync(
            builderA.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);
        var aResp3 = await httpClient.SendAsync(
            builderA.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // client-b — not configured → uses default RPP=100; still has plenty of tokens
        var bResp1 = await httpClient.SendAsync(
            builderB.BuildSignedRequest(HttpMethod.Get, "/api/rl/items"),
            TestContext.Current.CancellationToken);

        // Assert — client-a exhausted at request 3
        Assert.Equal(HttpStatusCode.OK, aResp1.StatusCode);               // token 1
        Assert.Equal(HttpStatusCode.OK, aResp2.StatusCode);               // token 2
        Assert.Equal(HttpStatusCode.TooManyRequests, aResp3.StatusCode);  // bucket empty

        // Assert — client-b's independent bucket is unaffected by client-a's exhaustion
        Assert.Equal(HttpStatusCode.OK, bResp1.StatusCode);
    }
}
