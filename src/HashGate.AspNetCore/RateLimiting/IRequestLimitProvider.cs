using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.RateLimiting;

/// <summary>Provides per-client rate limit snapshots to the rate limiting middleware.</summary>
public interface IRequestLimitProvider
{
    /// <summary>
    /// Returns the current rate limit snapshot for <paramref name="client"/>,
    /// or <see langword="null"/> if the client is unknown.
    /// </summary>
    /// <param name="client">The client identifier extracted from the HMAC Authorization header.</param>
    RequestLimitSnapshot? Get(string client);
}
