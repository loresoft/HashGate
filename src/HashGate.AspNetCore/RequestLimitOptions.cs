using Microsoft.AspNetCore.Http;

namespace HashGate.AspNetCore;

/// <summary>
/// Configures the token-bucket rate limit defaults, replenishment period, and endpoint
/// identification strategy used by <see cref="RequestLimitExtensions.AddHmacRateLimiter"/>.
/// </summary>
/// <remarks>
/// <see cref="RequestsPerPeriod"/> and <see cref="BurstFactor"/> serve as fallback limits for
/// any client not returned by <see cref="IRequestLimitProvider"/> (or when no provider is registered).
/// Per-client overrides are supplied by an <see cref="IRequestLimitProvider"/> registered via
/// <see cref="RequestLimitExtensions.AddHmacRateLimiter{TProvider}"/>.
/// </remarks>
public sealed class RequestLimitOptions
{
    /// <summary>
    /// Configuration section name used by <see cref="RequestLimitProvider"/> to locate
    /// per-client rate limit overrides.
    /// Defaults to <c>"HmacRateLimits"</c>.
    /// </summary>
    public string SectionName { get; set; } = "HmacRateLimits";

    /// <summary>
    /// Number of tokens replenished each <see cref="Period"/>.
    /// Determines both the steady-state request throughput and (with <see cref="BurstFactor"/>)
    /// the bucket ceiling: <c>TokenLimit = RequestsPerPeriod × BurstFactor</c>.
    /// Defaults to 20 requests per minute.
    /// </summary>
    public int RequestsPerPeriod { get; set; } = 20;

    /// <summary>
    /// Multiplier applied to <see cref="RequestsPerPeriod"/> to set the token-bucket ceiling,
    /// allowing short bursts above the steady-state rate.
    /// A value of 1 disables bursting (ceiling equals replenishment rate).
    /// Defaults to 2.
    /// </summary>
    public int BurstFactor { get; set; } = 2;

    /// <summary>
    /// Token replenishment period shared by all token buckets.
    /// Defaults to 1 minute.
    /// </summary>
    public TimeSpan Period { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Selects a stable string key that identifies the target endpoint for per-endpoint partitioning.
    /// Defaults to the endpoint display name, falling back to the request path.
    /// </summary>
    public Func<HttpContext, string> EndpointSelector { get; set; } = static ctx =>
        ctx.GetEndpoint()?.DisplayName ?? ctx.Request.Path.Value ?? "unknown";
}
