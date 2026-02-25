using Microsoft.AspNetCore.Http;

namespace HashGate.AspNetCore.RateLimiting;

/// <summary>
/// Configures default limits, replenishment period, and endpoint identification
/// for <see cref="RequestLimitExtensions.AddClientRateLimiter"/>.
/// </summary>
public sealed class RequestLimitOptions
{
    /// <summary>
    /// Gets or sets the configuration section name used for HMAC rate limit settings.
    /// </summary>
    public string SectionName { get; set; } = "HmacRateLimits";

    /// <summary>
    /// Fallback global limit used when a client has no registered snapshot.
    /// Defaults to 60 req/min with burst ×2.
    /// </summary>
    public RequestLimit DefaultGlobal { get; set; } = new(RequestsPerPeriod: 60, BurstFactor: 2);

    /// <summary>
    /// Fallback per-endpoint limit used when a client has no registered snapshot.
    /// Defaults to 20 req/min with burst ×2.
    /// </summary>
    public RequestLimit DefaultEndpoint { get; set; } = new(RequestsPerPeriod: 20, BurstFactor: 2);

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
