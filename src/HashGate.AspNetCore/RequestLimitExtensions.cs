using System.Threading.RateLimiting;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore;

/// <summary>
/// Extension methods for registering and applying HMAC client rate limiting.
/// </summary>
public static class RequestLimitExtensions
{
    /// <summary>
    /// Base name of the per-endpoint per-client rate limiting policy.
    /// </summary>
    public const string Policy = "hmac-client";

    // Key used to stash the resolved policy name in HttpContext.Items so OnRejectedAsync
    // can look up the correct named RequestLimitOptions without knowing the policy name.
    private static readonly object _policyItemKey = new();

    /// <summary>Returns the resolved rate limiting policy name, lowercased.</summary>
    /// <param name="policyName">
    /// Optional suffix that scopes the policy name, enabling multiple independent limiters in
    /// one application. Pass the same value used in <see cref="AddHmacRateLimiter"/> and
    /// <see cref="RequireHmacRateLimiting{TBuilder}"/>.
    /// </param>
    public static string PolicyName(string? policyName = null) =>
        (string.IsNullOrEmpty(policyName) ? Policy : $"{Policy}-{policyName}").ToLowerInvariant();

    /// <summary>
    /// Registers a token-bucket rate limiting policy partitioned by HMAC client ID and endpoint,
    /// using uniform limits from <see cref="RequestLimitOptions"/> for every client.
    /// </summary>
    /// <remarks>
    /// All authenticated clients share the same <see cref="RequestLimitOptions.RequestsPerPeriod"/>
    /// and <see cref="RequestLimitOptions.BurstFactor"/>; each client-endpoint pair maintains an
    /// independent token bucket. To apply different limits per client, use the generic overload
    /// <see cref="AddHmacRateLimiter{TProvider}"/> and supply an
    /// <see cref="IRequestLimitProvider"/> implementation.
    /// </remarks>
    /// <param name="services">The service collection to add the rate limiter to.</param>
    /// <param name="policyName">
    /// Optional suffix that scopes the policy name, enabling multiple independent limiters in one
    /// application. Must match the value passed to <see cref="RequireHmacRateLimiting{TBuilder}"/>.
    /// </param>
    /// <param name="configure">Optional delegate to override <see cref="RequestLimitOptions"/> defaults.</param>
    /// <returns>The original <paramref name="services"/> for chaining.</returns>
    public static IServiceCollection AddHmacRateLimiter(
        this IServiceCollection services,
        string? policyName = null,
        Action<RequestLimitOptions>? configure = null)
    {
        return AddHmacRateLimiterCore(services, policyName, configure);
    }

    /// <summary>
    /// Registers a token-bucket rate limiting policy partitioned by HMAC client ID and endpoint,
    /// with per-client limit overrides supplied by <typeparamref name="TProvider"/>.
    /// </summary>
    /// <remarks>
    /// <typeparamref name="TProvider"/> is registered as a <see cref="IRequestLimitProvider"/> service.
    /// On each request the provider's <see cref="IRequestLimitProvider.GetAsync"/> is called; returning
    /// <see langword="null"/> falls back to <see cref="RequestLimitOptions.RequestsPerPeriod"/> and
    /// <see cref="RequestLimitOptions.BurstFactor"/>. Use <see cref="RequestLimitProvider"/> for
    /// configuration-backed per-client limits.
    /// </remarks>
    /// <typeparam name="TProvider">The <see cref="IRequestLimitProvider"/> implementation to register.</typeparam>
    /// <param name="services">The service collection to add the rate limiter to.</param>
    /// <param name="policyName">
    /// Optional suffix that scopes the policy name. Must match the value passed to
    /// <see cref="RequireHmacRateLimiting{TBuilder}"/>.
    /// </param>
    /// <param name="lifetime">The service lifetime for <typeparamref name="TProvider"/>. Defaults to <see cref="ServiceLifetime.Scoped"/>.</param>
    /// <param name="configure">Optional delegate to override <see cref="RequestLimitOptions"/> defaults.</param>
    /// <returns>The original <paramref name="services"/> for chaining.</returns>
    public static IServiceCollection AddHmacRateLimiter<TProvider>(
        this IServiceCollection services,
        string? policyName = null,
        ServiceLifetime lifetime = ServiceLifetime.Scoped,
        Action<RequestLimitOptions>? configure = null)
        where TProvider : class, IRequestLimitProvider
    {
        var policy = PolicyName(policyName);
        services.TryAdd(new ServiceDescriptor(typeof(IRequestLimitProvider), policy, typeof(TProvider), lifetime));

        return AddHmacRateLimiterCore(services, policyName, configure);
    }

    /// <summary>
    /// Applies the per-endpoint HMAC client rate limiting policy to the endpoint.
    /// Call <see cref="AddHmacRateLimiter"/> (or the generic overload) first to register the policy.
    /// </summary>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <param name="policyName">
    /// Optional policy name suffix; must match the value passed to <see cref="AddHmacRateLimiter"/>.
    /// </param>
    public static TBuilder RequireHmacRateLimiting<TBuilder>(
        this TBuilder builder,
        string? policyName = null)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.RequireRateLimiting(PolicyName(policyName));
    }

    private static IServiceCollection AddHmacRateLimiterCore(
        IServiceCollection services,
        string? policyName,
        Action<RequestLimitOptions>? configure)
    {
        var policy = PolicyName(policyName);

        services.AddOptions<RequestLimitOptions>(policy);
        if (configure != null)
            services.Configure(policy, configure);

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = OnRejectedAsync;

            options.AddPolicy(policy, httpContext => Partition(httpContext, policy));
        });

        return services;
    }

    private static async ValueTask OnRejectedAsync(OnRejectedContext context, CancellationToken token)
    {
        var httpContext = context.HttpContext;

        // Look up the policy name and options to determine the appropriate Retry-After value for this request.
        var policyName = httpContext.Items[_policyItemKey] as string ?? Options.DefaultName;
        var opts = httpContext.RequestServices.GetRequiredService<IOptionsMonitor<RequestLimitOptions>>().Get(policyName);

        // Prefer the lease's own retry hint; token buckets replenish continuously so the lease
        // knows exactly when tokens will be available. Fall back to a short window within the period.
        if (!context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            retryAfter = TimeSpan.FromSeconds(Math.Max(1, Math.Min(5, opts.Period.TotalSeconds)));

        var retrySeconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));

        httpContext.Response.Headers.RetryAfter = retrySeconds.ToString();
        httpContext.Response.Headers["X-RateLimit-Reset"] = DateTimeOffset.UtcNow.AddSeconds(retrySeconds).ToUnixTimeSeconds().ToString();

        await httpContext.Response.WriteAsync($"Rate limit exceeded. Retry after {retrySeconds}s.", token);
    }

    private static RateLimitPartition<string> Partition(HttpContext httpContext, string policy)
    {
        var opts = httpContext.RequestServices
            .GetRequiredService<IOptionsMonitor<RequestLimitOptions>>()
            .Get(policy);

        // Stash the policy name so OnRejectedAsync can look up the same named options.
        httpContext.Items[_policyItemKey] = policy;

        var authorizationHeader = httpContext.Request.Headers.Authorization.ToString();

        // Authenticated requests are bucketed by HMAC client ID + endpoint;
        // unauthenticated requests fall back to remote IP so they don't share a client's quota.
        var parseResult = HmacHeaderParser.TryParse(authorizationHeader, true, out var hmacHeader);
        var client = parseResult == HmacHeaderError.None
            ? hmacHeader.Client
            : httpContext.Connection.RemoteIpAddress?.ToString()
            ?? "unknown";

        // EndpointSelector defaults to the endpoint display name, falling back to request path.
        var endpoint = opts.EndpointSelector(httpContext).ToLowerInvariant();

        // Per-client override: provider returns null → use options defaults.
        // Keyed lookup targets the provider registered for this specific policy;
        // non-keyed fallback preserves backward compat if no keyed registration exists.
        var provider = httpContext.RequestServices.GetKeyedService<IRequestLimitProvider>(policy)
            ?? httpContext.RequestServices.GetService<IRequestLimitProvider>();

        // default to options if provider doesn't exist
        // ASP.NET Core's partition callback is synchronous; GetAwaiter().GetResult() is safe here
        // because ASP.NET Core has no SynchronizationContext.
        var limit = provider?.GetAsync(client, httpContext.RequestAborted).GetAwaiter().GetResult()
            ?? new RequestLimit(opts.RequestsPerPeriod, opts.BurstFactor);

        // Include a content-derived version so that limit changes in configuration
        // cause new partition keys — and thus fresh token buckets — rather than
        // continuing to use stale limiters from the old configuration.
        var version = HashCode.Combine(limit.RequestsPerPeriod, limit.BurstFactor);
        var partitionKey = $"client:{client}:endpoint:{endpoint}:v{version}";

        return RateLimitPartition.GetTokenBucketLimiter(
            partitionKey,
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = Math.Max(1, limit.RequestsPerPeriod * limit.BurstFactor),
                TokensPerPeriod = Math.Max(1, limit.RequestsPerPeriod),
                ReplenishmentPeriod = opts.Period,
                AutoReplenishment = true,
                QueueLimit = 0 // fail-fast; no queuing under burst
            });
    }
}
