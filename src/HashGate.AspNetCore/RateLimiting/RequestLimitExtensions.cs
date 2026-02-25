using System.Threading.RateLimiting;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.RateLimiting;

/// <summary>Extension methods for registering and applying HMAC client rate limiting.</summary>
public static class RequestLimitExtensions
{
    /// <summary>Base name of the global per-client rate limiting policy.</summary>
    public const string GlobalPolicy = "hmac-global";

    /// <summary>Base name of the per-endpoint per-client rate limiting policy.</summary>
    public const string EndpointPolicy = "hmac-endpoint";

    /// <summary>Returns the resolved global rate limiting policy name, lowercased.</summary>
    /// <param name="policyName">Optional suffix; pass the same value used in <see cref="AddClientRateLimiter"/>.</param>
    public static string GlobalPolicyName(string? policyName = null) =>
        (string.IsNullOrEmpty(policyName) ? GlobalPolicy : $"{GlobalPolicy}-{policyName}").ToLowerInvariant();

    /// <summary>Returns the resolved per-endpoint rate limiting policy name, lowercased.</summary>
    /// <param name="policyName">Optional suffix; pass the same value used in <see cref="AddClientRateLimiter"/>.</param>
    public static string EndpointPolicyName(string? policyName = null) =>
        (string.IsNullOrEmpty(policyName) ? EndpointPolicy : $"{EndpointPolicy}-{policyName}").ToLowerInvariant();

    /// <summary>
    /// Registers two token bucket rate limiting policies — one global per client and one per endpoint per client —
    /// keyed by the HMAC <c>Client</c> field (or remote IP for unauthenticated requests),
    /// using the built-in <see cref="RequestLimitProvider"/> backed by <see cref="Microsoft.Extensions.Configuration.IConfiguration"/>.
    /// </summary>
    /// <param name="services">The service collection to add the rate limiter to.</param>
    /// <param name="policyName">
    /// Optional suffix that scopes the policy names, enabling multiple independent limiters in one application.
    /// Must match the value passed to <see cref="RequireClientRateLimiting{TBuilder}"/>.
    /// </param>
    /// <param name="configure">Optional delegate to override <see cref="RequestLimitOptions"/> defaults.</param>
    /// <returns>The original <paramref name="services"/> for chaining.</returns>
    public static IServiceCollection AddClientRateLimiter(
        this IServiceCollection services,
        string? policyName = null,
        Action<RequestLimitOptions>? configure = null)
        => AddClientRateLimiter<RequestLimitProvider>(services, policyName, configure);

    /// <summary>
    /// Registers two token bucket rate limiting policies — one global per client and one per endpoint per client —
    /// keyed by the HMAC <c>Client</c> field (or remote IP for unauthenticated requests),
    /// using a custom <typeparamref name="TProvider"/> registered as a scoped <see cref="IRequestLimitProvider"/>.
    /// If <see cref="IRequestLimitProvider"/> is already registered, the existing registration is preserved.
    /// </summary>
    /// <typeparam name="TProvider">The custom <see cref="IRequestLimitProvider"/> implementation to register.</typeparam>
    /// <param name="services">The service collection to add the rate limiter to.</param>
    /// <param name="policyName">
    /// Optional suffix that scopes the policy names, enabling multiple independent limiters in one application.
    /// Must match the value passed to <see cref="RequireClientRateLimiting{TBuilder}"/>.
    /// </param>
    /// <param name="configure">Optional delegate to override <see cref="RequestLimitOptions"/> defaults.</param>
    /// <returns>The original <paramref name="services"/> for chaining.</returns>
    public static IServiceCollection AddClientRateLimiter<TProvider>(
        this IServiceCollection services,
        string? policyName = null,
        Action<RequestLimitOptions>? configure = null)
        where TProvider : class, IRequestLimitProvider
    {
        var globalPolicy = GlobalPolicyName(policyName);
        var endpointPolicy = EndpointPolicyName(policyName);

        services.AddOptions<RequestLimitOptions>();
        if (configure != null)
            services.Configure(configure);

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = OnRejectedAsync;

            options.AddPolicy(globalPolicy, GlobalPartition);
            options.AddPolicy(endpointPolicy, EndpointPartition);
        });

        services.TryAddScoped<IRequestLimitProvider, TProvider>();

        return services;
    }

    /// <summary>
    /// Applies both the global and per-endpoint HMAC client rate limiting policies to the endpoint.
    /// </summary>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <param name="policyName">
    /// Optional policy name suffix; must match the value passed to <see cref="AddClientRateLimiter"/>.
    /// </param>
    public static TBuilder RequireClientRateLimiting<TBuilder>(
        this TBuilder builder,
        string? policyName = null)
        where TBuilder : IEndpointConventionBuilder
    {
        var globalPolicy = GlobalPolicyName(policyName);
        var endpointPolicy = EndpointPolicyName(policyName);

        return builder
            .RequireRateLimiting(globalPolicy)
            .RequireRateLimiting(endpointPolicy);
    }


    private static async ValueTask OnRejectedAsync(OnRejectedContext context, CancellationToken token)
    {
        var httpContext = context.HttpContext;

        var requestOptions = httpContext.RequestServices.GetRequiredService<IOptions<RequestLimitOptions>>();

        // Suggest a short retry window rather than the full period; token buckets
        // replenish continuously, so tokens may be available well before the period ends.
        var retry = Math.Max(1, (int)Math.Min(5, requestOptions.Value.Period.TotalSeconds));
        httpContext.Response.Headers.RetryAfter = retry.ToString();

        await httpContext.Response.WriteAsync("Rate limit exceeded. Retry shortly.", token);
    }

    private static RateLimitPartition<string> GlobalPartition(HttpContext httpContext)
    {
        var requestOptions = httpContext.RequestServices.GetRequiredService<IOptions<RequestLimitOptions>>();
        var requestLimitProvider = httpContext.RequestServices.GetRequiredService<IRequestLimitProvider>();
        var authorizationHeader = httpContext.Request.Headers.Authorization.ToString();

        // Authenticated requests are bucketed by HMAC client id;
        // unauthenticated requests fall back to remote IP so they don't share one global bucket.
        var result = HmacHeaderParser.TryParse(authorizationHeader, true, out var hmacHeader);
        string client = result == HmacHeaderError.None
            ? hmacHeader.Client
            : httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        var limitSnapshot = requestLimitProvider.Get(client);
        var requestLimit = limitSnapshot?.Global ?? requestOptions.Value.DefaultGlobal;

        // Encoding the version in the key forces a new bucket whenever the client's limits change,
        // discarding any accumulated token debt from the old configuration.
        var version = limitSnapshot?.Version ?? 0;

        var partitionKey = $"client:{client}:v{version}";

        return RateLimitPartition.GetTokenBucketLimiter(
            partitionKey,
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = Math.Max(1, requestLimit.RequestsPerPeriod * requestLimit.BurstFactor),
                TokensPerPeriod = Math.Max(1, requestLimit.RequestsPerPeriod),
                ReplenishmentPeriod = requestOptions.Value.Period,
                AutoReplenishment = true,
                QueueLimit = 0      // fail fast; no queuing under burst
            });
    }

    private static RateLimitPartition<string> EndpointPartition(HttpContext httpContext)
    {
        var requestOptions = httpContext.RequestServices.GetRequiredService<IOptions<RequestLimitOptions>>();
        var requestLimitProvider = httpContext.RequestServices.GetRequiredService<IRequestLimitProvider>();
        var authorizationHeader = httpContext.Request.Headers.Authorization.ToString();

        // Authenticated requests are bucketed by HMAC client id;
        // unauthenticated requests fall back to remote IP so they don't share one global bucket.
        var result = HmacHeaderParser.TryParse(authorizationHeader, true, out var hmacHeader);
        var client = result == HmacHeaderError.None
            ? hmacHeader.Client
            : httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        var limitSnapshot = requestLimitProvider.Get(client);

        // Per-endpoint buckets are independent of the global bucket; a burst on one
        // endpoint cannot exhaust the allowance for other endpoints.
        var requestLimit = limitSnapshot?.Endpoint ?? requestOptions.Value.DefaultEndpoint;
        var version = limitSnapshot?.Version ?? 0;

        // EndpointSelector defaults to the endpoint display name, falling back to request path.
        var endpoint = requestOptions.Value.EndpointSelector(httpContext).ToLowerInvariant();

        var partitionKey = $"client:{client}:endpoint:{endpoint}:v{version}";

        return RateLimitPartition.GetTokenBucketLimiter(
            partitionKey,
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = Math.Max(1, requestLimit.RequestsPerPeriod * requestLimit.BurstFactor),
                TokensPerPeriod = Math.Max(1, requestLimit.RequestsPerPeriod),
                ReplenishmentPeriod = requestOptions.Value.Period,
                AutoReplenishment = true,
                QueueLimit = 0      // fail fast; no queuing under burst
            });
    }
}
