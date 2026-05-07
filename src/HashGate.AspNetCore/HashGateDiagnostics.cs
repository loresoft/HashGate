// Ignore Spelling: Hmac

using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace HashGate.AspNetCore;

/// <summary>
/// Provides diagnostic source, meter, metric, and tag names used by HashGate ASP.NET Core instrumentation.
/// </summary>
public static class HashGateDiagnostics
{
    /// <summary>
    /// The name of the activity source used for HashGate ASP.NET Core tracing.
    /// </summary>
    public const string SourceName = "HashGate.AspNetCore";

    /// <summary>
    /// The name of the meter used for HashGate ASP.NET Core metrics.
    /// </summary>
    public const string MeterName = "HashGate.AspNetCore";

    /// <summary>
    /// The metric name for HMAC authentication request attempts.
    /// </summary>
    public const string AuthenticationRequestsName = "hashgate.auth.requests";

    /// <summary>
    /// The metric name for failed HMAC authentication attempts.
    /// </summary>
    public const string AuthenticationFailuresName = "hashgate.auth.failures";

    /// <summary>
    /// The metric name for HMAC authentication duration.
    /// </summary>
    public const string AuthenticationDurationName = "hashgate.auth.duration";

    /// <summary>
    /// The metric name for HMAC replay protection checks.
    /// </summary>
    public const string ReplayProtectionChecksName = "hashgate.replay_protection.checks";

    /// <summary>
    /// The metric name for rejected replayed HMAC signatures.
    /// </summary>
    public const string ReplayProtectionReplaysName = "hashgate.replay_protection.replays";

    /// <summary>
    /// The metric name for requests rejected by HashGate rate limiting.
    /// </summary>
    public const string RateLimitRejectionsName = "hashgate.rate_limit.rejections";

    /// <summary>
    /// The metric name for per-client rate limit provider lookups.
    /// </summary>
    public const string RateLimitProviderLookupsName = "hashgate.rate_limit.provider.lookup";

    /// <summary>
    /// The metric name for per-client rate limit provider lookups that used default limits.
    /// </summary>
    public const string RateLimitProviderMissesName = "hashgate.rate_limit.provider.miss";


    /// <summary>
    /// The tag name for the authentication scheme used by a request.
    /// </summary>
    public const string AuthenticationSchemeTagName = "hashgate.auth.scheme";

    /// <summary>
    /// The tag name for the authentication result.
    /// </summary>
    public const string AuthenticationResultTagName = "hashgate.auth.result";

    /// <summary>
    /// The tag name for the authentication failure reason.
    /// </summary>
    public const string AuthenticationFailureReasonTagName = "hashgate.auth.failure_reason";

    /// <summary>
    /// The tag name that indicates whether replay protection is enabled.
    /// </summary>
    public const string ReplayProtectionEnabledTagName = "hashgate.replay_protection.enabled";

    /// <summary>
    /// The tag name for the replay protection result.
    /// </summary>
    public const string ReplayProtectionResultTagName = "hashgate.replay_protection.result";

    /// <summary>
    /// The tag name for the count of signed HMAC headers.
    /// </summary>
    public const string HmacSignedHeadersCountTagName = "hashgate.hmac.signed_headers.count";

    /// <summary>
    /// The tag name that indicates whether a request was rejected by rate limiting.
    /// </summary>
    public const string RateLimitRejectedTagName = "hashgate.rate_limit.rejected";

    /// <summary>
    /// The tag name for the rate limit policy.
    /// </summary>
    public const string RateLimitPolicyTagName = "hashgate.rate_limit.policy";

    /// <summary>
    /// The tag name for the retry-after duration in milliseconds.
    /// </summary>
    public const string RateLimitRetryAfterMillisecondsTagName = "hashgate.rate_limit.retry_after_ms";

    /// <summary>
    /// The tag name for the rate limit client identifier.
    /// </summary>
    public const string RateLimitClientTagName = "hashgate.rate_limit.client";

    /// <summary>
    /// The tag name for the rate-limited endpoint.
    /// </summary>
    public const string RateLimitEndpointTagName = "hashgate.rate_limit.endpoint";

    /// <summary>
    /// The tag name for the configured requests per rate limit period.
    /// </summary>
    public const string RateLimitRequestsPerPeriodTagName = "hashgate.rate_limit.requests_per_period";

    /// <summary>
    /// The tag name for the configured rate limit burst factor.
    /// </summary>
    public const string RateLimitBurstFactorTagName = "hashgate.rate_limit.burst_factor";

    /// <summary>
    /// The tag name for the rate limit partition source.
    /// </summary>
    public const string RateLimitPartitionSourceTagName = "hashgate.rate_limit.partition_source";

    /// <summary>
    /// The tag name that indicates whether a rate limit provider lookup found client-specific limits.
    /// </summary>
    public const string RateLimitProviderFoundTagName = "hashgate.rate_limit.provider_found";

    /// <summary>
    /// The tag name for the resolved endpoint.
    /// </summary>
    public const string EndpointTagName = "hashgate.endpoint";

    /// <summary>
    /// The tag name for the resolved client.
    /// </summary>
    public const string ClientTagName = "hashgate.client";


    internal static readonly ActivitySource ActivitySource = new(SourceName, ThisAssembly.FileVersion);
    internal static readonly Meter Meter = new(MeterName, ThisAssembly.FileVersion);

    internal static readonly Counter<long> AuthenticationRequests = Meter.CreateCounter<long>(
        name: AuthenticationRequestsName,
        unit: "{request}",
        description: "Number of HMAC authentication attempts.");

    internal static readonly Counter<long> AuthenticationFailures = Meter.CreateCounter<long>(
        name: AuthenticationFailuresName,
        unit: "{failure}",
        description: "Number of failed HMAC authentication attempts.");

    internal static readonly Histogram<double> AuthenticationDuration = Meter.CreateHistogram<double>(
        name: AuthenticationDurationName,
        unit: "ms",
        description: "Duration of HMAC authentication attempts.");


    internal static readonly Counter<long> ReplayProtectionChecks = Meter.CreateCounter<long>(
        name: ReplayProtectionChecksName,
        unit: "{check}",
        description: "Number of HMAC replay protection checks.");

    internal static readonly Counter<long> ReplayProtectionReplays = Meter.CreateCounter<long>(
        name: ReplayProtectionReplaysName,
        unit: "{replay}",
        description: "Number of rejected replayed HMAC signatures.");

    internal static readonly Counter<long> RateLimitRejections = Meter.CreateCounter<long>(
        name: RateLimitRejectionsName,
        unit: "{rejection}",
        description: "Number of requests rejected by HashGate rate limiting.");

    internal static readonly Counter<long> RateLimitProviderLookups = Meter.CreateCounter<long>(
        name: RateLimitProviderLookupsName,
        unit: "{lookup}",
        description: "Number of per-client rate limit provider lookups.");

    internal static readonly Counter<long> RateLimitProviderMisses = Meter.CreateCounter<long>(
        name: RateLimitProviderMissesName,
        unit: "{miss}",
        description: "Number of per-client rate limit provider lookups that fell back to default limits.");


    internal static void RecordAuthentication(
        string scheme,
        string result,
        string? failureReason,
        long elapsedTicks,
        string? endpoint,
        string? client)
    {
        if (!AuthenticationRequests.Enabled &&
            !AuthenticationFailures.Enabled &&
            !AuthenticationDuration.Enabled)
        {
            return;
        }

        TagList tags =
        [
            new(AuthenticationSchemeTagName, scheme),
            new(AuthenticationResultTagName, result)
        ];

        if (failureReason is not null)
            tags.Add(new(AuthenticationFailureReasonTagName, failureReason));

        if (!string.IsNullOrWhiteSpace(endpoint))
            tags.Add(new(EndpointTagName, endpoint));

        if (!string.IsNullOrWhiteSpace(client))
            tags.Add(new(ClientTagName, client));

        AuthenticationRequests.Add(1, in tags);

        if (failureReason is not null)
            AuthenticationFailures.Add(1, in tags);

        var elapsed = GetElapsedMilliseconds(elapsedTicks);
        AuthenticationDuration.Record(elapsed, in tags);
    }

    internal static void RecordReplayProtectionCheck(string result, double ttlMilliseconds)
    {
        if (!ReplayProtectionChecks.Enabled
            && (result != "replay" || !ReplayProtectionReplays.Enabled))
        {
            return;
        }

        TagList tags =
        [
            new(ReplayProtectionResultTagName, result)
        ];

        ReplayProtectionChecks.Add(1, in tags);

        if (result == "replay")
            ReplayProtectionReplays.Add(1, in tags);
    }

    internal static void RecordRateLimitRejection(string policy, double retryAfterMilliseconds)
    {
        if (!RateLimitRejections.Enabled)
            return;

        TagList tags =
        [
            new(RateLimitPolicyTagName, policy)
        ];

        RateLimitRejections.Add(1, in tags);
    }

    internal static void RecordRateLimitProviderLookup(string policy, bool found)
    {
        if (!RateLimitProviderLookups.Enabled
            && (found || !RateLimitProviderMisses.Enabled))
        {
            return;
        }

        TagList tags =
        [
            new(RateLimitPolicyTagName, policy),
            new(RateLimitProviderFoundTagName, found)
        ];

        RateLimitProviderLookups.Add(1, in tags);

        if (!found)
            RateLimitProviderMisses.Add(1, in tags);
    }

    private static double GetElapsedMilliseconds(long startTimestamp)
        => Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds;
}
