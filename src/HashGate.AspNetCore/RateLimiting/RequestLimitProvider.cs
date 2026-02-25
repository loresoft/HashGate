using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.RateLimiting;

/// <summary>
/// Implements <see cref="IRequestLimitProvider"/> by reading per-client
/// <see cref="RequestLimitSnapshot"/> values from <see cref="IConfiguration"/>.
/// </summary>
/// <remarks>
/// Expects configuration structured as:
/// <code>
/// "HmacRateLimits": {
///   "&lt;clientId&gt;": {
///     "Global":   { "RequestsPerPeriod": 60, "BurstFactor": 2 },
///     "Endpoint": { "RequestsPerPeriod": 20, "BurstFactor": 2 }
///   }
/// }
/// </code>
/// The root section name is controlled by <see cref="RequestLimitOptions.SectionName"/>.
/// </remarks>
public class RequestLimitProvider : IRequestLimitProvider
{
    private readonly ILogger<RequestLimitProvider> _logger;
    private readonly IConfiguration _configuration;
    private readonly IOptionsMonitor<RequestLimitOptions> _options;

    /// <summary>
    /// Initializes a new instance of <see cref="RequestLimitProvider"/>.
    /// </summary>
    /// <param name="logger">Logger for warnings when a client is missing or misconfigured.</param>
    /// <param name="configuration">The application configuration used to resolve client sections.</param>
    /// <param name="options">Rate limit options providing the configuration section name and fallback limits.</param>
    public RequestLimitProvider(
        ILogger<RequestLimitProvider> logger,
        IConfiguration configuration,
        IOptionsMonitor<RequestLimitOptions> options)
    {
        _logger = logger;
        _configuration = configuration;
        _options = options;
    }

    /// <summary>
    /// Returns the <see cref="RequestLimitSnapshot"/> for <paramref name="client"/> by reading
    /// <c><see cref="RequestLimitOptions.SectionName"/>:&lt;client&gt;</c> from configuration,
    /// or <see langword="null"/> if the section is absent or cannot be bound.
    /// <see cref="RequestLimitSnapshot.Global"/> and <see cref="RequestLimitSnapshot.Endpoint"/>
    /// fall back to <see cref="RequestLimitOptions.DefaultGlobal"/> and <see cref="RequestLimitOptions.DefaultEndpoint"/>
    /// when not present in configuration.
    /// </summary>
    /// <param name="client">The client identifier extracted from the HMAC Authorization header.</param>
    public RequestLimitSnapshot? Get(string client)
    {
        var options = _options.CurrentValue;

        var clientSection = _configuration
            .GetSection(options.SectionName)
            .GetSection(client);

        if (!clientSection.Exists())
        {
            _logger.LogWarning("Client '{Client}' not found in configuration section '{SectionName}'.", client, options.SectionName);
            return null;
        }

        var snapshot = clientSection.Get<RequestLimitSnapshot>();
        if (snapshot == null)
        {
            _logger.LogWarning("Client '{Client}' has no valid rate limit snapshot in configuration section '{SectionName}'.", client, options.SectionName);
            return null;
        }

        // Fall back to configured defaults for any limit not present in the section.
        return snapshot with
        {
            Global = snapshot.Global == default ? options.DefaultGlobal : snapshot.Global,
            Endpoint = snapshot.Endpoint == default ? options.DefaultEndpoint : snapshot.Endpoint,
        };
    }
}
