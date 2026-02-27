using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore;

/// <summary>
/// Implements <see cref="IRequestLimitProvider"/> by reading per-client
/// <see cref="RequestLimit"/> values from <see cref="IConfiguration"/>.
/// </summary>
/// <remarks>
/// Expects configuration structured as:
/// <code>
/// "HmacRateLimits": {
///   "&lt;clientId&gt;": {
///     "RequestsPerPeriod": 60,
///     "BurstFactor": 2
///   }
/// }
/// </code>
/// Either property may be omitted; missing values fall back to the defaults on
/// <see cref="RequestLimitOptions"/> rather than being treated as zero.
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
    /// <param name="logger">Logger for warnings when a client section is absent.</param>
    /// <param name="configuration">Application configuration used to resolve client sections.</param>
    /// <param name="options">Rate limit options providing the section name and fallback limits.</param>
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
    /// Returns the <see cref="RequestLimit"/> for <paramref name="client"/> by reading
    /// <c><see cref="RequestLimitOptions.SectionName"/>:&lt;client&gt;</c> from configuration,
    /// or <see langword="null"/> if the section is absent (triggering fallback to option defaults).
    /// Individual missing properties fall back to the corresponding default on
    /// <see cref="RequestLimitOptions"/> rather than being treated as zero.
    /// </summary>
    /// <param name="client">The client identifier extracted from the HMAC Authorization header.</param>
    /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
    public Task<RequestLimit?> GetAsync(string client, CancellationToken cancellationToken = default)
    {
        var opts = _options.CurrentValue;

        var clientSection = _configuration
            .GetSection(opts.SectionName)
            .GetSection(client);

        if (!clientSection.Exists())
        {
            _logger.LogWarning(
                "Client '{Client}' not found in rate limit configuration section '{SectionName}'.",
                client, opts.SectionName);

            return Task.FromResult<RequestLimit?>(null);
        }

        // Read each field independently so partial configuration is valid.
        // A missing field (null) falls back to the option default rather than 0.
        var rpp = clientSection.GetValue<int?>("RequestsPerPeriod") ?? opts.RequestsPerPeriod;
        var bf = clientSection.GetValue<int?>("BurstFactor") ?? opts.BurstFactor;

        return Task.FromResult<RequestLimit?>(new RequestLimit(RequestsPerPeriod: rpp, BurstFactor: bf));
    }
}
