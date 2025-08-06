using System.Security.Claims;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore;

/// <summary>
/// Provides HMAC secret retrieval and claims generation using application configuration.
/// </summary>
/// <remarks>
/// Looks up HMAC secrets from a configuration section (default: "HmacSecrets"), configurable via <see cref="HmacAuthenticationSchemeOptions.SecretSectionName"/>.
/// Logs a warning and returns <c>null</c> if a secret is not found for a client.
/// </remarks>
/// <example>
/// Example <c>appsettings.json</c>:
/// <code language="json">
/// {
///   "HmacSecrets": {
///     "client1": "supersecretkey1"
///   }
/// }
/// </code>
/// Custom section:
/// <code language="json">
/// {
///   "MyCustomSecrets": {
///     "client1": "customsecret1"
///   }
/// }
/// </code>
/// Usage in <c>Program.cs</c>:
/// <code language="csharp">
/// builder.Services
///     .AddAuthentication(o => o.DefaultScheme = HmacAuthenticationOptions.DefaultScheme)
///     .AddHmacAuthentication(o => o.SecretSectionName = "MyCustomSecrets");
/// </code>
/// </example>
public class HmacKeyProvider : IHmacKeyProvider
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<HmacKeyProvider> _logger;
    private readonly IOptionsMonitor<HmacAuthenticationSchemeOptions> _options;

    /// <summary>
    /// Initializes a new <see cref="HmacKeyProvider"/>.
    /// </summary>
    /// <param name="configuration">Configuration for retrieving HMAC secrets.</param>
    /// <param name="logger">Logger for warnings or errors.</param>
    /// <param name="options">Options monitor for <see cref="HmacAuthenticationSchemeOptions"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown if any argument is <c>null</c>.</exception>
    public HmacKeyProvider(
        IConfiguration configuration,
        ILogger<HmacKeyProvider> logger,
        IOptionsMonitor<HmacAuthenticationSchemeOptions> options)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Generates a <see cref="ClaimsIdentity"/> for the specified client and authentication scheme.
    /// </summary>
    /// <param name="client">The client identifier. Must not be <c>null</c>, empty, or whitespace.</param>
    /// <param name="scheme">The authentication scheme. If <c>null</c>, the default scheme is used.</param>
    /// <param name="cancellationToken">Cancellation token (not used).</param>
    /// <returns>A <see cref="ClaimsIdentity"/> for the client.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="client"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="client"/> is empty or whitespace.</exception>
    public ValueTask<ClaimsIdentity> GenerateClaimsAsync(string client, string? scheme = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(client);

        scheme ??= HmacAuthenticationShared.DefaultSchemeName;

        Claim[] claims = [new Claim(ClaimTypes.Name, client)];
        var identity = new ClaimsIdentity(claims, scheme);

        return ValueTask.FromResult(identity);
    }

    /// <summary>
    /// Asynchronously retrieves the HMAC secret for the specified client from configuration.
    /// </summary>
    /// <param name="client">The client identifier. Must not be <c>null</c>, empty, or whitespace.</param>
    /// <param name="cancellationToken">Cancellation token (not used).</param>
    /// <returns>The HMAC secret as a <see cref="string"/>, or <c>null</c> if not found.</returns>
    /// <remarks>
    /// The secret is retrieved from the section specified by <see cref="HmacAuthenticationSchemeOptions.SecretSectionName"/>, or "HmacSecrets" if not set.
    /// </remarks>
    /// <exception cref="ArgumentException">Thrown if <paramref name="client"/> is <c>null</c>, empty, or whitespace.</exception>
    public ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(client);

        // Use the configured section name from options
        var sectionName = _options.CurrentValue.SecretSectionName ?? "HmacSecrets";
        var secret = _configuration[$"{sectionName}:{client}"];

        if (string.IsNullOrEmpty(secret))
        {
            _logger.LogWarning("No HMAC secret found for client '{Client}'.", client);
            return ValueTask.FromResult<string?>(null);
        }

        return ValueTask.FromResult<string?>(secret);
    }
}
