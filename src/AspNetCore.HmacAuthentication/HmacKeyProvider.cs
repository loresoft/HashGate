using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Provides an implementation of <see cref="IHmacKeyProvider"/> that retrieves HMAC secrets from application configuration.
/// </summary>
/// <remarks>
/// This provider looks up HMAC secrets from a configuration section, typically specified by <see cref="HmacAuthenticationSchemeOptions.SecretSectionName"/>.
/// If no section name is configured, "HmacSecrets" is used by default.
/// </remarks>
/// <example>
/// <para>
/// Example <c>appsettings.json</c> configuration for default section:
/// </para>
/// <code language="json">
/// {
///   "HmacSecrets": {
///     "client1": "supersecretkey1",
///     "client2": "supersecretkey2"
///   }
/// }
/// </code>
/// <para>
/// To use a custom section name, set <c>SecretSectionName</c> in your options and provide the secrets in that section:
/// </para>
/// <code language="json">
/// {
///   "MyCustomSecrets": {
///     "client1": "customsecret1"
///   }
/// }
/// </code>
/// <para>
/// Example usage in <c>Program.cs</c>:
/// </para>
/// <code language="csharp">
/// builder.Services
///     .AddAuthentication(options => options.DefaultScheme = HmacAuthenticationOptions.DefaultScheme)
///     .AddHmacAuthentication(options => options.SecretSectionName = "MyCustomSecrets);
/// </code>
/// </example>
public class HmacKeyProvider : IHmacKeyProvider
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<HmacKeyProvider> _logger;
    private readonly IOptionsMonitor<HmacAuthenticationSchemeOptions> _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacKeyProvider"/> class.
    /// </summary>
    /// <param name="configuration">The application configuration used to retrieve HMAC secrets.</param>
    /// <param name="logger">The logger instance for logging warnings or errors.</param>
    /// <param name="options">The options monitor for <see cref="HmacAuthenticationSchemeOptions"/>.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="configuration"/>, <paramref name="logger"/>, or <paramref name="options"/> is <c>null</c>.
    /// </exception>
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
    /// Asynchronously retrieves the HMAC secret for the specified client identifier from configuration.
    /// </summary>
    /// <param name="client">The client identifier whose HMAC secret is to be retrieved. Must not be <c>null</c> or whitespace.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> containing the HMAC secret as a string, or <c>null</c> if not found.
    /// </returns>
    /// <remarks>
    /// The secret is retrieved from the configuration section specified by <see cref="HmacAuthenticationSchemeOptions.SecretSectionName"/>.
    /// If the secret is not found, a warning is logged and <c>null</c> is returned.
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="client"/> is <c>null</c>, empty, or consists only of white-space characters.
    /// </exception>
    public ValueTask<string?> GetSecretAsync(string client)
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
