using Microsoft.AspNetCore.Authentication;


namespace HashGate.AspNetCore;

/// <summary>
/// Options for the HMAC authentication scheme.
/// </summary>
public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The default authentication scheme name.
    /// </summary>
    public const string DefaultScheme = "HMAC";

    /// <summary>
    /// The allowed time window (in minutes) for request timestamps to prevent replay attacks.
    /// Default is 5 minutes.
    /// </summary>
    public int ToleranceWindow { get; set; } = 5;

    /// <summary>
    /// The configuration section name where HMAC secrets are stored.
    /// Default is "HmacSecrets".
    /// </summary>
    public string SecretSectionName { get; set; } = "HmacSecrets";

    /// <summary>
    /// The service key used to resolve a custom <see cref="IHmacKeyProvider"/> from the dependency injection container.
    /// When set, the keyed service registered under this key is used instead of the default provider.
    /// </summary>
    public string? ProviderServiceKey { get; set; }
}

