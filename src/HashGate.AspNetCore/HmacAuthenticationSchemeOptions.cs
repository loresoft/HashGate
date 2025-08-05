using Microsoft.AspNetCore.Authentication;


namespace AspNetCore.HmacAuthentication;

public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
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
}

