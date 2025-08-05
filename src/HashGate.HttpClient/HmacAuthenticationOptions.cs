using System.ComponentModel.DataAnnotations;

namespace HashGate.HttpClient;

/// <summary>
/// Configuration options for HMAC authentication on the client side.
/// Contains the client credentials and signing configuration required for HTTP request authentication.
/// </summary>
/// <remarks>
/// <para>
/// This class is used to configure HMAC authentication for HTTP clients. The options can be configured
/// through dependency injection, configuration binding, or programmatically. The configuration section
/// name is defined by <see cref="ConfigurationName"/>.
/// </para>
/// <para>
/// All requests made by HTTP clients configured with these options will be automatically signed using
/// HMAC-SHA256 with the provided client credentials and signed headers.
/// </para>
/// </remarks>
/// <example>
/// <para>Configuration through appsettings.json:</para>
/// <code>
/// {
///   "HmacAuthentication": {
///     "Client": "my-client-id",
///     "Secret": "my-secret-key",
///     "SignedHeaders": ["host", "x-timestamp", "x-content-sha256", "content-type"]
///   }
/// }
/// </code>
/// <para>Programmatic configuration:</para>
/// <code>
/// services.AddHmacAuthentication(options =>
/// {
///     options.Client = "my-client-id";
///     options.Secret = "my-secret-key";
///     options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256"];
/// });
/// </code>
/// </example>
public class HmacAuthenticationOptions
{
    /// <summary>
    /// The configuration section name used for binding HMAC authentication options from configuration.
    /// </summary>
    /// <value>
    /// The string "HmacAuthentication" which corresponds to the configuration section name.
    /// </value>
    public const string ConfigurationName = "HmacAuthentication";

    /// <summary>
    /// Gets or sets the client identifier (access key ID) used for HMAC authentication.
    /// This value is included in the Authorization header and used by the server to identify the client.
    /// </summary>
    /// <value>
    /// A string representing the unique client identifier. This value is required and cannot be null or empty.
    /// </value>
    /// <remarks>
    /// The client identifier is used by the server to:
    /// <list type="bullet">
    /// <item><description>Identify which client is making the request</description></item>
    /// <item><description>Look up the corresponding secret key for signature validation</description></item>
    /// <item><description>Apply client-specific authorization policies</description></item>
    /// </list>
    /// </remarks>
    [Required]
    public required string Client { get; set; }

    /// <summary>
    /// Gets or sets the secret key used for HMAC-SHA256 signature generation.
    /// This value must be kept secure and should match the secret stored on the server for the corresponding client.
    /// </summary>
    /// <value>
    /// A string representing the secret key used for HMAC computation. This value is required and cannot be null or empty.
    /// </value>
    /// <remarks>
    /// <para>
    /// The secret key is used to generate HMAC-SHA256 signatures for request authentication.
    /// It should be:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Sufficiently long and random to ensure security</description></item>
    /// <item><description>Stored securely (e.g., in Azure Key Vault, environment variables, or secure configuration)</description></item>
    /// <item><description>Synchronized between client and server</description></item>
    /// <item><description>Rotated periodically for enhanced security</description></item>
    /// </list>
    /// <para>
    /// Never expose this value in logs, source code, or client-side applications.
    /// </para>
    /// </remarks>
    [Required]
    public required string Secret { get; set; }

    /// <summary>
    /// Gets or sets the list of HTTP header names that should be included in the HMAC signature calculation.
    /// If not specified, the default signed headers will be used.
    /// </summary>
    /// <value>
    /// A read-only list of header names to include in the signature, or <c>null</c> to use the default headers.
    /// When <c>null</c>, defaults to <see cref="HmacAuthenticationShared.DefaultSignedHeaders"/>.
    /// </value>
    /// <remarks>
    /// <para>
    /// The signed headers determine which HTTP headers are included when calculating the HMAC signature.
    /// The default signed headers are: host, x-timestamp, and x-content-sha256.
    /// </para>
    /// <para>
    /// Additional headers can be included to provide more security by signing headers like:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>content-type</c> - Ensures the content type cannot be modified</description></item>
    /// <item><description><c>user-agent</c> - Validates the client application</description></item>
    /// <item><description>Custom headers specific to your application</description></item>
    /// </list>
    /// <para>
    /// Header names should be in lowercase and must match exactly between client and server.
    /// The order of headers in this list determines the order they appear in the signed string.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Use default signed headers (host, x-timestamp, x-content-sha256)
    /// options.SignedHeaders = null;
    ///
    /// // Include additional headers in the signature
    /// options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256", "content-type", "user-agent"];
    /// </code>
    /// </example>
    public IReadOnlyList<string>? SignedHeaders { get; set; } = HmacAuthenticationShared.DefaultSignedHeaders;
}
