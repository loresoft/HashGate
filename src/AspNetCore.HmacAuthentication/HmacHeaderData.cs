namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Represents the parsed data from an HMAC authentication header.
/// </summary>
/// <remarks>
/// <para>
/// <b>Header format:</b><br/>
/// <c>HMAC &lt;clientId&gt;:&lt;timestamp&gt;:&lt;signedHeaders&gt;:&lt;signature&gt;</c>
/// </para>
/// <para>
/// <b>Components:</b>
/// <list type="bullet">
///   <item><description><c>&lt;clientId&gt;</c>: The client identifier (required, non-empty).</description></item>
///   <item><description><c>&lt;timestamp&gt;</c>: The Unix timestamp (in seconds) when the request was signed (required, non-empty, must be a valid integer).</description></item>
///   <item><description><c>&lt;signedHeaders&gt;</c>: Semicolon-separated list of HTTP headers included in the signature (may be empty).</description></item>
///   <item><description><c>&lt;signature&gt;</c>: The Base64-encoded HMAC SHA256 signature (required, non-empty).</description></item>
/// </list>
/// </para>
/// <para>
/// <b>Example header:</b><br/>
/// <c>HMAC myClient:1722450000:host;date;content-type:Q2hhbmdlVGhpcyBUb1lvdXJTZWN1cmVTZWNyZXQ=</c>
/// </para>
/// <para>
/// If parsing fails, the <see cref="Error"/> property will indicate the reason, and all other properties will be set to their default values.
/// </para>
/// </remarks>
/// <param name="ClientId">
/// The client identifier parsed from the header. This value is used to look up the shared HMAC secret. If parsing fails, this will be an empty string.
/// </param>
/// <param name="Timestamp">
/// The timestamp as a Unix epoch value parsed from the header. Used to prevent replay attacks with a configurable window. If parsing fails, this will be 0.
/// </param>
/// <param name="SignedHeaders">
/// The list of signed header names parsed from the header (semicolon-separated in the header; may be empty). If parsing fails, this will be an empty list.
/// </param>
/// <param name="Signature">
/// The HMAC signature parsed from the header, computed over the HTTP method, path, query string, timestamp, signed headers, and body. If parsing fails, this will be an empty string.
/// </param>
/// <param name="Error">
/// The error encountered during parsing, if any. <c>null</c> if parsing was successful; otherwise, a value from <see cref="HmacHeaderError"/>.
/// </param>
public readonly record struct HmacHeaderData(
    string ClientId,
    long Timestamp,
    IReadOnlyList<string> SignedHeaders,
    string Signature,
    HmacHeaderError? Error = null)
{
    /// <summary>
    /// Gets a value indicating whether the header was parsed successfully.
    /// Returns <c>true</c> if <see cref="Error"/> is <c>null</c>; otherwise, <c>false</c>.
    /// </summary>
    public bool IsSuccess => Error == null;

    /// <summary>
    /// Creates an <see cref="HmacHeaderData"/> instance representing a parsing error.
    /// All properties except <paramref name="error"/> are set to their default values.
    /// </summary>
    /// <param name="error">The error encountered during parsing.</param>
    /// <returns>
    /// An <see cref="HmacHeaderData"/> with the specified <paramref name="error"/> and default values for all other properties.
    /// </returns>
    public static HmacHeaderData Failed(HmacHeaderError error)
        => new(string.Empty, 0, [], string.Empty, error);
}
