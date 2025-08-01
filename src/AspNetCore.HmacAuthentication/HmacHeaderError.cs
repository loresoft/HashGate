namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Represents possible errors encountered when parsing an HMAC header.
/// </summary>
public enum HmacHeaderError
{
    /// <summary>The header is too short to be valid.</summary>
    TooShort,
    /// <summary>
    /// The header does not start with the expected prefix.
    /// Header must start with <c>HMAC </c>.
    /// </summary>
    InvalidPrefix,
    /// <summary>
    /// One or more required delimiters are missing.
    /// Header format: <c>HMAC &lt;clientId&gt;:&lt;timestamp&gt;:&lt;signedHeaders&gt;:&lt;signature&gt;</c>
    /// </summary>
    MissingDelimiters,
    /// <summary>
    /// The client ID component is empty. Client ID is required.
    /// </summary>
    EmptyClientId,
    /// <summary>
    /// The timestamp component is empty. Timestamp is required.
    /// </summary>
    EmptyTimestamp,
    /// <summary>
    /// The timestamp component is not a valid number. Timestamp must be a valid Unix epoch value.
    /// </summary>
    InvalidTimestamp,
    /// <summary>
    /// The signature component is empty. Signature is required.
    /// </summary>
    EmptySignature
}
