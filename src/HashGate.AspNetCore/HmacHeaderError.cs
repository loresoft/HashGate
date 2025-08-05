namespace HashGate.AspNetCore;

/// <summary>
/// Represents possible errors encountered when parsing an HMAC authentication header.
/// </summary>
public enum HmacHeaderError
{
    /// <summary>
    /// No error occurred. The HMAC header was successfully parsed.
    /// </summary>
    None,

    /// <summary>
    /// The authorization header is missing or malformed.
    /// </summary>
    InvalidHeader,

    /// <summary>
    /// The authorization header does not start with the expected "HMAC" scheme when required.
    /// </summary>
    InvalidSchema,

    /// <summary>
    /// The authorization header format is invalid. Expected format: "HMAC Client={value}&amp;SignedHeaders={value}&amp;Signature={value}".
    /// This error occurs when not all three required components (Client, SignedHeaders, Signature) are present.
    /// </summary>
    InvalidHeaderFormat,

    /// <summary>
    /// The Client parameter is missing or empty in the authorization header.
    /// The Client parameter should contain the access key ID used to compute the signature.
    /// </summary>
    InvalidClients,

    /// <summary>
    /// The Signature parameter is missing or empty in the authorization header.
    /// The Signature parameter should contain the Base64-encoded HMAC-SHA256 hash.
    /// </summary>
    InvalidSignature,

    /// <summary>
    /// The SignedHeaders parameter is missing or empty in the authorization header.
    /// The SignedHeaders parameter should contain a semicolon-separated list of header names that were included in the signature calculation.
    /// </summary>
    InvalidSignedHeaders
}
