namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Represents possible errors encountered when parsing an HMAC header.
/// </summary>
public enum HmacHeaderError
{
    None,
    InvalidHeader,
    InvalidSchema,
    InvalidHeaderFormat,
    InvalidClients,
    InvalidSignature,
    InvalidSignedHeaders
}
