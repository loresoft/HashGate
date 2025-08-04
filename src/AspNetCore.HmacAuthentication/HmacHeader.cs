namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Represents the HMAC authentication header.
/// </summary>
public readonly record struct HmacHeader(
    string Client,
    IReadOnlyList<string> SignedHeaders,
    string Signature
);
