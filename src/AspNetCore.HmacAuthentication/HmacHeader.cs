namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Represents the parsed components of an HMAC authentication header.
/// Contains the client identifier, list of signed headers, and the HMAC signature.
/// </summary>
/// <param name="Client">The client identifier used for authentication.</param>
/// <param name="SignedHeaders">The collection of header names that were included in the signature calculation.</param>
/// <param name="Signature">The Base64-encoded HMAC-SHA256 signature.</param>
public readonly record struct HmacHeader(
    string Client,
    IReadOnlyList<string> SignedHeaders,
    string Signature
);
