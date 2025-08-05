namespace HashGate.AspNetCore;

/// <summary>
/// Provides methods for parsing HMAC authentication headers into their component parts.
/// Supports parsing authorization headers in the format: "HMAC Client={value}&amp;SignedHeaders={value}&amp;Signature={value}".
/// </summary>
public static class HmacHeaderParser
{
    private const string PREFIX = "HMAC ";
    private const string CLIENT = "Client=";
    private const string SIGNED_HEADERS = "SignedHeaders=";
    private const string SIGNATURE = "Signature=";

    /// <summary>
    /// Attempts to parse an HMAC authentication header with optional "HMAC" prefix.
    /// This is a convenience method that calls the main TryParse method with requirePrefix set to false.
    /// </summary>
    /// <param name="input">The authorization header value to parse.</param>
    /// <param name="hmacHeader">When this method returns, contains the parsed HMAC header components if successful; otherwise, the default value.</param>
    /// <returns>
    /// <see cref="HmacHeaderError.None"/> if parsing succeeded; otherwise, an error value indicating the specific parsing failure.
    /// </returns>
    public static HmacHeaderError TryParse(ReadOnlySpan<char> input, out HmacHeader hmacHeader)
        => TryParse(input, false, out hmacHeader);

    /// <summary>
    /// Attempts to parse an HMAC authentication header into its component parts.
    /// The expected format is: "HMAC Client={clientId}&amp;SignedHeaders={headers}&amp;Signature={signature}"
    /// where headers are semicolon-separated header names.
    /// </summary>
    /// <param name="input">The authorization header value to parse.</param>
    /// <param name="requirePrefix">
    /// If <c>true</c>, the input must start with "HMAC " prefix;
    /// if <c>false</c>, the prefix is optional and will be stripped if present.
    /// </param>
    /// <param name="hmacHeader">
    /// When this method returns, contains the parsed HMAC header components if successful;
    /// otherwise, the default value.
    /// </param>
    /// <returns>
    /// <see cref="HmacHeaderError.None"/> if parsing succeeded; otherwise, an error value indicating the specific parsing failure:
    /// <list type="bullet">
    /// <item><description><see cref="HmacHeaderError.InvalidSchema"/> - Missing required "HMAC" prefix when requirePrefix is true</description></item>
    /// <item><description><see cref="HmacHeaderError.InvalidHeaderFormat"/> - Not all three required components (Client, SignedHeaders, Signature) are present</description></item>
    /// <item><description><see cref="HmacHeaderError.InvalidClients"/> - Client parameter is missing or empty</description></item>
    /// <item><description><see cref="HmacHeaderError.InvalidSignedHeaders"/> - SignedHeaders parameter is missing or empty</description></item>
    /// <item><description><see cref="HmacHeaderError.InvalidSignature"/> - Signature parameter is missing or empty</description></item>
    /// </list>
    /// </returns>
    /// <example>
    /// <code>
    /// var headerValue = "HMAC Client=myClientId&amp;SignedHeaders=host;x-timestamp&amp;Signature=abc123";
    /// var result = HmacHeaderParser.TryParse(headerValue, true, out var hmacHeader);
    /// if (result == HmacHeaderError.None)
    /// {
    ///     Console.WriteLine($"Client: {hmacHeader.Client}");
    ///     Console.WriteLine($"Headers: {string.Join(", ", hmacHeader.SignedHeaders)}");
    ///     Console.WriteLine($"Signature: {hmacHeader.Signature}");
    /// }
    /// </code>
    /// </example>
    public static HmacHeaderError TryParse(ReadOnlySpan<char> input, bool requirePrefix, out HmacHeader hmacHeader)
    {
        hmacHeader = default;

        // Check for prefix if required
        if (requirePrefix)
        {
            if (!input.StartsWith(PREFIX, StringComparison.OrdinalIgnoreCase))
                return HmacHeaderError.InvalidSchema;
            input = input[PREFIX.Length..];
        }
        else
        {
            // Make prefix optional
            if (input.StartsWith(PREFIX, StringComparison.OrdinalIgnoreCase))
                input = input[PREFIX.Length..];
        }

        // Use Span-based parsing for performance, avoid allocations
        ReadOnlySpan<char> client = default, signedHeadersRaw = default, signature = default;
        int found = 0;

        while (!input.IsEmpty)
        {
            int ampIdx = input.IndexOf('&');
            var part = ampIdx >= 0 ? input[..ampIdx] : input;

            if (part.StartsWith(CLIENT, StringComparison.OrdinalIgnoreCase))
            {
                client = part[CLIENT.Length..];
                found++;
            }
            else if (part.StartsWith(SIGNED_HEADERS, StringComparison.OrdinalIgnoreCase))
            {
                signedHeadersRaw = part[SIGNED_HEADERS.Length..];
                found++;
            }
            else if (part.StartsWith(SIGNATURE, StringComparison.OrdinalIgnoreCase))
            {
                signature = part[SIGNATURE.Length..];
                found++;
            }

            if (ampIdx < 0) break;
            input = input.Slice(ampIdx + 1);
        }

        if (found != 3)
            return HmacHeaderError.InvalidHeaderFormat;

        if (client.IsEmpty)
            return HmacHeaderError.InvalidClients;

        if (signedHeadersRaw.IsEmpty)
            return HmacHeaderError.InvalidSignedHeaders;

        if (signature.IsEmpty)
            return HmacHeaderError.InvalidSignature;

        // Split signed headers efficiently
        var headersList = signedHeadersRaw.ToString().Split(';', StringSplitOptions.RemoveEmptyEntries);

        hmacHeader = new HmacHeader(
            client.ToString(),
            headersList,
            signature.ToString()
        );

        return HmacHeaderError.None;
    }
}
