namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Provides methods for parsing HMAC authentication headers into their component parts.
/// </summary>
public static class HmacHeaderParser
{
    private const string PREFIX = "HMAC ";
    private const string CLIENT = "Client=";
    private const string SIGNED_HEADERS = "SignedHeaders=";
    private const string SIGNATURE = "Signature=";

    public static HmacHeaderError TryParse(ReadOnlySpan<char> input, out HmacHeader hmacHeader)
        => TryParse(input, false, out hmacHeader);

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
