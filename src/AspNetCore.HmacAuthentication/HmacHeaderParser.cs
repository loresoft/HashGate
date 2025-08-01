namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Provides methods for parsing HMAC authentication headers into their component parts.
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
///   <item><description><c>&lt;timestamp&gt;</c>: Unix epoch timestamp in seconds (required, non-empty, must be a valid integer).</description></item>
///   <item><description><c>&lt;signedHeaders&gt;</c>: Semicolon-separated list of header names included in the signature (may be empty).</description></item>
///   <item><description><c>&lt;signature&gt;</c>: The HMAC signature (required, non-empty).</description></item>
/// </list>
/// <b>Example:</b><br/>
/// <c>HMAC myClient:1722450000:host;date;content-type:abcdef1234567890</c>
/// </para>
/// <para>
/// If parsing fails, the returned <see cref="HmacHeaderData"/> will have the <see cref="HmacHeaderData.Error"/> property set to the encountered error, and all other properties will be set to their default values.
/// </para>
/// </remarks>
public static class HmacHeaderParser
{
    private const string PREFIX = "HMAC ";
    private const char DELIMITER = ':';
    private const char HEADER_SEPARATOR = ';';

    /// <summary>
    /// Attempts to parse an HMAC authentication header from a character span.
    /// </summary>
    /// <param name="input">The input span containing the HMAC header.</param>
    /// <returns>
    /// An <see cref="HmacHeaderData"/> instance containing the parsed header data if successful;
    /// otherwise, an instance with error information describing why parsing failed.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The expected header format is:
    /// <c>HMAC &lt;clientId&gt;:&lt;timestamp&gt;:&lt;signedHeaders&gt;:&lt;signature&gt;</c>
    /// </para>
    /// <para>
    /// If parsing fails, the <see cref="HmacHeaderData.Error"/> property will indicate the reason.
    /// </para>
    /// </remarks>
    public static HmacHeaderData TryParse(ReadOnlySpan<char> input)
    {
        // Check minimum length and prefix
        if (input.Length < PREFIX.Length)
            return HmacHeaderData.Failed(HmacHeaderError.TooShort);

        if (!input.StartsWith(PREFIX.AsSpan()))
            return HmacHeaderData.Failed(HmacHeaderError.InvalidPrefix);

        // Skip the "HMAC " prefix
        var remaining = input[PREFIX.Length..];

        // Find the three colons
        int firstColon = remaining.IndexOf(DELIMITER);
        if (firstColon < 0)
            return HmacHeaderData.Failed(HmacHeaderError.MissingDelimiters);

        int secondColon = remaining[(firstColon + 1)..].IndexOf(DELIMITER);
        if (secondColon < 0)
            return HmacHeaderData.Failed(HmacHeaderError.MissingDelimiters);

        secondColon += firstColon + 1; // Adjust to absolute position

        int thirdColon = remaining[(secondColon + 1)..].IndexOf(DELIMITER);
        if (thirdColon < 0)
            return HmacHeaderData.Failed(HmacHeaderError.MissingDelimiters);

        thirdColon += secondColon + 1; // Adjust to absolute position

        // Extract components using slicing
        var clientId = remaining[..firstColon].Trim();
        var timestampSpan = remaining.Slice(firstColon + 1, secondColon - firstColon - 1).Trim();
        var signedHeadersSpan = remaining.Slice(secondColon + 1, thirdColon - secondColon - 1).Trim();
        var signature = remaining[(thirdColon + 1)..].Trim();

        // Validate that all components have content (except signed headers which can be empty)
        if (clientId.IsEmpty)
            return HmacHeaderData.Failed(HmacHeaderError.EmptyClientId);

        if (timestampSpan.IsEmpty)
            return HmacHeaderData.Failed(HmacHeaderError.EmptyTimestamp);

        if (signature.IsEmpty)
            return HmacHeaderData.Failed(HmacHeaderError.EmptySignature);

        // Parse timestamp to long
        if (!long.TryParse(timestampSpan, out var timestamp))
            return HmacHeaderData.Failed(HmacHeaderError.InvalidTimestamp);

        if (signedHeadersSpan.IsEmpty)
            return new HmacHeaderData(clientId.ToString(), timestamp, [], signature.ToString());

        // Parse signed headers - split by semicolon (allow empty)
        var headersList = new List<string>();
        var headersRemaining = signedHeadersSpan;
        while (!headersRemaining.IsEmpty)
        {
            int separatorIndex = headersRemaining.IndexOf(HEADER_SEPARATOR);
            ReadOnlySpan<char> header;

            if (separatorIndex >= 0)
            {
                header = headersRemaining[..separatorIndex];
                headersRemaining = headersRemaining[(separatorIndex + 1)..];
            }
            else
            {
                header = headersRemaining;
                headersRemaining = [];
            }

            // Trim whitespace and add non-empty headers
            var trimmedHeader = header.Trim();
            if (!trimmedHeader.IsEmpty)
                headersList.Add(trimmedHeader.ToString());
        }

        return new HmacHeaderData(clientId.ToString(), timestamp, headersList, signature.ToString());
    }

    /// <summary>
    /// Attempts to parse an HMAC authentication header from a string.
    /// </summary>
    /// <param name="input">The input string containing the HMAC header.</param>
    /// <returns>
    /// An <see cref="HmacHeaderData"/> instance containing the parsed header data if successful;
    /// otherwise, an instance with error information describing why parsing failed.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The expected header format is:
    /// <c>HMAC &lt;clientId&gt;:&lt;timestamp&gt;:&lt;signedHeaders&gt;:&lt;signature&gt;</c>
    /// </para>
    /// <para>
    /// If parsing fails, the <see cref="HmacHeaderData.Error"/> property will indicate the reason.
    /// </para>
    /// </remarks>
    public static HmacHeaderData TryParse(string input)
        => TryParse(input.AsSpan());
}
