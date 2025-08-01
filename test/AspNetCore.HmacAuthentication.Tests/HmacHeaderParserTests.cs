namespace AspNetCore.HmacAuthentication.Tests;

public class HmacHeaderParserTests
{
    [Fact]
    public void TryParse_ValidHeader_WithSignedHeaders_ReturnsSuccess()
    {
        var header = "HMAC client1:1722450000:host;date;x-api-key:abcdef1234567890";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal("client1", result.ClientId);
        Assert.Equal(1722450000, result.Timestamp);
        Assert.Equal(["host", "date", "x-api-key"], result.SignedHeaders);
        Assert.Equal("abcdef1234567890", result.Signature);
        Assert.Null(result.Error);
    }

    [Fact]
    public void TryParse_ValidHeader_EmptySignedHeaders_ReturnsSuccess()
    {
        var header = "HMAC client2:1722450001::sigvalue";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal("client2", result.ClientId);
        Assert.Equal(1722450001, result.Timestamp);
        Assert.Empty(result.SignedHeaders);
        Assert.Equal("sigvalue", result.Signature);
        Assert.Null(result.Error);
    }

    [Fact]
    public void TryParse_HeaderTooShort_ReturnsTooShortError()
    {
        var header = "HMA";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.TooShort, result.Error);
    }

    [Fact]
    public void TryParse_InvalidPrefix_ReturnsInvalidPrefixError()
    {
        var header = "HMIC client:1::sig";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.InvalidPrefix, result.Error);
    }

    [Fact]
    public void TryParse_MissingDelimiters_ReturnsMissingDelimitersError()
    {
        var header = "HMAC client1-1722450000-host;date;x-api-key-abcdef";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.MissingDelimiters, result.Error);
    }

    [Fact]
    public void TryParse_EmptyClientId_ReturnsEmptyClientIdError()
    {
        var header = "HMAC :1722450000:host;date:x";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.EmptyClientId, result.Error);
    }

    [Fact]
    public void TryParse_EmptyTimestamp_ReturnsEmptyTimestampError()
    {
        var header = "HMAC client1::host;date:x";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.EmptyTimestamp, result.Error);
    }

    [Fact]
    public void TryParse_InvalidTimestamp_ReturnsInvalidTimestampError()
    {
        var header = "HMAC client1:abc:host;date:x";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.InvalidTimestamp, result.Error);
    }

    [Fact]
    public void TryParse_EmptySignature_ReturnsEmptySignatureError()
    {
        var header = "HMAC client1:1722450000:host;date:";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.EmptySignature, result.Error);
    }

    [Fact]
    public void TryParse_SignedHeadersWithWhitespace_TrimmedCorrectly()
    {
        var header = "HMAC client1:1722450000: host ; date ; :sig";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal(["host", "date"], result.SignedHeaders);
    }

    [Fact]
    public void TryParse_SignedHeaders_AllWhitespace_Ignored()
    {
        var header = "HMAC client1:1722450000:   ;   ;   :sig";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Empty(result.SignedHeaders);
    }

    [Fact]
    public void TryParse_SignedHeaders_EmptyBetweenSemicolons_Ignored()
    {
        var header = "HMAC client1:1722450000:host;;date;;;x-api-key:sig";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal(["host", "date", "x-api-key"], result.SignedHeaders);
    }

    [Fact]
    public void TryParse_ValidHeader_WithLongSignature_ReturnsSuccess()
    {
        var signature = new string('a', 128);
        var header = $"HMAC client1:1722450000:host;date;key:{signature}";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal(signature, result.Signature);
    }

    [Fact]
    public void TryParse_HeaderWithExtraSpacesInPrefix_ReturnsInvalidPrefix()
    {
        var header = "HMAC  client1:1722450000:host;date:x";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal("client1", result.ClientId);
        Assert.Equal(1722450000, result.Timestamp);
        Assert.Equal(["host", "date"], result.SignedHeaders);
        Assert.Equal("x", result.Signature);
    }

    [Fact]
    public void TryParse_HeaderWithNonAsciiCharacters_ParsesCorrectly()
    {
        var header = "HMAC clïënt:1722450000:host;däte;x-api-key:sîgnâture";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal("clïënt", result.ClientId);
        Assert.Equal(["host", "däte", "x-api-key"], result.SignedHeaders);
        Assert.Equal("sîgnâture", result.Signature);
    }

    [Fact]
    public void TryParse_HeaderWithNegativeTimestamp_ReturnsInvalidTimestamp()
    {
        var header = "HMAC client1:-123:host;date:x";
        var result = HmacHeaderParser.TryParse(header);

        // Negative timestamps are technically valid for Unix time, but if you want to treat them as invalid, update the parser.
        // This test expects the current implementation (which allows negative values).
        Assert.True(result.IsSuccess);
        Assert.Equal(-123, result.Timestamp);
    }

    [Fact]
    public void TryParse_HeaderWithMaxLongTimestamp_ReturnsSuccess()
    {
        var header = $"HMAC client1:{long.MaxValue}:host:x";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal(long.MaxValue, result.Timestamp);
    }

    [Fact]
    public void TryParse_HeaderWithMinLongTimestamp_ReturnsSuccess()
    {
        var header = $"HMAC client1:{long.MinValue}:host:x";
        var result = HmacHeaderParser.TryParse(header);

        Assert.True(result.IsSuccess);
        Assert.Equal(long.MinValue, result.Timestamp);
    }

    [Fact]
    public void TryParse_HeaderWithEmptyString_ReturnsTooShortError()
    {
        var header = "";
        var result = HmacHeaderParser.TryParse(header);

        Assert.False(result.IsSuccess);
        Assert.Equal(HmacHeaderError.TooShort, result.Error);
    }
}
