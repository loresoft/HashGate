namespace HashGate.AspNetCore.Tests;

public class HmacHeaderParserTests
{
    [Fact]
    public void TryParse_ValidHeaderWithPrefix_ReturnsNoneAndParsesCorrectly()
    {
        var input = "HMAC Client=abc123&SignedHeaders=host;date&Signature=xyz789";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.None, result);
        Assert.Equal("abc123", header.Client);
        Assert.Equal(["host", "date"], header.SignedHeaders);
        Assert.Equal("xyz789", header.Signature);
    }

    [Fact]
    public void TryParse_ValidHeaderWithoutPrefix_ReturnsNoneAndParsesCorrectly()
    {
        var input = "Client=abc123&SignedHeaders=host;date&Signature=xyz789";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.None, result);
        Assert.Equal("abc123", header.Client);
        Assert.Equal(["host", "date"], header.SignedHeaders);
        Assert.Equal("xyz789", header.Signature);
    }

    [Fact]
    public void TryParse_MissingClient_ReturnsInvalidClients()
    {
        var input = "SignedHeaders=host;date&Signature=xyz789";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidHeaderFormat, result);
    }

    [Fact]
    public void TryParse_MissingSignedHeaders_ReturnsInvalidSignedHeaders()
    {
        var input = "Client=abc123&Signature=xyz789";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidHeaderFormat, result);
    }

    [Fact]
    public void TryParse_MissingSignature_ReturnsInvalidSignature()
    {
        var input = "Client=abc123&SignedHeaders=host;date";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidHeaderFormat, result);
    }

    [Fact]
    public void TryParse_EmptyInput_ReturnsInvalidHeaderFormat()
    {
        var input = "";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidHeaderFormat, result);
    }

    [Fact]
    public void TryParse_ValidHeader_OutOfOrder_ReturnsNoneAndParsesCorrectly()
    {
        var input = "Signature=xyz789&Client=abc123&SignedHeaders=host;date";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.None, result);
        Assert.Equal("abc123", header.Client);
        Assert.Equal(["host", "date"], header.SignedHeaders);
        Assert.Equal("xyz789", header.Signature);
    }

    [Fact]
    public void TryParse_EmptyClient_ReturnsInvalidClients()
    {
        var input = "Client=&SignedHeaders=host;date&Signature=xyz789";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidClients, result);
    }

    [Fact]
    public void TryParse_EmptySignedHeaders_ReturnsInvalidSignedHeaders()
    {
        var input = "Client=abc123&SignedHeaders=&Signature=xyz789";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidSignedHeaders, result);
    }

    [Fact]
    public void TryParse_EmptySignature_ReturnsInvalidSignature()
    {
        var input = "Client=abc123&SignedHeaders=host;date&Signature=";
        var result = HmacHeaderParser.TryParse(input, out var header);

        Assert.Equal(HmacHeaderError.InvalidSignature, result);
    }
}
