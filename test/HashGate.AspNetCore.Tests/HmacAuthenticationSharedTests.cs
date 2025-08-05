using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace AspNetCore.HmacAuthentication.Tests;

public class HmacAuthenticationSharedTests
{
    [Fact]
    public void CreateStringToSign_CreatesExpectedFormat()
    {
        var method = "get";
        var pathAndQuery = "/api/resource?x=1";
        var headers = new[] { "value1", "value2" };
        var result = HmacAuthenticationShared.CreateStringToSign(method, pathAndQuery, headers);

        Assert.Equal("GET\n/api/resource?x=1\nvalue1;value2", result);
    }

    [Fact]
    public void CreateStringToSign_EmptyHeaders_CreatesExpectedFormat()
    {
        var method = "post";
        var pathAndQuery = "/api/empty";
        var headers = Array.Empty<string>();
        var result = HmacAuthenticationShared.CreateStringToSign(method, pathAndQuery, headers);

        Assert.Equal("POST\n/api/empty\n", result);
    }

    [Fact]
    public void CreateStringToSign_SingleHeader_CreatesExpectedFormat()
    {
        var method = "put";
        var pathAndQuery = "/api/one";
        var headers = new[] { "onlyone" };
        var result = HmacAuthenticationShared.CreateStringToSign(method, pathAndQuery, headers);

        Assert.Equal("PUT\n/api/one\nonlyone", result);
    }

    [Theory]
    [InlineData("", "", true)]
    [InlineData(" ", " ", true)]
    [InlineData("abc", "", false)]
    [InlineData("", "abc", false)]
    public void FixedTimeEquals_EmptyAndWhitespaceCases(string left, string right, bool expected)
    {
        Assert.Equal(expected, HmacAuthenticationShared.FixedTimeEquals(left, right));
    }

    [Theory]
    [InlineData("abc", "abc", true)]
    [InlineData("abc", "def", false)]
    [InlineData("abc", "abcd", false)]
    [InlineData("abc", "abc ", false)]
    public void FixedTimeEquals_ComparesCorrectly(string left, string right, bool expected)
    {
        Assert.Equal(expected, HmacAuthenticationShared.FixedTimeEquals(left, right));
    }


    [Fact]
    public void GenerateAuthorizationHeader_CreatesExpectedHeader()
    {
        var client = "abc123";
        var signedHeaders = new[] { "host", "date" };
        var signature = "xyz789";
        var header = HmacAuthenticationShared.GenerateAuthorizationHeader(client, signedHeaders, signature);

        Assert.Equal("HMAC Client=abc123&SignedHeaders=host;date&Signature=xyz789", header);
    }

    [Fact]
    public void GenerateAuthorizationHeader_EmptyHeaders_CreatesExpectedHeader()
    {
        var client = "empty";
        var signedHeaders = Array.Empty<string>();
        var signature = "sig";
        var header = HmacAuthenticationShared.GenerateAuthorizationHeader(client, signedHeaders, signature);

        Assert.Equal("HMAC Client=empty&SignedHeaders=&Signature=sig", header);
    }

    [Fact]
    public void GenerateSignature_EmptyInputs_ReturnsExpectedBase64()
    {
        var signature = HmacAuthenticationShared.GenerateSignature("", "");
        Assert.Equal(44, signature.Length);
        Assert.True(Convert.TryFromBase64String(signature, new Span<byte>(new byte[32]), out _));
    }

    [Fact]
    public void GenerateSignature_ReturnsExpectedBase64()
    {
        var stringToSign = "GET\n/api/resource?x=1\nvalue1;value2";
        var secretKey = "mysecret";
        var signature = HmacAuthenticationShared.GenerateSignature(stringToSign, secretKey);

        // Validate base64 length for SHA256
        Assert.Equal(44, signature.Length);

        // Should be valid base64
        Assert.True(Convert.TryFromBase64String(signature, new Span<byte>(new byte[32]), out _));
    }
}
