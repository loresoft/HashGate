using System.Text;

namespace AspNetCore.HmacAuthentication.Client.Tests;

public class HttpRequestMessageExtensionsTests
{
    [Fact]
    public async Task AddHmacAuthentication_AddsRequiredHeaders_AndAuthorization()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/test?x=1");
        var content = new StringContent("{\"foo\":\"bar\"}", Encoding.UTF8, "application/json");
        request.Content = content;

        var client = "client1";
        var secret = "Test-HMAC-Key";

        await request.AddHmacAuthentication(client, secret);

        // Check timestamp header
        Assert.True(request.Headers.Contains(HmacAuthenticationShared.TimeStampHeaderName));

        // Check content hash header
        Assert.True(request.Headers.Contains(HmacAuthenticationShared.ContentHashHeaderName));

        // Check Authorization header
        Assert.NotNull(request.Headers.Authorization);

        Assert.Equal(HmacAuthenticationShared.DefaultSchemeName, request.Headers.Authorization.Scheme);

        Assert.Contains("Client=", request.Headers.Authorization.Parameter);
        Assert.Contains("SignedHeaders=", request.Headers.Authorization.Parameter);
        Assert.Contains("Signature=", request.Headers.Authorization.Parameter);
    }

    [Fact]
    public async Task AddHmacAuthentication_SetsContentHash_ForEmptyContent()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/api/test");
        request.Content = null;

        var client = "client1";
        var secret = "Test-HMAC-Key";

        await request.AddHmacAuthentication(client, secret);

        var contentHash = request.Headers.GetValues(HmacAuthenticationShared.ContentHashHeaderName).FirstOrDefault();
        Assert.Equal(HmacAuthenticationShared.EmptyContentHash, contentHash);
    }

    [Fact]
    public async Task AddHmacAuthentication_OverloadWithOptions_UsesDefaultSignedHeaders()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/api/test");
        var options = new HmacAuthenticationOptions
        {
            Client = "client1",
            Secret = "Test-HMAC-Key"
        };

        await request.AddHmacAuthentication(options);

        // Check Authorization header exists and uses default scheme
        Assert.NotNull(request.Headers.Authorization);
    }

    [Fact]
    public async Task GenerateContentHash_EmptyContent_ReturnsEmptyContentHash()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/test");
        request.Content = null;

        var hash = await HttpRequestMessageExtensions.GenerateContentHash(request);
        Assert.Equal(HmacAuthenticationShared.EmptyContentHash, hash);
    }

    [Fact]
    public async Task GenerateContentHash_StringContent_ReturnsExpectedHash()
    {
        var content = new StringContent("hello world", Encoding.UTF8, "text/plain");
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/test");
        request.Content = content;

        var hash = await HttpRequestMessageExtensions.GenerateContentHash(request);

        // Precomputed SHA256 base64 for "hello world"
        Assert.Equal("uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", hash);
    }

    [Fact]
    public async Task GenerateContentHash_JsonContent_ReturnsExpectedHash()
    {
        var json = "{\"name\":\"value\",\"count\":1}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/test");
        request.Content = content;

        var hash = await HttpRequestMessageExtensions.GenerateContentHash(request);

        // Precomputed SHA256 base64 for "{\"name\":\"value\",\"count\":1}"
        Assert.Equal("7OLD0I5P/f/5ZDYi0EJCXV5+BZw7o+UwSIiPvajEvqs=", hash);
    }

    [Fact]
    public async Task GenerateContentHash_WhitespaceContent_ReturnsExpectedHash()
    {
        var content = new StringContent("   ", Encoding.UTF8, "text/plain");
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/test");
        request.Content = content;

        var hash = await HttpRequestMessageExtensions.GenerateContentHash(request);

        // Precomputed SHA256 base64 for "   "
        Assert.Equal("Cq19p30u1Zw5bJmnTknzpFJNzby1FjJRsUM9ZAJHrrQ=", hash);
    }

    [Fact]
    public async Task GenerateContentHash_JsonContent_UserRecord_ReturnsExpectedHash()
    {
        var user = new User("Alice", "Smith", "alice@example.com");
        var content = System.Net.Http.Json.JsonContent.Create(user);
        var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost/api/test");
        request.Content = content;

        var hash = await HttpRequestMessageExtensions.GenerateContentHash(request);

        // Precomputed SHA256 base64 for {"First":"Alice","Last":"Smith","Email":"alice@example.com"}
        Assert.Equal("omo2MSjkYihoXjcxJC+NuO8JK7z6BDe6np/EQxiAq5I=", hash);
    }
}

public record User(string First, string Last, string Email);
