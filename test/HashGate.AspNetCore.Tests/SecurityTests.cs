using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.Tests;

/// <summary>
/// Security-focused tests for HMAC authentication hardening.
/// Covers: timing side-channels, CIDR validation, Content-Length bypass,
/// and signed-header enforcement.
/// </summary>
public class SecurityTests
{
    // ── FixedTimeEquals ──────────────────────────────────────────────

    [Theory]
    [InlineData("short", "muchlongerstring")]
    [InlineData("a", "ab")]
    [InlineData("abc", "ab")]
    public void FixedTimeEquals_DifferentLengths_ReturnsFalse(string left, string right)
    {
        Assert.False(HmacAuthenticationShared.FixedTimeEquals(left, right));
    }

    [Theory]
    [InlineData("same", "same")]
    [InlineData("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    public void FixedTimeEquals_IdenticalStrings_ReturnsTrue(string left, string right)
    {
        Assert.True(HmacAuthenticationShared.FixedTimeEquals(left, right));
    }

    [Fact]
    public void FixedTimeEquals_EmptyStrings_ReturnsTrue()
    {
        Assert.True(HmacAuthenticationShared.FixedTimeEquals("", ""));
    }

    // ── CIDR prefix length bounds ────────────────────────────────────

    [Theory]
    [InlineData(-1)]
    [InlineData(-100)]
    [InlineData(33)]  // IPv4 max is 32
    [InlineData(64)]
    [InlineData(999)]
    public void IsIpInNetwork_InvalidIPv4PrefixLength_ReturnsFalse(int prefix)
    {
        var ip = IPAddress.Parse("192.168.1.100");
        Assert.False(IpAddressWhitelist.IsIpInNetwork(ip, $"192.168.1.0/{prefix}"));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-100)]
    [InlineData(129)]  // IPv6 max is 128
    [InlineData(256)]
    public void IsIpInNetwork_InvalidIPv6PrefixLength_ReturnsFalse(int prefix)
    {
        var ip = IPAddress.Parse("2001:db8::1");
        Assert.False(IpAddressWhitelist.IsIpInNetwork(ip, $"2001:db8::/{prefix}"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(24)]
    [InlineData(32)]
    public void IsIpInNetwork_ValidIPv4PrefixLength_DoesNotThrow(int prefix)
    {
        var ip = IPAddress.Parse("192.168.1.100");
        // Should not throw; may return true or false depending on actual match
        _ = IpAddressWhitelist.IsIpInNetwork(ip, $"192.168.1.0/{prefix}");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(64)]
    [InlineData(128)]
    public void IsIpInNetwork_ValidIPv6PrefixLength_DoesNotThrow(int prefix)
    {
        var ip = IPAddress.Parse("2001:db8::1");
        _ = IpAddressWhitelist.IsIpInNetwork(ip, $"2001:db8::/{prefix}");
    }

    [Fact]
    public void IsIpInNetwork_NegativePrefixLength_DoesNotMatchAll()
    {
        // Before the fix, prefixLength=-1 would match ANY IP. Verify it doesn't.
        var ip = IPAddress.Parse("10.0.0.1");
        Assert.False(IpAddressWhitelist.IsIpInNetwork(ip, "192.168.1.0/-1"));
    }

    // ── Signed headers enforcement ───────────────────────────────────

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenTimestampNotInSignedHeaders()
    {
        // Build a request that omits x-timestamp from SignedHeaders
        var secretKey = "Test-HMAC-Key";
        var handler = CreateHandler();
        var context = CreateContextWithCustomSignedHeaders(
            secretKey: secretKey,
            // Missing x-timestamp
            signedHeaders: ["host", HmacAuthenticationShared.ContentHashHeaderName]);

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Missing required signed headers", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenContentHashNotInSignedHeaders()
    {
        // Build a request that omits x-content-sha256 from SignedHeaders
        var secretKey = "Test-HMAC-Key";
        var handler = CreateHandler();
        var context = CreateContextWithCustomSignedHeaders(
            secretKey: secretKey,
            // Missing x-content-sha256
            signedHeaders: ["host", HmacAuthenticationShared.TimeStampHeaderName]);

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Missing required signed headers", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsSuccess_WhenAllRequiredSignedHeadersPresent()
    {
        var secretKey = "Test-HMAC-Key";
        var handler = CreateHandler();
        var context = CreateContextWithCustomSignedHeaders(
            secretKey: secretKey,
            signedHeaders: HmacAuthenticationShared.DefaultSignedHeaders);

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsSuccess_WhenExtraSignedHeadersIncluded()
    {
        // Extra signed headers beyond the required ones should be fine
        var secretKey = "Test-HMAC-Key";
        var handler = CreateHandler();
        var context = CreateContextWithCustomSignedHeaders(
            secretKey: secretKey,
            signedHeaders: ["host", HmacAuthenticationShared.TimeStampHeaderName, HmacAuthenticationShared.ContentHashHeaderName, "content-type"],
            contentType: "application/json");

        await handler.InitializeAsync(CreateScheme(), context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private static HmacAuthenticationHandler CreateHandler()
    {
        var options = new HmacAuthenticationSchemeOptions();
        var optionsMonitor = new TestOptionsMonitor(options);
        return new HmacAuthenticationHandler(optionsMonitor, new NullLoggerFactory(), UrlEncoder.Default);
    }

    private static AuthenticationScheme CreateScheme()
    {
        return new AuthenticationScheme(
            HmacAuthenticationShared.DefaultSchemeName,
            "HMAC Scheme",
            typeof(HmacAuthenticationHandler));
    }

    private static DefaultHttpContext CreateContextWithCustomSignedHeaders(
        string secretKey,
        IReadOnlyList<string> signedHeaders,
        string? content = null,
        string? contentType = null)
    {
        var context = new DefaultHttpContext();

        var services = new ServiceCollection();
        services.AddSingleton<IHmacKeyProvider>(new TestHmacKeyProvider(secretKey));
        context.RequestServices = services.BuildServiceProvider();

        context.Request.Method = "POST";
        var uri = new Uri("http://localhost/api/test", UriKind.Absolute);
        context.Request.Scheme = uri.Scheme;
        context.Request.Host = new HostString(uri.Host, uri.Port);
        context.Request.Path = uri.AbsolutePath;
        context.Request.QueryString = new QueryString(uri.Query);

        if (contentType != null)
            context.Request.ContentType = contentType;

        // Set timestamp header
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        context.Request.Headers.Append(HmacAuthenticationShared.TimeStampHeaderName, timestamp);

        // Compute content hash
        var contentBytes = Encoding.UTF8.GetBytes(content ?? string.Empty);
        var contentHash = Convert.ToBase64String(SHA256.HashData(contentBytes));

        context.Request.Body = new MemoryStream(contentBytes);
        context.Request.ContentLength = contentBytes.Length;
        context.Request.Headers.Append(HmacAuthenticationShared.ContentHashHeaderName, contentHash);

        // Build header values in SignedHeaders order
        var headerValues = new string[signedHeaders.Count];
        for (int i = 0; i < signedHeaders.Count; i++)
        {
            headerValues[i] = signedHeaders[i] switch
            {
                "host" or "Host" => context.Request.Host.ToString(),
                "x-timestamp" => timestamp,
                "x-content-sha256" => contentHash,
                "content-type" or "Content-Type" => contentType ?? string.Empty,
                _ => string.Empty
            };
        }

        var stringToSign = HmacAuthenticationShared.CreateStringToSign(
            method: context.Request.Method,
            pathAndQuery: context.Request.Path + context.Request.QueryString,
            headerValues: headerValues);

        var signature = HmacAuthenticationShared.GenerateSignature(stringToSign, secretKey);

        context.Request.Headers.Authorization = HmacAuthenticationShared.GenerateAuthorizationHeader(
            client: "client1",
            signedHeaders: signedHeaders,
            signature: signature);

        return context;
    }
}
