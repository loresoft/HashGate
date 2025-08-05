using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.HmacAuthentication.Tests;

public class HmacAuthenticationHandlerTests
{
    private readonly HmacAuthenticationSchemeOptions _options;
    private readonly AuthenticationScheme _scheme;
    private readonly IOptionsMonitor<HmacAuthenticationSchemeOptions> _optionsMonitor;
    private readonly ILoggerFactory _loggerFactory;
    private readonly UrlEncoder _urlEncoder;

    public HmacAuthenticationHandlerTests()
    {
        _options = new HmacAuthenticationSchemeOptions();
        _scheme = new AuthenticationScheme(HmacAuthenticationShared.DefaultSchemeName, "HMAC Scheme", typeof(HmacAuthenticationHandler));
        _optionsMonitor = new TestOptionsMonitor(_options);
        _loggerFactory = new NullLoggerFactory();
        _urlEncoder = UrlEncoder.Default;
    }

    private HmacAuthenticationHandler CreateHandler(string key = "Test-HMAC-Key")
    {
        var provider = new TestHmacKeyProvider(key);
        return new HmacAuthenticationHandler(_optionsMonitor, _loggerFactory, _urlEncoder, provider);
    }

    private static DefaultHttpContext CreateHttpContext(
        string method = "GET",
        string url = "/",
        string? content = null,
        string secretKey = "Test-HMAC-Key")
    {
        var context = new DefaultHttpContext();

        // Set HTTP method
        context.Request.Method = method;

        // Parse URL and set request properties
        var uri = new Uri("http://localhost" + url, UriKind.Absolute);

        context.Request.Scheme = uri.Scheme;
        context.Request.Host = new HostString(uri.Host, uri.Port);
        context.Request.Path = uri.AbsolutePath;
        context.Request.QueryString = new QueryString(uri.Query);

        // set timestamp header
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        context.Request.Headers.Append(HmacAuthenticationShared.TimeStampHeaderName, timestamp);

        // get content hash
        var contentBytes = Encoding.UTF8.GetBytes(content ?? string.Empty);
        var contentHash = SHA256.HashData(contentBytes);
        var contentHashEncoded = Convert.ToBase64String(contentHash);

        // Set content body
        context.Request.Body = new System.IO.MemoryStream(contentBytes);
        context.Request.ContentLength = contentBytes.Length;

        // set content hash header
        context.Request.Headers.Append(HmacAuthenticationShared.ContentHashHeaderName, contentHashEncoded);

        // Generate the Authorization header
        var stringToSign = HmacAuthenticationShared.CreateStringToSign(
            method: context.Request.Method,
            pathAndQuery: context.Request.Path + context.Request.QueryString,
            headerValues: [context.Request.Host.ToString(), timestamp, contentHashEncoded]
        );

        var signature = HmacAuthenticationShared.GenerateSignature(stringToSign, secretKey);

        context.Request.Headers.Authorization = HmacAuthenticationShared.GenerateAuthorizationHeader(
            client: "client1",
            signedHeaders: HmacAuthenticationShared.DefaultSignedHeaders,
            signature: signature
        );

        return context;
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsSuccess_WhenSignatureIsValid()
    {
        var handler = CreateHandler();
        var context = CreateHttpContext();
        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.IsType<ClaimsPrincipal>(result.Principal);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenSignatureIsInvalid()
    {
        var handler = CreateHandler("Wrong-Key");
        var context = CreateHttpContext(secretKey: "Test-HMAC-Key");
        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid signature", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenAuthorizationHeaderMissing()
    {
        var handler = CreateHandler();
        var context = CreateHttpContext();

        // Remove Authorization header to simulate missing header
        context.Request.Headers.Remove("Authorization");

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid Authorization header", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenTimestampExpired()
    {
        var handler = CreateHandler();
        var context = CreateHttpContext();

        // Set timestamp to 10 minutes ago (assuming default tolerance is 5)
        var expiredTimestamp = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds().ToString();
        context.Request.Headers[HmacAuthenticationShared.TimeStampHeaderName] = expiredTimestamp;

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid timestamp header", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenContentHashHeaderMissing()
    {
        var handler = CreateHandler();
        var context = CreateHttpContext();

        // Remove ContentHash header to simulate missing header
        context.Request.Headers.Remove(HmacAuthenticationShared.ContentHashHeaderName);

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid content hash header", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsSuccess_WithValidJsonContent()
    {
        var handler = CreateHandler();

        var jsonContent ="""{ "username": "testuser", "password": "secret" }""";

        var context = CreateHttpContext(
            method: "POST",
            url: "/api/login",
            content: jsonContent,
            secretKey: "Test-HMAC-Key"
        );
        context.Request.ContentType = "application/json";

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.IsType<ClaimsPrincipal>(result.Principal);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsSuccess_WithJsonContentAndQueryString()
    {
        var handler = CreateHandler();

        var jsonContent = """{ "username": "testuser", "password": "secret" }""";

        var context = CreateHttpContext(
            method: "POST",
            url: "/api/login?returnUrl=%2Fdashboard",
            content: jsonContent,
            secretKey: "Test-HMAC-Key"
        );
        context.Request.ContentType = "application/json";

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.IsType<ClaimsPrincipal>(result.Principal);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenTimestampHeaderMissing()
    {
        var handler = CreateHandler();
        var context = CreateHttpContext();

        // Remove Timestamp header to simulate missing header
        context.Request.Headers.Remove(HmacAuthenticationShared.TimeStampHeaderName);

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid timestamp header", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenAuthorizationHeaderFormatIsInvalid()
    {
        var handler = CreateHandler();
        var context = CreateHttpContext();

        // Set Authorization header to an invalid format
        context.Request.Headers.Authorization = "InvalidFormat";

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid Authorization header: InvalidSchema", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ReturnsFail_WhenContentHashDoesNotMatch()
    {
        var handler = CreateHandler();

        var jsonContent = """{ "username": "testuser", "password": "secret" }""";

        var context = CreateHttpContext(
            method: "POST",
            url: "/api/login",
            content: jsonContent,
            secretKey: "Test-HMAC-Key"
        );
        context.Request.ContentType = "application/json";

        // Overwrite the content hash header with an incorrect value
        context.Request.Headers[HmacAuthenticationShared.ContentHashHeaderName] = Convert.ToBase64String(Encoding.UTF8.GetBytes("wrong-hash"));

        await handler.InitializeAsync(_scheme, context);

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid content hash header", result.Failure?.Message);
    }
}


public class TestOptionsMonitor(HmacAuthenticationSchemeOptions options) : IOptionsMonitor<HmacAuthenticationSchemeOptions>
{
    public HmacAuthenticationSchemeOptions CurrentValue { get; } = options;

    public HmacAuthenticationSchemeOptions Get(string? name) => CurrentValue;

    public IDisposable? OnChange(Action<HmacAuthenticationSchemeOptions, string?> listener) => null;
}

public class TestHmacKeyProvider(string key = "Test-HMAC-Key") : IHmacKeyProvider
{
    public ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default) => new(key);
}
