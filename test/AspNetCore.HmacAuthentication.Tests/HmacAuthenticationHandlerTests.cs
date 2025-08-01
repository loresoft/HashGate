using System.Text;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AspNetCore.HmacAuthentication.Tests;

public class HmacAuthenticationHandlerTests
{
    private class TestHmacKeyProvider : IHmacKeyProvider
    {
        private readonly Dictionary<string, string> _secrets;
        public TestHmacKeyProvider(Dictionary<string, string> secrets) => _secrets = secrets;
        public ValueTask<string?> GetSecretAsync(string clientId)
            => new(_secrets.TryGetValue(clientId, out var secret) ? secret : null);
    }

    private class TestOptionsMonitor<T> : IOptionsMonitor<T> where T : class
    {
        public T CurrentValue { get; }
        public TestOptionsMonitor(T value) => CurrentValue = value;
        public T Get(string name) => CurrentValue;
        public IDisposable OnChange(Action<T, string> listener) => null!;
    }

    private static HmacAuthenticationHandler CreateHandler(
        string authorizationHeader,
        string method = "GET",
        string path = "/api/test",
        string query = "",
        string body = "",
        long timestamp = 1722450000,
        string clientId = "myClient",
        string clientSecret = "superSecret",
        IEnumerable<string>? signedHeaders = null,
        string? overrideSignature = null,
        int toleranceWindow = 10)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.QueryString = new QueryString(query);
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        context.Request.ContentLength = body.Length;
        context.Request.Headers.Authorization = authorizationHeader;

        if (signedHeaders != null)
        {
            foreach (var header in signedHeaders)
                context.Request.Headers[header] = "header-value";
        }

        var options = new HmacAuthenticationOptions
        {
            ToleranceWindow = toleranceWindow
        };

        var optionsMonitor = new TestOptionsMonitor<HmacAuthenticationOptions>(options);
        var loggerFactory = new NullLoggerFactory();
        var encoder = UrlEncoder.Default;

        var secrets = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(clientId))
            secrets[clientId] = clientSecret ?? "";

        var keyProvider = new TestHmacKeyProvider(secrets);

        var handler = new HmacAuthenticationHandler(optionsMonitor, loggerFactory, encoder, keyProvider);
        handler.InitializeAsync(new AuthenticationScheme("HMAC", null, typeof(HmacAuthenticationHandler)), context);

        return handler;
    }

    private static string BuildAuthorizationHeader(
        string clientId,
        long timestamp,
        IEnumerable<string> signedHeaders,
        string signature)
    {
        var headers = string.Join(";", signedHeaders);
        return $"HMAC {clientId}:{timestamp}:{headers}:{signature}";
    }

    [Fact]
    public async Task HandleAuthenticateAsync_SuccessfulAuthentication_ReturnsSuccess()
    {
        var clientId = "myClient";
        var clientSecret = "superSecret";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedHeaders = new[] { "host" };
        var method = "GET";
        var path = "/api/test";
        var query = "";
        var body = "";

        var canonicalHeaders = "host:header-value";
        var stringToSign = HmacAuthenticationHandler.CreateStringToSign(method, new PathString(path), new QueryString(query), timestamp, canonicalHeaders, signedHeaders, body);
        var signature = HmacAuthenticationHandler.GenerateHmacSignature(stringToSign, clientSecret);

        var authorizationHeader = BuildAuthorizationHeader(clientId, timestamp, signedHeaders, signature);

        var handler = CreateHandler(
            authorizationHeader,
            method,
            path,
            query,
            body,
            timestamp,
            clientId,
            clientSecret,
            signedHeaders);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.Equal(clientId, result.Principal.Identity?.Name);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MissingAuthorizationHeader_ReturnsFail()
    {
        var handler = CreateHandler("");
        var result = await handler.AuthenticateAsync();
        Assert.False(result.Succeeded);
        Assert.Contains("Invalid Authorization header", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidSignature_ReturnsFail()
    {
        var clientId = "myClient";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedHeaders = new[] { "host" };
        var authorizationHeader = BuildAuthorizationHeader(clientId, timestamp, signedHeaders, "invalidsignature");

        var handler = CreateHandler(
            authorizationHeader,
            clientId: clientId,
            signedHeaders: signedHeaders);

        var result = await handler.AuthenticateAsync();
        Assert.False(result.Succeeded);
        Assert.Contains("Invalid signature", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExpiredTimestamp_ReturnsFail()
    {
        var clientId = "myClient";
        var clientSecret = "superSecret";
        var timestamp = DateTimeOffset.UtcNow.AddMinutes(-30).ToUnixTimeSeconds();
        var signedHeaders = new[] { "host" };
        var method = "GET";
        var path = "/api/test";
        var query = "";
        var body = "";

        var canonicalHeaders = "host:header-value";
        var stringToSign = HmacAuthenticationHandler.CreateStringToSign(method, new PathString(path), new QueryString(query), timestamp, canonicalHeaders, signedHeaders, body);
        var signature = HmacAuthenticationHandler.GenerateHmacSignature(stringToSign, clientSecret);

        var authorizationHeader = BuildAuthorizationHeader(clientId, timestamp, signedHeaders, signature);

        var handler = CreateHandler(
            authorizationHeader,
            method,
            path,
            query,
            body,
            timestamp,
            clientId,
            clientSecret,
            signedHeaders);

        var result = await handler.AuthenticateAsync();
        Assert.False(result.Succeeded);
        Assert.Contains("timestamp is invalid or expired", result.Failure?.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidClientId_ReturnsFail()
    {
        var clientId = "unknownClient";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedHeaders = new[] { "host" };
        var authorizationHeader = BuildAuthorizationHeader(clientId, timestamp, signedHeaders, "signature");

        var handler = CreateHandler(
            authorizationHeader,
            clientId: clientId,
            clientSecret: "",
            signedHeaders: signedHeaders);

        var result = await handler.AuthenticateAsync();
        Assert.False(result.Succeeded);
        Assert.Contains("Invalid client ID", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_EmptySignedHeaders_AllowsEmptyCanonicalHeaders()
    {
        var clientId = "myClient";
        var clientSecret = "superSecret";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedHeaders = Array.Empty<string>();
        var method = "POST";
        var path = "/api/emptyheaders";
        var query = "?foo=bar";
        var body = "test-body";

        var canonicalHeaders = "";
        var stringToSign = HmacAuthenticationHandler.CreateStringToSign(method, new PathString(path), new QueryString(query), timestamp, canonicalHeaders, signedHeaders, body);
        var signature = HmacAuthenticationHandler.GenerateHmacSignature(stringToSign, clientSecret);

        var authorizationHeader = BuildAuthorizationHeader(clientId, timestamp, signedHeaders, signature);

        var handler = CreateHandler(
            authorizationHeader,
            method,
            path,
            query,
            body,
            timestamp,
            clientId,
            clientSecret,
            signedHeaders);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.Equal(clientId, result.Principal.Identity?.Name);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RequestBodyIsReadCorrectly()
    {
        var clientId = "myClient";
        var clientSecret = "superSecret";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedHeaders = new[] { "host" };
        var method = "POST";
        var path = "/api/body";
        var query = "";
        var body = "request-body-content";

        var canonicalHeaders = "host:header-value";
        var stringToSign = HmacAuthenticationHandler.CreateStringToSign(method, new PathString(path), new QueryString(query), timestamp, canonicalHeaders, signedHeaders, body);
        var signature = HmacAuthenticationHandler.GenerateHmacSignature(stringToSign, clientSecret);

        var authorizationHeader = BuildAuthorizationHeader(clientId, timestamp, signedHeaders, signature);

        var handler = CreateHandler(
            authorizationHeader,
            method,
            path,
            query,
            body,
            timestamp,
            clientId,
            clientSecret,
            signedHeaders);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.Equal(clientId, result.Principal.Identity?.Name);
    }

    [Fact]
    public void CreateStringToSign_ProducesExpectedFormat()
    {
        // Arrange
        var method = "POST";
        var path = new PathString("/api/resource");
        var query = new QueryString("?foo=bar&baz=qux");
        long timestamp = 1722450000;
        var canonicalHeaders = "host:example.com\ncontent-type:application/json";
        var signedHeaders = new[] { "host", "content-type" };
        var body = "{\"data\":42}";

        // Act
        var result = HmacAuthenticationHandler.CreateStringToSign(
            method,
            path,
            query,
            timestamp,
            canonicalHeaders,
            signedHeaders,
            body);

        // Assert
        var expected =
            "POST\n" +
            "/api/resource?foo=bar&baz=qux\n" +
            "1722450000\n" +
            "host:example.com\ncontent-type:application/json\n" +
            "host;content-type\n" +
            "{\"data\":42}";
        Assert.Equal(expected, result);
    }

    [Fact]
    public void CreateStringToSign_EmptyHeadersAndBody_ProducesExpectedFormat()
    {
        // Arrange
        var method = "GET";
        var path = new PathString("/api/empty");
        var query = QueryString.Empty;
        long timestamp = 1234567890;
        var canonicalHeaders = "";
        var signedHeaders = Array.Empty<string>();
        var body = "";

        // Act
        var result = HmacAuthenticationHandler.CreateStringToSign(
            method,
            path,
            query,
            timestamp,
            canonicalHeaders,
            signedHeaders,
            body);

        // Assert
        var expected =
            "GET\n" +
            "/api/empty\n" +
            "1234567890\n" +
            "\n" +
            "\n";
        Assert.Equal(expected, result);
    }

    [Fact]
    public void GenerateHmacSignature_ProducesExpectedSignature()
    {
        // Arrange
        var stringToSign = "POST\n/api/resource?foo=bar\n1722450000\nhost:example.com\nhost\n{\"data\":42}";
        var secretKey = "superSecret";

        // Act
        var signature = HmacAuthenticationHandler.GenerateHmacSignature(stringToSign, secretKey);

        // Assert
        // Compute expected signature using .NET's HMACSHA256
        var expectedBytes = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(secretKey))
            .ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
        var expectedSignature = Convert.ToBase64String(expectedBytes);

        Assert.Equal(expectedSignature, signature);
    }

    [Fact]
    public void GenerateHmacSignature_EmptyStringAndKey_ProducesExpectedSignature()
    {
        // Arrange
        var stringToSign = "";
        var secretKey = "";

        // Act
        var signature = HmacAuthenticationHandler.GenerateHmacSignature(stringToSign, secretKey);

        // Assert
        var expectedBytes = new System.Security.Cryptography.HMACSHA256(Array.Empty<byte>())
            .ComputeHash(Array.Empty<byte>());
        var expectedSignature = Convert.ToBase64String(expectedBytes);

        Assert.Equal(expectedSignature, signature);
    }
}
