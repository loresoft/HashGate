using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Tests;

public class HmacAuthenticationHttpHandlerTests
{
    [Fact]
    [Obsolete]
    public async Task SendAsync_UsesOptionsAccessorValue()
    {
        // Arrange
        var options = Microsoft.Extensions.Options.Options.Create(new HmacAuthenticationOptions
        {
            Client = "options-client",
            Secret = "options-secret"
        });

        var innerHandler = new CaptureRequestHandler();
        using var handler = new HmacAuthenticationHttpHandler(options)
        {
            InnerHandler = innerHandler
        };

        using var httpClient = new System.Net.Http.HttpClient(handler);

        // Act
        using var response = await httpClient.GetAsync("https://api.example.com/options", TestContext.Current.CancellationToken);

        // Assert
        var request = Assert.Single(innerHandler.Requests);
        Assert.StartsWith("HMAC Client=options-client&", request.Headers.Authorization?.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_UsesCurrentOptionsForEachRequest()
    {
        // Arrange
        var optionsMonitor = new TestOptionsMonitor(new HmacAuthenticationOptions
        {
            Client = "initial-client",
            Secret = "initial-secret"
        });

        var innerHandler = new CaptureRequestHandler();
        using var handler = new HmacAuthenticationHttpHandler(optionsMonitor)
        {
            InnerHandler = innerHandler
        };

        using var httpClient = new System.Net.Http.HttpClient(handler);

        // Act
        using var firstResponse = await httpClient.GetAsync("https://api.example.com/first", TestContext.Current.CancellationToken);

        optionsMonitor.CurrentValue = new HmacAuthenticationOptions
        {
            Client = "updated-client",
            Secret = "updated-secret"
        };

        using var secondResponse = await httpClient.GetAsync("https://api.example.com/second", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(2, innerHandler.Requests.Count);
        Assert.StartsWith("HMAC Client=initial-client&", innerHandler.Requests[0].Headers.Authorization?.ToString(), StringComparison.Ordinal);
        Assert.StartsWith("HMAC Client=updated-client&", innerHandler.Requests[1].Headers.Authorization?.ToString(), StringComparison.Ordinal);
    }

    private sealed class CaptureRequestHandler : System.Net.Http.HttpMessageHandler
    {
        public List<System.Net.Http.HttpRequestMessage> Requests { get; } = [];

        protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(
            System.Net.Http.HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);

            return Task.FromResult(new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    private sealed class TestOptionsMonitor(HmacAuthenticationOptions currentValue) : IOptionsMonitor<HmacAuthenticationOptions>
    {
        public HmacAuthenticationOptions CurrentValue { get; set; } = currentValue;

        public HmacAuthenticationOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<HmacAuthenticationOptions, string?> listener) => null;
    }
}
