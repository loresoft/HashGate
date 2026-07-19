using Microsoft.Extensions.Options;

namespace HashGate.HttpClient.Tests;

public class HmacAuthenticationHttpHandlerTests
{
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
        using var firstResponse = await httpClient.GetAsync("https://api.example.com/first");

        optionsMonitor.CurrentValue = new HmacAuthenticationOptions
        {
            Client = "updated-client",
            Secret = "updated-secret"
        };

        using var secondResponse = await httpClient.GetAsync("https://api.example.com/second");

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
