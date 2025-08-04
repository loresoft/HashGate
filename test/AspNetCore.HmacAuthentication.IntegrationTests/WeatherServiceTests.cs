using AspNetCore.HmacAuthentication.IntegrationService;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AspNetCore.HmacAuthentication.IntegrationTests;

public class WeatherServiceTests : BaseIntegrationTest
{
    public WeatherServiceTests(WebApplicationFactory<Program> factory) : base(factory)
    {
    }

    [Fact]
    public void Test1()
    {
        var service = Factory.Services.GetService<WeatherForecast[]>();
        var client = Factory.CreateDefaultClient()

        var response = client.GetAsync("/hello").Result;

    }
}


public class BaseIntegrationTest : IClassFixture<WebApplicationFactory<Program>>
{
    public BaseIntegrationTest(WebApplicationFactory<Program> factory)
    {
        Factory = factory;
        HttpClient = factory.CreateClient();
    }

    public WebApplicationFactory<Program> Factory { get; }

    public HttpClient HttpClient { get; }
}
