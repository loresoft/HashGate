using HashGate.HttpClient;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Sample.Client;

internal static class Program
{
    static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddHmacClient("HmacClient");
        builder.Services.AddHostedService<Worker>();

        var app = builder.Build();

        await app.RunAsync();
    }
}
