using Microsoft.AspNetCore.Authorization;

namespace AspNetCore.HmacAuthentication.IntegrationService;

public class Program
{
    private static readonly string[] _summaries = ["Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"];

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services
            .AddAuthentication(HmacAuthenticationShared.DefaultSchemeName)
            .AddHmacAuthentication();

        builder.Services.AddAuthorization();

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet(
            pattern: "/hello",
            handler: () => "Hello World!"
        );

        app.MapGet(
            pattern: "/weather",
            handler: [Authorize] () =>
            {
                return Enumerable
                    .Range(1, 5)
                    .Select(index =>
                        new WeatherForecast(
                            Date: DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                            Temperature: Random.Shared.Next(-20, 55),
                            Summary: _summaries[Random.Shared.Next(_summaries.Length)]
                        )
                    )
                    .ToArray();
            }
        );

        app.Run();
    }
}

public record WeatherForecast(DateOnly Date, int Temperature, string? Summary);
