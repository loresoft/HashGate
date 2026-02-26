using System.Security.Claims;

using HashGate.AspNetCore;

using Sample.Shared;

using Scalar.AspNetCore;

namespace Sample.MinimalApi;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services
            .AddAuthentication()
            .AddHmacAuthentication();

        builder.Services.AddAuthorization();

        builder.Services.AddOpenApi();
        builder.Services.AddEndpointsApiExplorer();

        builder.Services.AddHmacRateLimiter(configure: options =>
        {
            options.RequestsPerPeriod = 10;
            options.BurstFactor = 1;
        });

        var application = builder.Build();

        application.UseHttpsRedirection();

        application.UseRateLimiter();

        application.UseAuthentication();
        application.UseAuthorization();

        application
            .MapGet("/", () => "Hello World!");

        application
            .MapGet("/weather", () => WeatherFaker.Instance.Generate(5))
            .WithName("GetWeather")
            .RequireHmacRateLimiting();

        application
            .MapPost("/weather", (Weather weather) => Results.Ok(weather))
            .WithName("PostWeather");

        application
            .MapGet("/users", () => UserFaker.Instance.Generate(10))
            .WithName("GetUsers")
            .RequireAuthorization()
            .RequireHmacRateLimiting();

        application
            .MapPost("/users", (User user) => Results.Ok(user))
            .WithName("PostUser")
            .RequireAuthorization()
            .RequireHmacRateLimiting();

        application
            .MapGet("/addresses", () => AddressFaker.Instance.Generate(10))
            .WithName("GetAddresses")
            .RequireAuthorization()
            .RequireHmacRateLimiting();

        application
            .MapPost("/addresses", (Address address) => Results.Ok(address))
            .WithName("PostAddress")
            .RequireAuthorization()
            .RequireHmacRateLimiting();

        application
            .MapGet("/current", (ClaimsPrincipal? principal) => new { principal?.Identity?.Name })
            .RequireAuthorization();

        application.MapOpenApi();
        application.MapScalarApiReference();

        application.Run();
    }
}
