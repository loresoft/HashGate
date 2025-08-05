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

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/", () => "Hello World!");

        app.MapGet("/weather", () => WeatherFaker.Instance.Generate(5))
            .WithName("GetWeather")
            .WithOpenApi();

        app.MapPost("/weather", (Weather weather) => Results.Ok(weather))
            .WithName("PostWeather")
            .WithOpenApi();

        app.MapGet("/users", () => UserFaker.Instance.Generate(10))
            .WithName("GetUsers")
            .WithOpenApi()
            .RequireAuthorization();

        app.MapPost("/users", (User user) => Results.Ok(user))
            .WithName("PostUser")
            .WithOpenApi()
            .RequireAuthorization();

        app.MapGet("/addresses", () => AddressFaker.Instance.Generate(10))
            .WithName("GetAddresses")
            .WithOpenApi()
            .RequireAuthorization();

        app.MapPost("/addresses", (Address address) => Results.Ok(address))
            .WithName("PostAddress")
            .WithOpenApi()
            .RequireAuthorization();

        app.MapGet("/current", (ClaimsPrincipal? principal) => new { principal?.Identity?.Name })
            .RequireAuthorization();

        app.MapOpenApi();
        app.MapScalarApiReference();

        app.Run();
    }
}
