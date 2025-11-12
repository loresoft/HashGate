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
            .WithName("GetWeather");

        app.MapPost("/weather", (Weather weather) => Results.Ok(weather))
            .WithName("PostWeather");

        app.MapGet("/users", () => UserFaker.Instance.Generate(10))
            .WithName("GetUsers")
            .RequireAuthorization();

        app.MapPost("/users", (User user) => Results.Ok(user))
            .WithName("PostUser")
            .RequireAuthorization();

        app.MapGet("/addresses", () => AddressFaker.Instance.Generate(10))
            .WithName("GetAddresses")
            .RequireAuthorization();

        app.MapPost("/addresses", (Address address) => Results.Ok(address))
            .WithName("PostAddress")
            .RequireAuthorization();

        app.MapGet("/current", (ClaimsPrincipal? principal) => new { principal?.Identity?.Name })
            .RequireAuthorization();

        app.MapOpenApi();
        app.MapScalarApiReference();

        app.Run();
    }
}
