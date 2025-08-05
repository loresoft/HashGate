using HashGate.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Sample.Shared;
using WebApplication = Microsoft.AspNetCore.Builder.WebApplication;

namespace HashGate.Integration.Tests;

/// <summary>
/// Test web application for integration testing HMAC authentication
/// </summary>
public class TestWebApplication
{
    public static WebApplication CreateApp()
    {
        var builder = WebApplication.CreateBuilder();

        // Configure authentication with HMAC
        builder.Services
            .AddAuthentication()
            .AddHmacAuthentication();

        builder.Services.AddAuthorization();
        builder.Services.AddControllers();

        // Configure HMAC secrets for testing
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["HmacSecrets:TestClient"] = "test-secret-key-12345",
            ["HmacSecrets:InvalidClient"] = "invalid-secret-key"
        });

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        // Configure test endpoints
        app.MapGet("/", () => Results.Ok("Hello World"));

        app.MapGet("/public", () => Results.Ok(new { message = "Public endpoint", timestamp = DateTime.UtcNow }));

        app.MapGet("/protected", [Authorize] () => Results.Ok(new { message = "Protected endpoint", timestamp = DateTime.UtcNow }));

        app.MapGet("/weather", () => Results.Ok(WeatherFaker.Instance.Generate(3)));

        app.MapPost("/weather", ([FromBody] Weather weather) => Results.Ok(weather));

        app.MapGet("/users", [Authorize] () => Results.Ok(UserFaker.Instance.Generate(2)));

        app.MapPost("/users", [Authorize] ([FromBody] User user) => Results.Ok(user));

        app.MapGet("/auth-info", [Authorize] (HttpContext context) =>
        {
            var user = context.User;
            return Results.Ok(new
            {
                IsAuthenticated = user.Identity?.IsAuthenticated ?? false,
                AuthenticationType = user.Identity?.AuthenticationType,
                Name = user.Identity?.Name,
                Claims = user.Claims.Select(c => new { c.Type, c.Value }).ToArray()
            });
        });

        return app;
    }
}
