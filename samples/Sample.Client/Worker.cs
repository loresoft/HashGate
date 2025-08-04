using System.Net.Http.Json;

using Microsoft.Extensions.Hosting;

using Sample.Shared;

namespace Sample.Client;

public class Worker : BackgroundService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly Dictionary<string, Command> _commandMap;

    public Worker(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
        _commandMap = new Dictionary<string, Command>
        {
            ["0"] = new("0", "Hello World [GET /]", HelloCommand),
            ["1"] = new("1", "Get Weather [GET /weather]", WeatherCommand),
            ["2"] = new("2", "Get Users [GET /users]", UsersCommand),
            ["3"] = new("3", "Post User [POST /users]", PostUserCommand),
            ["4"] = new("4", "Get Addresses [GET /addresses]", AddressesCommand),
            ["5"] = new("5", "Post Address [POST /addresses]", PostAddressCommand),
        };
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Test HTTP Client");

            foreach (var cmd in _commandMap.Values)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write($"  {cmd.Key} ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(cmd.Description);
            }

            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write($"  Q ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Quit");

            Console.ResetColor();

            var line = Console.ReadLine();
            await RunCommand(line);
        }
    }


    private async Task RunCommand(string? line)
    {
        try
        {
            if (line != null && _commandMap.TryGetValue(line, out var command))
            {
                await command.Action();
            }
            else if (line == "Q" || line == "q")
            {
                QuitCommand();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Unknown Command '{line}'");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine("Error: " + ex.Message);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Error.WriteLine(ex.ToString());

            Console.ResetColor();
        }
    }

    private async Task HelloCommand()
    {
        var httpClient = _httpClientFactory.CreateClient("HmacClient");
        var result = await httpClient.GetAsync("/");

        await OutputReseponse(result);
    }

    private async Task WeatherCommand()
    {
        var httpClient = _httpClientFactory.CreateClient("HmacClient");
        var result = await httpClient.GetAsync("weather");

        await OutputReseponse(result);
    }

    private async Task UsersCommand()
    {
        var httpClient = _httpClientFactory.CreateClient("HmacClient");
        var result = await httpClient.GetAsync("users");

        await OutputReseponse(result);
    }

    private async Task PostUserCommand()
    {
        var user = UserFaker.Instance.Generate();
        var httpClient = _httpClientFactory.CreateClient("HmacClient");

        var result = await httpClient.PostAsJsonAsync("users", user);

        await OutputReseponse(result);
    }

    private async Task AddressesCommand()
    {
        var httpClient = _httpClientFactory.CreateClient("HmacClient");
        var result = await httpClient.GetAsync("addresses");

        await OutputReseponse(result);
    }

    private async Task PostAddressCommand()
    {
        var address = AddressFaker.Instance.Generate();
        var httpClient = _httpClientFactory.CreateClient("HmacClient");
        var result = await httpClient.PostAsJsonAsync("addresses", address);

        await OutputReseponse(result);
    }

    private void QuitCommand()
    {
        Console.WriteLine("Exiting...");
        Environment.Exit(0);
    }


    private static async Task OutputReseponse(HttpResponseMessage response)
    {
        var request = response.RequestMessage;

        // Request Section
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("=== HTTP Request ===");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"{request?.Method} {request?.RequestUri}");

        if (request?.Headers != null)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            foreach (var header in request.Headers)
                Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
        }

        if (request?.Content != null)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            foreach (var header in request.Content.Headers)
                Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");

            var requestBody = await request.Content.ReadAsStringAsync();
            if (!string.IsNullOrWhiteSpace(requestBody))
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(requestBody);
            }
        }

        // Response Section
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine();
        Console.WriteLine("=== HTTP Response ===");

        // Status coloring
        if ((int)response.StatusCode >= 200 && (int)response.StatusCode < 300)
            Console.ForegroundColor = ConsoleColor.Green;
        else if ((int)response.StatusCode >= 400)
            Console.ForegroundColor = ConsoleColor.Red;
        else
            Console.ForegroundColor = ConsoleColor.Yellow;

        Console.WriteLine($"Status: {(int)response.StatusCode} {response.StatusCode}");

        Console.ForegroundColor = ConsoleColor.DarkGray;
        foreach (var header in response.Headers)
            Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");

        if (response.Content != null)
        {
            foreach (var header in response.Content.Headers)
                Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");

            var responseBody = await response.Content.ReadAsStringAsync();
            if (!string.IsNullOrWhiteSpace(responseBody))
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(responseBody);
            }
        }

        Console.ResetColor();
        Console.WriteLine();
    }
}

public record struct Command(string Key, string Description, Func<Task> Action);
