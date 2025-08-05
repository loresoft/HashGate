# HashGate

A HMAC (Hash-based Message Authentication Code) authentication system for ASP.NET Core applications. This library provides both server-side authentication middleware and client-side HTTP handlers for secure API communication.

[![Build Project](https://github.com/loresoft/HashGate/actions/workflows/dotnet.yml/badge.svg)](https://github.com/loresoft/HashGate/actions/workflows/dotnet.yml)

[![Coverage Status](https://coveralls.io/repos/github/loresoft/HashGate/badge.svg?branch=main)](https://coveralls.io/github/loresoft/HashGate?branch=main)

[![HashGate.AspNetCore](https://img.shields.io/nuget/v/HashGate.svg)](https://www.nuget.org/packages/HashGate/)

## Features

- **Secure HMAC-SHA256 authentication** with timestamp validation
- **Easy integration** with ASP.NET Core authentication system
- **Client library included** for .NET HttpClient integration
- **Cross-platform** compatible (.NET 8.0 and .NET 9.0)
- **Request replay protection** with configurable time windows
- **Highly configurable** key providers and validation options

## Overview

This library implements HMAC authentication similar to AWS Signature Version 4 and Azure HMAC Authentication. All HTTP requests must be transmitted over TLS and include cryptographic signatures to ensure request integrity and authenticity.

## Why HMAC Authentication

HMAC authentication is particularly well-suited for server-to-server communication and microservices architectures for following reasons:

### **Enhanced Security**

- **No credentials in transit**: Unlike bearer tokens, HMAC signatures are computed from request data, meaning the actual secret never travels over the network
- **Request integrity**: Each request is cryptographically signed, ensuring the payload hasn't been tampered with during transmission
- **Replay attack protection**: Built-in timestamp validation prevents malicious replaying of captured requests

### **Microservices Architecture Benefits**

- **Stateless authentication**: No need for centralized token stores or session management across services
- **Service-to-service isolation**: Each service can have unique HMAC keys, limiting blast radius if one service is compromised
- **Zero-dependency authentication**: No reliance on external identity providers or token validation services

### **Operational Advantages**

- **High performance**: HMAC computation is fast and doesn't require network calls to validate authenticity
- **Reduced infrastructure**: No need for token refresh endpoints, session stores, or identity service dependencies
- **Deterministic debugging**: Failed requests can be reproduced locally since signatures are deterministic

### **Implementation Flexibility**

- **Language agnostic**: HMAC-SHA256 is supported by virtually every programming language and platform
- **Framework independent**: Works with any HTTP client/server combination, not tied to specific OAuth flows
- **Custom key management**: Full control over key rotation, storage, and distribution strategies

### **Scalability & Reliability**

- **No single point of failure**: Authentication doesn't depend on external services being available
- **Linear scaling**: Authentication overhead doesn't increase with the number of services or requests
- **Offline capability**: Services can authenticate requests even when disconnected from identity providers

### Use Cases Where HMAC Excels

- **Internal API gateways** communicating with backend services
- **Microservice mesh** where services need to authenticate each other
- **Webhook validation** from external systems
- **Background job services** accessing protected APIs
- **IoT device communication** where OAuth flows are impractical

## Installation

Install the NuGet packages for your server and client projects:

### Server Package (ASP.NET Core)

```bash
dotnet add package HashGate.AspNetCore
```

### Client Package (.NET HttpClient)

```bash
dotnet add package HashGate.HttpClient
```

## Quick Start

### Server Setup (ASP.NET Core)

```csharp
using HashGate.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add HMAC authentication
builder.Services
    .AddAuthentication()
    .AddHmacAuthentication();

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Your protected endpoints
app.MapGet("/api/secure", () => "Hello, authenticated user!")
    .RequireAuthorization();

app.Run();
```

**appsettings.json** (Server):

```json
{
  "HmacSecrets": {
    "MyClientId": "your-secret-key-here",
    "AnotherClient": "another-secret-key"
  }
}
```

### Client Setup (.NET HttpClient)

```csharp
using HashGate.HttpClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

// Add HMAC authentication services
builder.Services.AddHmacAuthentication();

// Configure HttpClient with HMAC authentication
builder.Services
    .AddHttpClient("SecureApi", client => client.BaseAddress = new Uri("https://api.example.com"))
    .AddHttpMessageHandler<HmacAuthenticationHttpHandler>();

var app = builder.Build();

// Get the HttpClient and make authenticated requests
var httpClientFactory = app.Services.GetRequiredService<IHttpClientFactory>();
var httpClient = httpClientFactory.CreateClient("SecureApi");
var response = await httpClient.GetAsync("/api/secure");
```

**appsettings.json** (Client):

```json
{
  "HmacAuthentication": {
    "Client": "MyClientId",
    "Secret": "your-secret-key-here"
  }
}
```

## Authentication Details

### Prerequisites

Each client must have:

- **Client** - A unique identifier for the access key used to compute the signature
- **Secret** - The secret key used for HMAC-SHA256 signature generation

### Required HTTP Headers

Every authenticated request must include these headers:

| Request Header       | Description                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Host**             | Internet host and port number                                                                                      |
| **x-timestamp**      | Unix timestamp (seconds since epoch) when the request was created. Must be within 5 minutes of current server time |
| **x-content-sha256** | Base64-encoded SHA256 hash of the request body. Required even for requests with empty bodies                       |
| **Authorization**    | HMAC authentication information (see format details below)                                                         |

### Example Request

```http
GET /api/users?page=1 HTTP/1.1
Host: api.example.com
x-timestamp: 1722776096
x-content-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
Authorization: HMAC Client=123456789&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=AbCdEf123456...
```

## Authorization Header Format

### Syntax

```text
Authorization: HMAC Client=<value>&SignedHeaders=<value>&Signature=<value>
```

| Parameter         | Description                                                           | Required |
| ----------------- | --------------------------------------------------------------------- | -------- |
| **HMAC**          | Authorization scheme identifier                                       | Yes      |
| **Client**        | The client identifier of the access key used to compute the signature | Yes      |
| **SignedHeaders** | Semicolon-separated list of HTTP headers included in the signature    | Yes      |
| **Signature**     | Base64-encoded HMACSHA256 hash of the String-To-Sign                  | Yes      |

### Client

The unique identifier for the access key used to compute the signature. This allows the server to identify which HMAC secret key to use for signature verification.

### Signed Headers

Semicolon-separated list of HTTP header names that were included in the signature calculation. These headers must be present in the request with the exact values used during signing.

#### Required Headers

The following headers must always be included:

- `host`
- `x-timestamp`
- `x-content-sha256`

#### Optional Headers

You can include additional headers for enhanced security:

```text
host;x-timestamp;x-content-sha256;content-type;accept
```

### Signature Generation

The signature is a Base64-encoded HMACSHA256 hash of the String-To-Sign using the client's secret key:

```text
Signature = base64_encode(HMACSHA256(String-To-Sign, Secret))
```

### String-To-Sign Format

The String-To-Sign is a canonical representation of the request constructed as follows:

```text
String-To-Sign = HTTP_METHOD + '\n' + path_and_query + '\n' + signed_headers_values
```

#### Components

| Component                 | Description                                                                               |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| **HTTP_METHOD**           | Uppercase HTTP method name (GET, POST, PUT, DELETE, etc.)                                 |
| **path_and_query**        | The request path and query string (e.g., `/api/users?page=1`)                             |
| **signed_headers_values** | Semicolon-separated list of header values in the same order as specified in SignedHeaders |

#### Example

For a GET request to `/kv?fields=*&api-version=1.0`:

```javascript
String-To-Sign =
    "GET" + '\n' +                                                             // HTTP method
    "/kv?fields=*&api-version=1.0" + '\n' +                                    // path and query
    "api.example.com;1722776096;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="  // header values
```

## Configuration Options

### Server Configuration

```csharp
// Basic configuration with default settings
builder.Services
    .AddAuthentication()
    .AddHmacAuthentication();

// Configuration with custom options
builder.Services
    .AddAuthentication()
    .AddHmacAuthentication(options =>
    {
        options.ToleranceWindow = 10; // 10 minutes timestamp tolerance
        options.SecretSectionName = "MyHmacSecrets"; // Custom config section
    });
```

### Client Configuration

```csharp
// Basic configuration using appsettings.json
services.AddHmacAuthentication();

// Configuration with custom options
services.AddHmacAuthentication(options =>
{
    options.Client = "MyClientId";
    options.Secret = "my-secret-key";
    options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256", "content-type"];
});
```

## Advanced Usage

### Custom Key Provider

Implement `IHmacKeyProvider` to load keys from your preferred storage:

```csharp
public class DatabaseKeyProvider : IHmacKeyProvider
{
    private readonly IKeyRepository _keyRepository;

    public DatabaseKeyProvider(IKeyRepository keyRepository)
    {
        _keyRepository = keyRepository;
    }

    public async ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default)
    {
        var key = await _keyRepository.GetKeyAsync(client, cancellationToken);
        return key?.Secret;
    }
}

// Register in DI container with custom key provider
builder.Services
    .AddAuthentication()
    .AddHmacAuthentication<DatabaseKeyProvider>();

// Or register the key provider separately if needed
builder.Services.AddScoped<IHmacKeyProvider, DatabaseKeyProvider>();

builder.Services.AddScoped<IKeyRepository, KeyRepository>();
```

## Samples and Examples

The repository includes comprehensive sample implementations:

### Sample.MinimalApi

ASP.NET Core minimal API demonstrating server-side HMAC authentication:

- **Location**: `samples/Sample.MinimalApi/`
- **Features**: Protected endpoints, OpenAPI integration, custom key provider
- **Run**: `dotnet run --project samples/Sample.MinimalApi`

### Sample.Client

.NET client implementation using HttpClient with HMAC authentication:

- **Location**: `samples/Sample.Client/`
- **Features**: Automatic signature generation, HttpClient integration, background service
- **Run**: `dotnet run --project samples/Sample.Client`

### Sample.JavaScript

JavaScript/Node.js client implementation:

- **Location**: `samples/Sample.JavaScript/`
- **Features**: Browser and Node.js compatible, TypeScript definitions
- **Run**: `npm install && npm start`

## Security Considerations

- **Always use HTTPS** in production environments
- **Protect HMAC secret keys** - never expose them in client-side code
- **Monitor timestamp tolerance** - shorter windows provide better security
- **Rotate keys regularly** - implement key rotation policies
- **Log authentication failures** - monitor for potential attacks
- **Validate all inputs** - especially timestamp and signature formats

## Troubleshooting

### Common Issues

1. **"Invalid signature" errors**:

    - Verify client and server are using the same secret key
    - Check that all required headers are included and properly formatted
    - Ensure timestamp is within the allowed window

2. **"Timestamp validation failed"**:

    - Synchronize client and server clocks
    - Adjust `ToleranceWindow` if needed

3. **"Missing required headers"**:
    - Ensure `host`, `x-timestamp`, and `x-content-sha256` headers are present

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

This implementation is inspired by:

- [Azure HMAC Authentication](https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac)
- [AWS Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
