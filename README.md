# HashGate

A HMAC (Hash-based Message Authentication Code) authentication system for ASP.NET Core applications. This library provides both server-side authentication and client-side HTTP handlers for secure API communication.

[![Build Project](https://github.com/loresoft/HashGate/actions/workflows/dotnet.yml/badge.svg)](https://github.com/loresoft/HashGate/actions/workflows/dotnet.yml)
[![License](https://img.shields.io/github/license/loresoft/HashGate.svg)](https://github.com/loresoft/HashGate/blob/main/LICENSE)
[![Coverage Status](https://coveralls.io/repos/github/loresoft/HashGate/badge.svg?branch=main)](https://coveralls.io/github/loresoft/HashGate?branch=main)

| Package                                                                    | Version                                                                                                                 | Description                                                   |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [HashGate.AspNetCore](https://www.nuget.org/packages/HashGate.AspNetCore/) | [![NuGet](https://img.shields.io/nuget/v/HashGate.AspNetCore.svg)](https://www.nuget.org/packages/HashGate.AspNetCore/) | Server-side HMAC authentication for ASP.NET Core applications |
| [HashGate.HttpClient](https://www.nuget.org/packages/HashGate.HttpClient/) | [![NuGet](https://img.shields.io/nuget/v/HashGate.HttpClient.svg)](https://www.nuget.org/packages/HashGate.HttpClient/) | Client-side HTTP message handler for HMAC authentication      |

## Features

- **Secure HMAC-SHA256 authentication** with timestamp validation
- **Easy integration** with ASP.NET Core authentication system
- **Client library included** for .NET HttpClient integration
- **Request replay protection** with configurable time windows and optional signature replay cache
- **Nonce support** for guaranteed per-request signature uniqueness
- **Highly configurable** key providers and validation options
- **OpenTelemetry diagnostics** with ActivitySource traces and Meter metrics

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

**Using .NET CLI:**

```bash
dotnet add package HashGate.AspNetCore
```

**Using PowerShell:**

```powershell
Install-Package HashGate.AspNetCore
```

### Client Package (.NET HttpClient)

**Using .NET CLI:**

```bash
dotnet add package HashGate.HttpClient
```

**Using PowerShell:**

```powershell
Install-Package HashGate.HttpClient
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

| Request Header       | Description                                                                                                                                                                                                                                                                      |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Host**             | Internet host and port number                                                                                                                                                                                                                                                    |
| **x-timestamp**      | Unix timestamp (seconds since epoch) when the request was created. Must be within 5 minutes of current server time                                                                                                                                                               |
| **x-content-sha256** | Base64-encoded SHA256 hash of the request body. Required even for requests with empty bodies                                                                                                                                                                                     |
| **x-nonce**          | Unique per-request value (GUID). Included by default in signed headers and auto-generated by the .NET client. Not server-enforced, but strongly recommended — without it, identical requests within the same second are rejected when replay protection is enabled (the default) |
| **Authorization**    | HMAC authentication information (see format details below)                                                                                                                                                                                                                       |

### Example Request

```http
GET /api/users?page=1 HTTP/1.1
Host: api.example.com
x-timestamp: 1722776096
x-nonce: a3f1c2d4e5b64a7f8c9d0e1f2a3b4c5d
x-content-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
Authorization: HMAC Client=123456789&SignedHeaders=host;x-timestamp;x-content-sha256;x-nonce&Signature=AbCdEf123456...
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

The following headers **must** always be included in `SignedHeaders`. The server enforces their presence and will reject requests that omit them:

- `host`
- `x-timestamp` — required for replay protection; cryptographically binds the timestamp to the signature
- `x-content-sha256` — required for body integrity; cryptographically binds the content hash to the signature

#### Optional Headers

You can include additional headers beyond the required set for enhanced security:

```text
host;x-timestamp;x-content-sha256;x-nonce;content-type;accept
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
    "api.example.com;1722776096;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;a3f1c2d4e5b64a7f8c9d0e1f2a3b4c5d"  // header values
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

### Replay Protection

HashGate provides two layers of replay protection:

**Layer 1 — Timestamp window (always active):** The server rejects any request whose `x-timestamp` falls outside `ToleranceWindow` minutes of server time (default: 5 minutes).

**Layer 2 — Signature replay cache (enabled by default):** `EnableReplayProtection` is `true` by default. The server records each validated signature and immediately rejects any duplicate that arrives within its validity window — even within the same second. To opt out, set `EnableReplayProtection = false`.

```csharp
// Server — replay protection is enabled by default
builder.Services
    .AddAuthentication()
    .AddHmacAuthentication();

// To disable replay protection:
// .AddHmacAuthentication(options => options.EnableReplayProtection = false);
```

> **Important — nonce:** The timestamp has only one-second resolution, so two identical requests sent within the same second produce the same signature and the second would be falsely rejected. Every request automatically includes a unique `x-nonce` header, making each signature cryptographically unique.

```csharp
// Client — x-nonce is always included automatically
services.AddHmacAuthentication(options =>
{
    options.Client = "MyClientId";
    options.Secret = "my-secret-key";
});
```

**Multi-server / distributed deployments:** The default `DefaultHmacReplayProtection` is backed by `HybridCache` (in-process L1). Register a distributed cache (e.g. Redis) alongside it; `HybridCache` will automatically promote it to the L2 backing store — no custom code required.

```csharp
// Add Redis as the distributed backing store for replay protection
builder.Services.AddStackExchangeRedisCache(options =>
    options.Configuration = builder.Configuration.GetConnectionString("Redis"));

builder.Services
    .AddAuthentication()
    .AddHmacAuthentication();
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
    options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256", "x-nonce", "content-type"];
});
```

## Advanced Usage

### OpenTelemetry Diagnostics

`HashGate.AspNetCore` emits OpenTelemetry-compatible traces and metrics through `System.Diagnostics`.

| Signal          | Name                  |
| --------------- | --------------------- |
| Activity source | `HashGate.AspNetCore` |
| Meter           | `HashGate.AspNetCore` |

Authentication activities are emitted as `HashGate.Authenticate` for requests that include an HMAC `Authorization` header. Requests without an authorization header, or requests using another authentication scheme such as `Bearer`, return no authentication result and do not emit a HashGate authentication activity.

```csharp
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddAspNetCoreInstrumentation()
        .AddSource("HashGate.AspNetCore"))
    .WithMetrics(metrics => metrics
        .AddAspNetCoreInstrumentation()
        .AddMeter("HashGate.AspNetCore"));
```

#### Activities

| Activity                | Description                                  |
| ----------------------- | -------------------------------------------- |
| `HashGate.Authenticate` | HMAC authentication validation for a request |

Common activity tags:

| Tag                                    | Description                                                                                                                                                                                             |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hashgate.auth.scheme`                 | Authentication scheme name                                                                                                                                                                              |
| `hashgate.auth.result`                 | `success` or `failure`                                                                                                                                                                                  |
| `hashgate.auth.failure_reason`         | Failure reason, such as `invalid_signature`, `invalid_timestamp`, `invalid_content_hash`, `missing_required_signed_headers`, `too_many_signed_headers`, `replayed_signature`, or `authentication_error` |
| `hashgate.replay_protection.enabled`   | Whether replay protection is enabled for the scheme                                                                                                                                                     |
| `hashgate.replay_protection.result`    | Replay protection outcome: `new`, `replay`, or `not_configured`                                                                                                                                         |
| `hashgate.hmac.client`                 | HMAC client identifier from the request                                                                                                                                                                 |
| `hashgate.hmac.signed_headers.count`   | Number of headers included in the signature                                                                                                                                                             |
| `hashgate.rate_limit.policy`           | Resolved HashGate rate limit policy name                                                                                                                                                                |
| `hashgate.rate_limit.client`           | Client or remote IP used for the rate limit partition                                                                                                                                                   |
| `hashgate.rate_limit.endpoint`         | Endpoint key used for rate limiting                                                                                                                                                                     |
| `hashgate.rate_limit.partition_source` | `hmac_client` or `remote_ip`                                                                                                                                                                            |
| `hashgate.rate_limit.rejected`         | `true` when the request was rejected by rate limiting                                                                                                                                                   |
| `hashgate.rate_limit.retry_after_ms`   | Retry delay in milliseconds for rejected requests                                                                                                                                                       |

Authentication activities also add `hashgate.content_hash.validated` when the request body hash is valid and `hashgate.content_hash.failed` when body hash validation fails. Failed authentication activities are marked with `ActivityStatusCode.Error`.

#### Metrics

| Metric                                | Type      | Unit          | Description                                                                       |
| ------------------------------------- | --------- | ------------- | --------------------------------------------------------------------------------- |
| `hashgate.auth.requests`              | Counter   | `{request}`   | Number of HMAC authentication attempts                                            |
| `hashgate.auth.failures`              | Counter   | `{failure}`   | Number of failed HMAC authentication attempts                                     |
| `hashgate.auth.duration`              | Histogram | `ms`          | Duration of HMAC authentication attempts                                          |
| `hashgate.replay_protection.checks`   | Counter   | `{check}`     | Number of HMAC replay protection checks                                           |
| `hashgate.replay_protection.replays`  | Counter   | `{replay}`    | Number of rejected replayed HMAC signatures                                       |
| `hashgate.endpoint.requests`          | Counter   | `{request}`   | Number of rate-limited endpoint requests resolved by HashGate                     |
| `hashgate.rate_limit.rejections`      | Counter   | `{rejection}` | Number of requests rejected by HashGate rate limiting                             |
| `hashgate.rate_limit.provider.lookup` | Counter   | `{lookup}`    | Number of per-client rate limit provider lookups                                  |
| `hashgate.rate_limit.provider.miss`   | Counter   | `{miss}`      | Number of per-client rate limit provider lookups that fell back to default limits |

Authentication metrics include `hashgate.auth.scheme`, `hashgate.auth.result`, and, for failures, `hashgate.auth.failure_reason`. Replay protection metrics include `hashgate.replay_protection.result`. Rate limit metrics include `hashgate.rate_limit.policy`; endpoint request metrics also include `hashgate.hmac.client`; provider lookup metrics also include `hashgate.rate_limit.provider_found`.

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

    public async ValueTask<ClaimsIdentity> GenerateClaimsAsync(string client, string? scheme = null, CancellationToken cancellationToken = default)
    {
        var identity = new ClaimsIdentity(scheme);
        identity.AddClaim(new Claim(ClaimTypes.Name, client));

        // Add additional claims based on your requirements
        var model = await _keyRepository.GetClientAsync(client, cancellationToken);
        if (model != null)
        {
            identity.AddClaim(new Claim("display_name", model.DisplayName));
            // Add role claims, permissions, etc. as needed
        }

        return identity;
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

### Sample.Bruno

[Bruno](https://www.usebruno.com/) API collection demonstrating HMAC authentication:

- **Location**: `samples/Sample.Bruno/`
- **Features**: Pre-request HMAC authentication script, public and authenticated endpoints, environment configuration
- **Requirements**: Bruno in Developer Mode for Node.js module support
- **Usage**: Import the collection into Bruno and test endpoints

### Sample.JavaScript

JavaScript/Node.js client implementation:

- **Location**: `samples/Sample.JavaScript/`
- **Features**: Browser and Node.js compatible, TypeScript definitions
- **Run**: `npm install && npm start`

### Sample.Python

Python client implementation:

- **Location**: `samples/Sample.Python/`
- **Features**: Easy-to-use client class, demo script, interactive testing tool, unit tests
- **Requirements**: Python 3, dependencies in `requirements.txt`
- **Run**: `pip install -r requirements.txt && python demo.py`

### Sample.Java

Java client implementation using the built-in `java.net.http.HttpClient`:

- **Location**: `samples/Sample.Java/`
- **Features**: HMAC client class, demo and example apps, unit tests, no external HTTP dependencies
- **Requirements**: Java 25+, Maven 3.9+
- **Run**: `mvn compile && mvn exec:java`

## Security Considerations

- **Always use HTTPS** in production environments
- **Protect HMAC secret keys** - never expose them in client-side code
- **Always include required signed headers** - `host`, `x-timestamp`, and `x-content-sha256` must be in `SignedHeaders` (the server enforces this). Including `x-nonce` (the default) is strongly recommended when replay protection is enabled
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

4. **"Replayed signature" errors when `EnableReplayProtection` is enabled**:
    - Every request automatically includes a unique `x-nonce` header, ensuring every signature is unique

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Migration Guide: v2.x → v3.x

### Migration Overview

Version 3 introduces **nonce support** to guarantee per-request signature uniqueness. The `x-nonce` header is now included in the default signed headers.

> **Note:** The `x-nonce` header is **not required** by the server. However, without it, two identical requests sent within the same second produce the same signature. Because `EnableReplayProtection` is enabled by default, the second request will be rejected with a **401 Unauthorized** response because the signature was already recorded. Including `x-nonce` is strongly recommended to avoid this.

### What Changed

| Area                       | v2.x                                                              | v3.x                                                                              |
| -------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Default signed headers** | `host;x-timestamp;x-content-sha256`                               | `host;x-timestamp;x-content-sha256;x-nonce`                                       |
| **`x-nonce` header**       | Not present                                                       | Optional but included by default; automatically generated (GUID) on every request |
| **Replay protection**      | Identical requests in the same second produced the same signature | Each request has a cryptographically unique signature via nonce                   |

### .NET Client (`HashGate.HttpClient`)

If you are using the **default signed headers**, no code changes are required. The client automatically generates and includes `x-nonce` on every request.

If you have **custom `SignedHeaders`** configured, add `x-nonce` to the list:

```diff
 services.AddHmacAuthentication(options =>
 {
     options.Client = "MyClientId";
     options.Secret = "my-secret-key";
-    options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256", "content-type"];
+    options.SignedHeaders = ["host", "x-timestamp", "x-content-sha256", "x-nonce", "content-type"];
 });
```

### .NET Server (`HashGate.AspNetCore`)

Update the NuGet package to v3.x. The server automatically recognizes `x-nonce` in the `SignedHeaders` list. No configuration changes are needed unless you have custom header validation logic.

### Non-.NET Clients

All non-.NET clients should be updated to include `x-nonce`. While the server does not require it, omitting the nonce means identical requests within the same second will share the same signature and be rejected with **401** because `EnableReplayProtection` is enabled by default.

1. **Generate a unique nonce** (GUID/UUID) for each request
2. **Set the `x-nonce` header** on the request
3. **Add `x-nonce` to the `SignedHeaders` list** in the `Authorization` header so the nonce value is included in the string-to-sign and the resulting signature

## References

This implementation is inspired by:

- [Azure HMAC Authentication](https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac)
- [AWS Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
