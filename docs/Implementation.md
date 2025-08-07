# HMAC Authentication Client Implementation Guide

This guide provides detailed instructions on how to implement HMAC authentication in client applications. HMAC (Hash-based Message Authentication Code) provides secure authentication for API communications by signing requests with a shared secret.

## Table of Contents

- [Overview](#overview)
- [Implementation Details](#implementation-details)
- [Authentication Flow](#authentication-flow)
- [Client Prerequisites](#client-prerequisites)
- [.NET Client Implementation](#net-client-implementation)
- [JavaScript/Node.js Client Implementation](#javascriptnodejs-client-implementation)
- [Configuration Options](#configuration-options)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

## Overview

HMAC Authentication provides HMAC-SHA256 authentication that ensures:

- **Request Integrity**: Signed requests cannot be tampered with
- **Authentication**: Only clients with valid credentials can access protected endpoints
- **Replay Protection**: Timestamp validation prevents request replay attacks
- **Cross-Platform Compatibility**: Works with .NET, JavaScript, and other platforms

### How It Works

1. **Client Credentials**: Each client has a unique identifier and secret key
2. **Request Signing**: Client calculates HMAC signature of request details
3. **Headers Added**: Authentication headers are added to the request
4. **Server Validation**: Server validates the signature using the shared secret

## Implementation Details

This section provides the essential constants, algorithms, and formats needed to implement HMAC authentication from scratch.

### Core Constants

```text
DEFAULT_SCHEME_NAME = "HMAC"
TIME_STAMP_HEADER_NAME = "x-timestamp"
CONTENT_HASH_HEADER_NAME = "x-content-sha256"
DEFAULT_SIGNED_HEADERS = ["host", "x-timestamp", "x-content-sha256"]
```

### Header Requirements

Every authenticated request MUST include these headers:

1. **Host**: The target host (including port if not standard)
2. **x-timestamp**: Unix timestamp in seconds
3. **x-content-sha256**: Base64-encoded SHA256 hash of request body
4. **Authorization**: HMAC authentication header

### String-to-Sign Format

The canonical string for signing follows this exact format and is critical for generating a valid HMAC signature. Any deviation from this format will result in authentication failures.

#### Format Structure

```text
{HTTP_METHOD_UPPERCASE}\n{PATH_WITH_QUERY}\n{SEMICOLON_SEPARATED_HEADER_VALUES}
```

#### Component Breakdown

1. **HTTP Method**: Must be uppercase (GET, POST, PUT, DELETE, etc.)
2. **Newline Character**: Literal `\n` (ASCII 10)
3. **Path with Query**: Full path including query string parameters
4. **Newline Character**: Literal `\n` (ASCII 10)
5. **Header Values**: Semicolon-separated values in exact order

#### Header Values Order

The header values must be in the exact order specified by the `SignedHeaders` parameter in the Authorization header. The order cannot be arbitrary - it must match the sequence defined in the SignedHeaders parameter.

**Default Order** (when using default signed headers):

1. **Host** (e.g., `api.example.com`)
2. **x-timestamp** (e.g., `1640995200`)
3. **x-content-sha256** (e.g., `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`)

**Custom Order Example**:
If SignedHeaders=`host;x-timestamp;x-content-sha256;content-type;user-agent`, then header values must be ordered as:

1. host value
2. x-timestamp value  
3. x-content-sha256 value
4. content-type value
5. user-agent value

**Important**: The semicolon-separated order in the Authorization header's SignedHeaders parameter determines the exact sequence that header values must appear in the string-to-sign construction.

#### Construction Rules

- **Case Sensitivity**: HTTP method must be uppercase
- **Path Encoding**: Use the exact path as it appears in the request URL
- **Query Parameters**: Include all query parameters in their original order

#### Examples

**GET Request with Query Parameters**:

```text
GET\n/api/users?page=1&limit=10\napi.example.com;1640995200;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

**POST Request with Body**:

```text
POST\n/api/users\napi.example.com;1640995201;jZKwqY8QqKqzQe7xJKwqY8QqKqzQe7xKwqY8QqKqzQe=
```

#### Implementation Tips

- Use UTF-8 encoding when converting the string to bytes for HMAC calculation
- Ensure consistent newline characters across platforms (use `\n`, not `\r\n`)
- Validate that semicolons in header values don't conflict with the separator
- Double-check the order of header values matches the signed headers list

### Authorization Header Format

The Authorization header contains the HMAC authentication information in a specific format that must be constructed precisely to ensure successful authentication.

#### Header Structure

```text
HMAC Client={CLIENT_ID}&SignedHeaders={HEADER_NAMES}&Signature={BASE64_SIGNATURE}
```

#### Component Details

1. **Scheme Name**: Always starts with `HMAC` (case-sensitive)
2. **Space Separator**: Single space character after scheme name
3. **Client Parameter**: `Client={CLIENT_ID}` - Your unique client identifier
4. **Ampersand Separator**: `&` character between parameters
5. **SignedHeaders Parameter**: `SignedHeaders={HEADER_NAMES}` - Semicolon-separated list of header names
6. **Signature Parameter**: `Signature={BASE64_SIGNATURE}` - Base64-encoded HMAC signature

#### Parameter Requirements

**Client ID**:

- Must match the client identifier configured on the server
- Case-sensitive string
- Should not contain special characters that require URL encoding
- Example: `demo-client`, `api-user-123`, `mobile-app-v2`

**SignedHeaders**:

- Semicolon-separated list of header names included in the signature
- Order must match the order used in string-to-sign construction
- Default: `host;x-timestamp;x-content-sha256`
- Example with custom headers: `host;x-timestamp;x-content-sha256;content-type;user-agent`

**Signature**:

- Base64-encoded HMAC-SHA256 signature
- Generated from the string-to-sign using the client's secret key
- Must not contain any whitespace or line breaks
- Example: `xyz789abc123def456ghi789jkl012mno345pqr678stu901vwx234yz=`

#### Construction Process

1. **Build Parameter String**: Combine client ID, signed headers, and signature
2. **URL Encoding**: Apply URL encoding to parameter values if they contain special characters
3. **Final Assembly**: Prepend with `HMAC` scheme name and space

#### Authorization Header Examples

**Basic Authorization Header**:

```text
HMAC Client=demo-client&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890=
```

**With Custom Headers**:

```text
HMAC Client=mobile-app&SignedHeaders=host;x-timestamp;x-content-sha256;content-type&Signature=xyz789abc123def456ghi789jkl012mno345pqr678stu901vwx234yz=
```

#### Header Validation Rules

- **No Extra Spaces**: Avoid spaces around `=` and `&` characters
- **Parameter Order**: Parameters can be in any order, but consistency is recommended
- **Case Sensitivity**: Scheme name and parameter names are case-sensitive
- **URL Encoding**: Apply URL encoding to parameter values containing special characters
- **Length Limits**: Most servers accept headers up to 8KB; keep signatures reasonable

#### Common Formatting Errors

**Incorrect Spacing**:

```text
// Wrong
HMAC  Client=demo&SignedHeaders=host&Signature=abc123
HMAC Client = demo & SignedHeaders = host & Signature = abc123

// Correct
HMAC Client=demo&SignedHeaders=host&Signature=abc123
```

**Wrong Case**:

```text
// Wrong
hmac Client=demo&signedheaders=host&signature=abc123
Hmac Client=demo&SignedHeaders=host&Signature=abc123

// Correct
HMAC Client=demo&SignedHeaders=host&Signature=abc123
```

**Missing Parameters**:

```text
// Wrong
HMAC Client=demo&Signature=abc123
HMAC SignedHeaders=host&Signature=abc123

// Correct
HMAC Client=demo&SignedHeaders=host&Signature=abc123
```

### Cryptographic Operations

1. **Content Hash**: SHA256 hash of UTF-8 encoded body, then Base64 encode
2. **Signature**: HMAC-SHA256 of string-to-sign using UTF-8 encoded secret, then Base64 encode

### Implementation Algorithm

```text
1. Extract host from request URL
2. Generate current Unix timestamp
3. Calculate SHA256 hash of request body (use EMPTY_CONTENT_HASH if no body)
4. Create header values array: [host, timestamp, content_hash]
5. Create string-to-sign: "METHOD\nPATH\nheader_values_joined_by_semicolon"
6. Generate HMAC-SHA256 signature of string-to-sign using secret key
7. Base64 encode the signature
8. Create authorization header with client ID, signed headers, and signature
9. Add all required headers to request
```

### Validation Rules

- **Timestamp**: Must be within server's time tolerance window (typically 5 minutes)
- **Content Hash**: Must match actual request body hash
- **Signature**: Must match server's calculated signature
- **Headers**: All signed headers must be present and match signed values

## Authentication Flow

### 1. Request Preparation

When making a request, the client:

1. **Generates Timestamp**: Current Unix timestamp for replay protection
2. **Calculates Content Hash**: SHA256 hash of request body (Base64 encoded)
3. **Creates String to Sign**: Canonical string containing method, path, and header values
4. **Generates Signature**: HMAC-SHA256 signature of the string to sign

### 2. Required Headers

Every authenticated request must include these headers:

| Request Header       | Description                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Host**             | Internet host and port number                                                                                      |
| **x-timestamp**      | Unix timestamp (seconds since epoch) when the request was created. Must be within 5 minutes of current server time |
| **x-content-sha256** | Base64-encoded SHA256 hash of the request body. Required even for requests with empty bodies                       |
| **Authorization**    | HMAC authentication information (see format details below)                                                         |

```http
Host: api.example.com
x-timestamp: 1640995200
x-content-sha256: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
Authorization: HMAC Client=your-client-id&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=abc123...
```

### 3. String to Sign Format

```javascript
const stringToSign = `${upperMethod}\n${pathAndQuery}\n${headerValues}`;
```

Example:

```text
GET
/api/users?page=1
api.example.com;1640995200;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

## Client Prerequisites

### For .NET Clients

- HashGate.HttpClient NuGet package
- Microsoft.Extensions.Http package (for HttpClient factory)

### For JavaScript/Node.js Clients

- Node.js 18.0.0 or higher
- Built-in `crypto` module
- `node-fetch` package (for Node.js environments)

## .NET Client Implementation

### 1. Installation

Install the HashGate.HttpClient NuGet package:

```bash
dotnet add package HashGate.HttpClient
```

### 2. Basic Setup

```csharp
using HashGate.HttpClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

// Register HMAC authentication services
builder.Services.AddHmacAuthentication();

// Configure HttpClient with HMAC authentication
builder.Services
    .AddHttpClient("SecureApiClient", client =>
    {
        client.BaseAddress = new Uri("https://api.example.com");
    })
    .AddHttpMessageHandler<HmacAuthenticationHttpHandler>();

var app = builder.Build();
```

### 3. Configuration

#### Using appsettings.json

```json
{
    "HmacAuthentication": {
        "Client": "your-client-id",
        "Secret": "your-secret-key"
    }
}
```

#### Programmatic Configuration

```csharp
builder.Services.AddHmacAuthentication(options =>
{
    options.Client = "your-client-id";
    options.Secret = "your-secret-key";
    options.SignedHeaders = new[] { "host", "x-timestamp", "x-content-sha256", "content-type" };
});
```

### 4. Making Authenticated Requests

```csharp
// Get the configured HttpClient
var httpClientFactory = app.Services.GetRequiredService<IHttpClientFactory>();
var httpClient = httpClientFactory.CreateClient("SecureApiClient");

// Make authenticated requests
var response = await httpClient.GetAsync("/api/users");
var users = await response.Content.ReadFromJsonAsync<List<User>>();

// POST request with JSON body
var newUser = new User { Name = "John Doe", Email = "john@example.com" };
var postResponse = await httpClient.PostAsJsonAsync("/api/users", newUser);
```

### 5. Advanced Configuration

```csharp
// Multiple HttpClients with different configurations
builder.Services.AddHmacAuthentication();

// Admin API client
builder.Services
    .AddHttpClient("AdminApiClient", client => client.BaseAddress = new Uri("https://admin.api.com"))
    .AddHttpMessageHandler<HmacAuthenticationHttpHandler>();

// Public API client (no authentication)
builder.Services
    .AddHttpClient("PublicApiClient", client => client.BaseAddress = new Uri("https://public.api.com"));

// User API client with custom headers
builder.Services.AddHmacAuthentication("UserApiAuth", options =>
{
    options.Client = "user-client";
    options.Secret = "user-secret";
    options.SignedHeaders = new[] { "host", "x-timestamp", "x-content-sha256", "user-agent" };
});
```

## JavaScript/Node.js Client Implementation

### 1. Core HMAC Client Class

```javascript
import crypto from "crypto";

export class HmacClient {
    constructor(client, secret, baseUrl = "https://api.example.com") {
        this.client = client;
        this.secret = secret;
        this.baseUrl = baseUrl.replace(/\/$/, "");

        // Constants matching .NET implementation
        this.DEFAULT_SCHEME_NAME = "HMAC";
        this.TIME_STAMP_HEADER_NAME = "x-timestamp";
        this.CONTENT_HASH_HEADER_NAME = "x-content-sha256";
        this.EMPTY_CONTENT_HASH =
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        this.DEFAULT_SIGNED_HEADERS = [
            "host",
            this.TIME_STAMP_HEADER_NAME,
            this.CONTENT_HASH_HEADER_NAME,
        ];
    }

    /**
     * Creates canonical string for signing
     */
    createStringToSign(method, pathAndQuery, headerValues) {
        const upperMethod = method.toUpperCase();
        const headerString = headerValues.join(";");
        return `${upperMethod}\n${pathAndQuery}\n${headerString}`;
    }

    /**
     * Generates HMAC-SHA256 signature
     */
    generateSignature(stringToSign) {
        const hmac = crypto.createHmac("sha256", this.secret);
        hmac.update(stringToSign, "utf8");
        return hmac.digest("base64");
    }

    /**
     * Calculates SHA256 hash of content
     */
    calculateContentHash(content) {
        if (!content) {
            return this.EMPTY_CONTENT_HASH;
        }
        const hash = crypto.createHash("sha256");
        hash.update(content, "utf8");
        return hash.digest("base64");
    }

    /**
     * Creates authenticated headers
     */
    createAuthenticatedHeaders(method, path, content = null) {
        const url = new URL(this.baseUrl + path);
        const host = url.host;
        const pathAndQuery = url.pathname + url.search;

        // Generate Unix timestamp
        const timestamp = Math.floor(Date.now() / 1000).toString();

        // Calculate content hash
        const contentHash = this.calculateContentHash(content);

        // Create header values in order
        const headerValues = [host, timestamp, contentHash];

        // Create string to sign and generate signature
        const stringToSign = this.createStringToSign(
            method,
            pathAndQuery,
            headerValues
        );
        const signature = this.generateSignature(stringToSign);

        // Generate authorization header
        const signedHeadersString = this.DEFAULT_SIGNED_HEADERS.join(";");
        const authorizationHeader = `${this.DEFAULT_SCHEME_NAME} Client=${this.client}&SignedHeaders=${signedHeadersString}&Signature=${signature}`;

        // Build headers
        const headers = {
            Host: host,
            [this.TIME_STAMP_HEADER_NAME]: timestamp,
            [this.CONTENT_HASH_HEADER_NAME]: contentHash,
            Authorization: authorizationHeader,
        };

        if (content) {
            headers["Content-Type"] = "application/json";
        }

        return headers;
    }

    /**
     * Makes authenticated HTTP request
     */
    async request(method, path, body = null) {
        const content = body ? JSON.stringify(body) : null;
        const headers = this.createAuthenticatedHeaders(method, path, content);

        const requestOptions = {
            method: method.toUpperCase(),
            headers,
        };

        if (content) {
            requestOptions.body = content;
        }

        const fetch = (await import("node-fetch")).default;
        return fetch(this.baseUrl + path, requestOptions);
    }

    // Convenience methods
    async get(path) {
        return this.request("GET", path);
    }
    async post(path, body) {
        return this.request("POST", path, body);
    }
    async put(path, body) {
        return this.request("PUT", path, body);
    }
    async delete(path) {
        return this.request("DELETE", path);
    }
}
```

### 2. Usage Examples

```javascript
// Create client instance
const client = new HmacClient(
    "your-client-id",
    "your-secret-key",
    "https://api.example.com"
);

// GET request
const response = await client.get("/api/users");
const users = await response.json();

// POST request
const newUser = { name: "John Doe", email: "john@example.com" };
const createResponse = await client.post("/api/users", newUser);
const createdUser = await createResponse.json();

// Error handling
try {
    const response = await client.get("/api/protected");
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const data = await response.json();
    console.log(data);
} catch (error) {
    console.error("Request failed:", error.message);
}
```

## Configuration Options

### Client Configuration Properties

| Property        | Type     | Required | Description                                                                     |
| --------------- | -------- | -------- | ------------------------------------------------------------------------------- |
| `Client`        | string   | Yes      | Unique client identifier                                                        |
| `Secret`        | string   | Yes      | Secret key for HMAC signing                                                     |
| `SignedHeaders` | string[] | No       | Headers included in signature (defaults to host, x-timestamp, x-content-sha256) |

### Default Signed Headers

- **host**: Target host header
- **x-timestamp**: Unix timestamp of request
- **x-content-sha256**: SHA256 hash of request body

### Custom Signed Headers

You can include additional headers in the signature for enhanced security:

```csharp
// .NET
options.SignedHeaders = new[] { "host", "x-timestamp", "x-content-sha256", "content-type", "user-agent" };
```

```javascript
// JavaScript
const signedHeaders = [
    "host",
    "x-timestamp",
    "x-content-sha256",
    "content-type",
];
```

## Security Considerations

### 1. Secret Management

- **Never hardcode secrets** in source code
- Use **environment variables** or **secure vaults** (Azure Key Vault, AWS Secrets Manager)
- **Rotate secrets** regularly
- Use different secrets for different environments

```csharp
// .NET - Use configuration
builder.Services.AddHmacAuthentication(options =>
{
    options.Client = Environment.GetEnvironmentVariable("HMAC_CLIENT_ID");
    options.Secret = Environment.GetEnvironmentVariable("HMAC_SECRET");
});
```

```javascript
// JavaScript - Use environment variables
const client = new HmacClient(
    process.env.HMAC_CLIENT_ID,
    process.env.HMAC_SECRET,
    process.env.API_BASE_URL
);
```

### 2. HTTPS Only

- **Always use HTTPS** for production
- HMAC provides integrity but not confidentiality
- Disable certificate validation only for development

### 3. Time Synchronization

- Keep client and server clocks synchronized
- Server validates timestamp to prevent replay attacks
- Default tolerance is usually 5 minutes

### 4. Request Replay Protection

- Each request includes a unique timestamp
- Server rejects requests with expired timestamps
- Consider implementing nonce for additional protection

## Troubleshooting

### Common Issues

#### 1. Authentication Failures

**Symptoms**: HTTP 401 Unauthorized responses

**Causes & Solutions**:

- **Incorrect credentials**: Verify client ID and secret match server configuration
- **Clock skew**: Ensure client and server clocks are synchronized
- **Wrong signature**: Check that signing algorithm matches server implementation

#### 2. Invalid Authorization Header

**Symptoms**: "Invalid Authorization header" error

**Solutions**:

- Ensure Authorization header format matches: `HMAC Client={clientId}&SignedHeaders={headerNames}&Signature={signature}`
- Verify no extra spaces or encoding issues
- Check that signed headers order matches

#### 3. Content Hash Mismatch

**Symptoms**: "Invalid content hash header" error

**Solutions**:

- Ensure body content is identical during hash calculation and transmission
- Use UTF-8 encoding consistently
- For empty body, use the empty content hash constant

#### 4. Timestamp Validation Errors

**Symptoms**: "Invalid timestamp header" error

**Solutions**:

- Use Unix timestamp (seconds since epoch)
- Synchronize system clocks
- Check server's timestamp tolerance settings

## Examples

### Complete .NET Console Application

```csharp
using HashGate.HttpClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text.Json;

var builder = Host.CreateApplicationBuilder(args);

// Configure HMAC authentication
builder.Services.AddHmacAuthentication(options =>
{
    options.Client = "demo-client";
    options.Secret = "demo-secret-key";
});

// Configure HttpClient
builder.Services
    .AddHttpClient("ApiClient", client => client.BaseAddress = new Uri("https://api.example.com"))
    .AddHttpMessageHandler<HmacAuthenticationHttpHandler>();

var app = builder.Build();

// Use the client
var httpClientFactory = app.Services.GetRequiredService<IHttpClientFactory>();
var httpClient = httpClientFactory.CreateClient("ApiClient");

try
{
    // GET request
    var response = await httpClient.GetAsync("/api/users");
    response.EnsureSuccessStatusCode();

    var json = await response.Content.ReadAsStringAsync();
    var users = JsonSerializer.Deserialize<List<object>>(json);

    Console.WriteLine($"Retrieved {users?.Count} users");
}
catch (HttpRequestException ex)
{
    Console.WriteLine($"Request failed: {ex.Message}");
}
```

### Complete JavaScript Application

```javascript
import { HmacClient } from "./hmac-client.js";

// Create client
const client = new HmacClient(
    "demo-client",
    "demo-secret-key",
    "https://api.example.com"
);

async function main() {
    try {
        // GET request
        const response = await client.get("/api/users");

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const users = await response.json();
        console.log(`Retrieved ${users.length} users`);

        // POST request
        const newUser = {
            name: "Jane Doe",
            email: "jane@example.com",
        };

        const createResponse = await client.post("/api/users", newUser);
        const createdUser = await createResponse.json();
        console.log("Created user:", createdUser);
    } catch (error) {
        console.error("Error:", error.message);
    }
}

main();
```

### Environment Configuration

**.env file**:

```env
HMAC_CLIENT_ID=your-client-id
HMAC_SECRET=your-secret-key
API_BASE_URL=https://api.example.com
```

**appsettings.json**:

```json
{
    "HmacAuthentication": {
        "Client": "your-client-id",
        "Secret": "your-secret-key"
    },
    "ApiSettings": {
        "BaseUrl": "https://api.example.com"
    }
}
```

This comprehensive guide provides detailed instructions for implementing HMAC authentication across multiple programming languages and deployment scenarios. 
