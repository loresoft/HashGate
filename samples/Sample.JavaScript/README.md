# JavaScript HMAC Authentication Sample Client

This sample demonstrates how to implement HMAC authentication in JavaScript/Node.js for communicating with an ASP.NET Core API using the `HashGate.AspNetCore` library.

## Prerequisites

- Node.js 18.0.0 or higher
- The Sample.MinimalApi project running on `https://localhost:7134`

## Installation

1. Navigate to the JavaScript sample directory:

   ```bash
   cd samples/Sample.JavaScript
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

## Configuration

The client is configured to work with the default sample settings:

- **Client ID**: `SampleClient`
- **Secret**: `sample-client-secret`
- **Base URL**: `https://localhost:7134`

These settings match the configuration in the ASP.NET Core `Sample.MinimalApi` project.

## Running the Sample

### Start the API Server

First, make sure the Sample.MinimalApi is running:

```bash
cd samples/Sample.MinimalApi
dotnet run
```

### Start the JavaScript Client

```bash
npm start
```

Or for development with auto-restart:

```bash
npm run dev
```

Or for a quick demonstration:

```bash
npm run demo
```

Or to run the tests:

```bash
npm test
```

## Features

The sample client provides an interactive console menu with the following commands:

- **0** - Hello World [GET /] - Public endpoint
- **1** - Get Weather [GET /weather] - Public endpoint
- **2** - Get Users [GET /users] - Requires HMAC authentication
- **3** - Post User [POST /users] - Requires HMAC authentication
- **4** - Get Addresses [GET /addresses] - Requires HMAC authentication
- **5** - Post Address [POST /addresses] - Requires HMAC authentication
- **Q** - Quit

## HMAC Authentication Implementation

The `HmacClient` class in `hmac-client.js` implements the HMAC authentication protocol that matches the .NET implementation:

### Key Components

1. **String to Sign Creation**: Creates a canonical string from HTTP method, path, and signed headers
2. **Signature Generation**: Uses HMAC-SHA256 to sign the canonical string
3. **Authorization Header**: Formats the signature into the required authorization header format
4. **Content Hashing**: Calculates SHA256 hash of request body content

### Signed Headers

By default, the following headers are included in the signature:

- `host` - The target host
- `x-timestamp` - ISO 8601 timestamp of the request
- `x-content-sha256` - SHA256 hash of the request body (base64 encoded)

### Authorization Header Format

```text
HMAC Client={clientId}&SignedHeaders={signedHeaders}&Signature={signature}
```

Example:

```text
HMAC Client=SampleClient&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=abc123...
```

## Code Structure

- `hmac-client.js` - Core HMAC authentication client implementation
- `index.js` - Interactive console application demonstrating usage
- `package.json` - Node.js project configuration

## Security Notes

- The sample disables TLS certificate validation for development (`NODE_TLS_REJECT_UNAUTHORIZED=0`)
- In production, ensure proper TLS certificate validation
- Store secrets securely (environment variables, key vaults, etc.)
- Consider implementing request replay protection with timestamp validation

## Examples

### Simple GET Request

```javascript
import { HmacClient } from './hmac-client.js';

const client = new HmacClient('SampleClient', 'sample-client-secret');
const response = await client.get('/users');
const data = await response.json();
console.log(data);
```

### POST Request with Body

```javascript
const user = { firstName: 'John', lastName: 'Doe' };
const response = await client.post('/users', user);
const result = await response.json();
console.log(result);
```

## Troubleshooting

1. **Certificate Errors**: The sample automatically disables TLS validation for localhost
2. **Authentication Failures**: Verify the client ID and secret match the server configuration
3. **Time Sync Issues**: Ensure system clocks are synchronized (HMAC uses timestamps)
4. **CORS Issues**: The API should have CORS configured if running from browser

## Related

- [Sample.Client](../Sample.Client/) - .NET client implementation
- [Sample.MinimalApi](../Sample.MinimalApi/) - ASP.NET Core API server
- [HashGate.AspNetCore](../../src/HashGate.AspNetCore/) - Core authentication library
