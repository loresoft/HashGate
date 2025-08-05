# HashGate Bruno Collection

This [Bruno](https://www.usebruno.com/) collection demonstrates how to use HMAC authentication with the HashGate library. It provides a complete set of API requests that showcase both public endpoints (no authentication required) and authenticated endpoints (HMAC authentication required).

## Prerequisites

### Bruno Setup

- **[Bruno](https://www.usebruno.com/) must be running in Developer Mode** to use this collection
- The pre-request script requires Node.js modules (`crypto-js` and `url`) which are only available in developer mode

To enable developer mode in Bruno:

1. Open Bruno
2. Go to Settings/Preferences
3. Enable "Developer Mode" or "Use Node.js runtime"

### Sample Server

This collection is designed to work with a HashGate-enabled API server. You can use the included samples:

- `Sample.MinimalApi` - A minimal API server with HashGate authentication
- Any ASP.NET Core application configured with HashGate

## Quick Start

1. **Enable Bruno Developer Mode** (see Prerequisites above)

2. **Start your API server**

    ```bash
    # Navigate to the Sample.MinimalApi directory
    cd ../Sample.MinimalApi

    # Run the API server
    dotnet run
    ```

3. **Import the collection** into Bruno

    - Open Bruno
    - Import this folder as a collection

4. **Configure environment variables**

    - The `Local` environment is pre-configured with default values
    - Modify `environments/Local.bru` if your server runs on different settings

5. **Test the endpoints**
    - Start with Public Endpoints (no authentication required)
    - Then try Authenticated Endpoints (automatic HMAC authentication)

## Collection Structure

```text
Sample.Bruno/
├── README.md                  # This file
├── collection.bru             # Pre-request script with HMAC authentication
├── bruno.json                 # Bruno collection configuration
├── environments/
│   └── Local.bru              # Local development environment variables
├── Public Endpoints/          # Endpoints that don't require authentication
│   ├── Hello World.bru        # Simple GET request
│   ├── Get Weather.bru        # GET request with response
│   └── Post Weather.bru       # POST request with body
└── Authenticated Endpoints/   # Endpoints that require HMAC authentication
    ├── Get Users.bru          # GET authenticated request
    ├── Post User.bru          # POST authenticated request
    ├── Get Addresses.bru      # GET authenticated request
    └── Post Address.bru       # POST authenticated request
```

## HMAC Authentication Script

The collection includes an automatic HMAC authentication system via a pre-request script located in `collection.bru`. This script runs before every request and automatically generates the required HMAC authentication headers.

### Finding the Script

To view or modify the pre-request script:

1. Open the collection in Bruno
2. Look for the "Collection Settings" or "Pre-request Script" section
3. The script is also available in the `collection.bru` file in this directory

### Script Reference

Here's the complete pre-request script used for HMAC authentication:

```javascript
const CryptoJS = require('crypto-js');
const { URL } = require('url');

// Get collection variables
const client = bru.getEnvVar('client');
const secret = bru.getEnvVar('secret');

// Get request details
const method = req.method;
const url = new URL(bru.interpolate(req.url));
const host = url.host;
const pathAndQuery = url.pathname + url.search;

// Generate timestamp
const timestamp = Math.floor(Date.now() / 1000).toString();

// Prepare body and calculate content hash
let body = bru.interpolate(req.body || '');
if (typeof body === 'object') {
  body = JSON.stringify(body);
}
const contentHash = CryptoJS.SHA256(body).toString(CryptoJS.enc.Base64);

// Create signed headers and string to sign
const headerValues = `${host};${timestamp};${contentHash}`;
const stringToSign = `${method}\n${pathAndQuery}\n${headerValues}`;

// Generate signature
const signature = CryptoJS.HmacSHA256(stringToSign, secret).toString(CryptoJS.enc.Base64);

// Construct Authorization header
const signedHeader = 'host;x-timestamp;x-content-sha256';
const authorization = `HMAC Client=${client}&SignedHeaders=${signedHeader}&Signature=${signature}`;

// Set headers
req.setHeader('Host', host);
req.setHeader('x-timestamp', timestamp);
req.setHeader('x-content-sha256', contentHash);
req.setHeader('Authorization', authorization);

// Set formatted body
req.setBody(body);
```

### How the Script Works

1. **Environment Variables**: Retrieves `client` and `secret` from Bruno environment
2. **Request Analysis**: Extracts method, URL components, and body
3. **Timestamp Generation**: Creates Unix timestamp for replay protection
4. **Content Hashing**: Generates SHA256 hash of request body
5. **String Construction**: Builds canonical string for signing
6. **HMAC Signature**: Creates HMAC-SHA256 signature using secret
7. **Header Injection**: Automatically adds all required authentication headers

The script ensures that every request includes proper HMAC authentication headers without any manual intervention.

## Configuration

### Environment Variables

The collection uses the following environment variables (configured in `environments/Local.bru`):

| Variable  | Default Value            | Description                               |
| --------- | ------------------------ | ----------------------------------------- |
| `baseUrl` | `https://localhost:7134` | Base URL of your API server               |
| `client`  | `SampleClient`           | Client identifier for HMAC authentication |
| `secret`  | `sample-client-secret`   | Secret key for HMAC signature generation  |

### Modifying Configuration

To use with your own API server:

1. Edit `environments/Local.bru`
2. Update the `baseUrl` to match your server
3. Set the correct `client` and `secret` values for your HashGate configuration

## Testing Endpoints

### Public Endpoints

These endpoints don't require authentication and can be used to verify your server is running:

- **Hello World**: Simple GET request returning a greeting
- **Get Weather**: GET request returning weather data
- **Post Weather**: POST request with JSON body

### Authenticated Endpoints

These endpoints require HMAC authentication (handled automatically by the pre-request script):

- **Get Users**: Retrieve list of users
- **Post User**: Create a new user
- **Get Addresses**: Retrieve list of addresses
- **Post Address**: Create a new address

## Troubleshooting

### Common Issues

1. **"crypto-js is not defined" error**

    - Ensure Bruno is running in Developer Mode
    - Restart Bruno after enabling Developer Mode

2. **Authentication failures**

    - Verify the `client` and `secret` values match your server configuration
    - Check that your server is running and accessible at the `baseUrl`
    - Ensure your server has HashGate properly configured

3. **Connection errors**
    - Verify the `baseUrl` in your environment configuration
    - Check that your API server is running
    - Ensure there are no firewall or network connectivity issues

### Debug Tips

- Check the Bruno console for detailed error messages
- Verify the generated headers in the request preview
- Use the Public Endpoints first to ensure basic connectivity
- Compare the generated Authorization header format with server expectations
