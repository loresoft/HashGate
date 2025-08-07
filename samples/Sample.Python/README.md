# Python HMAC Client Sample

This sample demonstrates how to use HMAC authentication with Python to make authenticated requests to APIs protected by HashGate.AspNetCore.

## Features

- **HMAC Authentication**: Implements the same authentication scheme as HashGate.AspNetCore
- **Simple API**: Easy-to-use client class with convenience methods for GET, POST, PUT, DELETE
- **Demo Script**: Complete demonstration of authentication workflow
- **Interactive Tool**: Menu-driven interface for testing API endpoints
- **Test Suite**: Unit tests for client functionality

## Installation

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

1. Verify your setup:

```bash
python setup.py
```

This will check your Python version, verify dependencies, and test basic functionality.

## Usage

### Prerequisites

Before running the samples, make sure the Sample.MinimalApi is running:

```bash
cd ../Sample.MinimalApi
dotnet run
```

The API will be available at `https://localhost:7134`.

### Running the Demo

Run the demonstration script to see the HMAC authentication in action:

```bash
python demo.py
```

This will test various endpoints including:

- Public endpoints (Hello World, Weather data)
- Authenticated endpoints (Users, Addresses)
- POST operations with authentication

### Interactive Testing

For manual testing and exploration, use the interactive tool:

```bash
python interactive.py
```

This provides a menu-driven interface where you can:

- Test individual endpoints
- Create custom requests
- See detailed response information

### Running Tests

Run the unit test suite:

```bash
python test.py
```

## Basic Usage Example

```python
from hmac_client import HmacClient

# Create client
client = HmacClient(
    client="SampleClient",
    secret="ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",
    base_url="https://localhost:7134"
)

# Make authenticated GET request
response = client.get("/users")
if response.status_code == 200:
    users = response.json()
    print(f"Found {len(users)} users")

# Make authenticated POST request
new_user = {
    "first": "John",
    "last": "Doe", 
    "email": "john.doe@example.com"
}
response = client.post("/users", new_user)
if response.status_code == 200:
    created_user = response.json()
    print(f"Created user: {created_user}")
```

## How It Works

The `HmacClient` class implements the HMAC authentication scheme compatible with HashGate.AspNetCore:

1. **Timestamp Generation**: Creates a Unix timestamp for request timing
2. **Content Hashing**: Calculates SHA256 hash of request body (if any)
3. **String to Sign**: Creates canonical string from method, path, and header values
4. **HMAC Signature**: Generates HMAC-SHA256 signature using the secret key
5. **Authorization Header**: Formats the signature into proper authorization header

### Authentication Headers

Each authenticated request includes:

- `Host`: The target host
- `x-timestamp`: Unix timestamp when request was created
- `x-content-sha256`: SHA256 hash of request body (base64 encoded)
- `Authorization`: HMAC signature with client ID and signed headers

## Configuration

The client can be configured with:

- **client**: Client identifier (must match server configuration)
- **secret**: Secret key for HMAC signing (must match server configuration)
- **base_url**: Base URL of the target API

For development with localhost, SSL verification is automatically disabled.

## Files

- `hmac_client.py`: Main HMAC client implementation
- `demo.py`: Demonstration script showing authentication workflow
- `example.py`: Simple example showing basic usage
- `interactive.py`: Interactive testing tool with menu interface
- `test.py`: Unit test suite
- `setup.py`: Setup verification script
- `requirements.txt`: Python dependencies
- `README.md`: This documentation

## Error Handling

The client includes error handling for:

- Network connectivity issues
- SSL certificate problems (automatically handled for localhost)
- Invalid JSON responses
- Authentication failures

Common errors and solutions:

- **Connection Refused**: Make sure the Sample.MinimalApi is running
- **SSL Errors**: Client automatically disables SSL verification for localhost
- **Authentication Failed**: Verify client ID and secret match server configuration
