# Java HMAC Client Sample

This sample demonstrates how to use HMAC authentication with Java to make authenticated requests to APIs protected by HashGate.AspNetCore.

## Features

- **HMAC Authentication**: Implements the same authentication scheme as HashGate.AspNetCore
- **Simple API**: Easy-to-use client class with convenience methods for GET, POST, PUT, DELETE
- **Demo Script**: Complete demonstration of authentication workflow
- **Test Suite**: Unit tests for client functionality
- **No External HTTP Dependencies**: Uses Java's built-in `java.net.http.HttpClient` (Java 11+)

## Requirements

- Java 25 or later
- Maven 3.9 or later

## Building

```bash
mvn compile
```

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
```

This will test various endpoints including:

- Public endpoints (Hello World, Weather data)
- Authenticated endpoints (Users, Addresses)
- POST operations with authentication

### Running the Example

A simpler example showing basic usage:

```bash
```

### Running Tests

Run the unit test suite:

```bash
mvn test
```

## Basic Usage Example

```java
import hashgate.sample.HmacClient;
import java.net.http.HttpResponse;

// Create client
HmacClient client = new HmacClient(
    "SampleClient",
    "ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",
    "https://localhost:7134"
);

// Make authenticated GET request
HttpResponse<String> response = client.get("/users");
if (response.statusCode() == 200) {
    System.out.println("Users: " + response.body());
}

// Make authenticated POST request
String newUser = """
    {"first":"John","last":"Doe","email":"john.doe@example.com"}""";
HttpResponse<String> createResponse = client.post("/users", newUser);
if (createResponse.statusCode() == 200) {
    System.out.println("Created user: " + createResponse.body());
}
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
- **baseUrl**: Base URL of the target API

## Files

- `src/main/java/hashgate/sample/HmacClient.java`: Main HMAC client implementation
- `src/main/java/hashgate/sample/Demo.java`: Demonstration script showing authentication workflow
- `src/main/java/hashgate/sample/Example.java`: Simple example showing basic usage
- `src/test/java/hashgate/sample/HmacClientTest.java`: Unit test suite
- `pom.xml`: Maven build configuration
- `README.md`: This documentation
