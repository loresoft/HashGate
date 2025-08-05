# HashGate Integration Tests

This project contains comprehensive integration tests for the HashGate HMAC authentication libraries, specifically testing the interaction between `HashGate.AspNetCore` and `HashGate.HttpClient`.

## Overview

The integration tests verify that:
- HMAC authentication works correctly between client and server
- Protected endpoints require proper authentication
- Public endpoints remain accessible
- Different HTTP methods work with HMAC authentication
- Multiple clients with different secrets can authenticate
- Error scenarios are handled properly
- Performance remains acceptable under load

## Test Structure

### Core Test Classes

#### `HashGateIntegrationTests`
Main integration test class that tests:
- Public endpoint access (with and without authentication)
- Protected endpoint access control
- CRUD operations with HMAC authentication
- Multiple sequential and concurrent requests
- Different HTTP methods (GET, POST, etc.)

#### `HmacSignatureTests`
Tests focused on HMAC signature validation:
- Missing or malformed headers
- Invalid signatures
- Expired timestamps
- Non-existent clients
- Signature generation validation

#### `ConfigurationTests`
Tests for different configuration scenarios:
- Multiple clients with different secrets
- Configuration via options pattern
- Parameter validation
- Wrong credentials handling

#### `PerformanceTests`
Performance and load testing:
- High-volume sequential requests
- Concurrent request handling
- Mixed workload scenarios
- Large payload handling
- Authentication performance consistency

### Test Infrastructure

#### `TestWebApplication`
A minimal test web application that provides:
- Public endpoints (no authentication required)
- Protected endpoints (HMAC authentication required)
- CRUD operations for testing different HTTP methods
- Authentication information endpoint for verification

## Configuration

The tests use in-memory configuration with predefined client secrets:
- `TestClient`: `test-secret-key-12345`
- `Client1`: `secret1`
- `Client2`: `secret2`
- `AdminClient`: `admin-secret`
- `PerfTestClient`: `performance-test-secret-key`

## Running the Tests

### Prerequisites
- .NET 9.0 SDK
- Visual Studio 2022 or JetBrains Rider (optional)

### Command Line
```bash
# Run all integration tests
dotnet test HashGate.Integration.Tests.csproj

# Run specific test class
dotnet test --filter "ClassName=HashGateIntegrationTests"

# Run with verbose output
dotnet test --logger "console;verbosity=detailed"

# Generate coverage report
dotnet test --collect:"XPlat Code Coverage"
```

### Visual Studio
1. Open the solution in Visual Studio
2. Build the solution
3. Open Test Explorer (Test → Test Explorer)
4. Run all tests or select specific tests

## Test Scenarios Covered

### Authentication Scenarios
- ✅ Valid HMAC authentication
- ✅ Invalid/missing credentials
- ✅ Expired timestamps
- ✅ Wrong client secrets
- ✅ Malformed headers
- ✅ Missing required headers

### Endpoint Testing
- ✅ Public endpoints (accessible without auth)
- ✅ Protected endpoints (require auth)
- ✅ GET operations
- ✅ POST operations with body
- ✅ Different content types

### Client Configuration
- ✅ Multiple clients with unique secrets
- ✅ Configuration via dependency injection
- ✅ Options pattern configuration
- ✅ Parameter validation

### Performance Testing
- ✅ Sequential request performance
- ✅ Concurrent request handling
- ✅ Mixed workload scenarios
- ✅ Large payload handling
- ✅ Authentication overhead measurement

### Error Handling
- ✅ Network failures
- ✅ Server errors
- ✅ Authentication failures
- ✅ Configuration errors

## Expected Test Results

All tests should pass, demonstrating:
1. Seamless integration between AspNetCore and HttpClient libraries
2. Proper HMAC signature generation and validation
3. Secure authentication flow
4. Good performance characteristics
5. Robust error handling

## Troubleshooting

### Common Issues

**Tests failing with 401 Unauthorized**
- Check that client secrets match between server and client configuration
- Verify that timestamps are not expired
- Ensure all required headers are present

**Performance tests timing out**
- Check system resources
- Verify network connectivity
- Review test timeouts in configuration

**Build errors**
- Ensure all required NuGet packages are installed
- Verify .NET 9.0 SDK is installed
- Check project references are correct

### Debugging
1. Enable verbose logging in test output
2. Use debugger to step through authentication flow
3. Check HTTP headers in failing requests
4. Verify HMAC signature generation

## Contributing

When adding new integration tests:
1. Follow the existing naming conventions
2. Include both positive and negative test cases
3. Add appropriate documentation
4. Ensure tests are deterministic and reliable
5. Clean up resources in test disposal methods

## Dependencies

- `xunit` - Testing framework
- `Microsoft.AspNetCore.Mvc.Testing` - ASP.NET Core test host
- `HashGate.AspNetCore` - Server-side HMAC authentication
- `HashGate.HttpClient` - Client-side HMAC authentication
- `Sample.Shared` - Shared models for testing
