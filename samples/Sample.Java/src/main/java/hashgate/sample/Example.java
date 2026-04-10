package hashgate.sample;

import java.net.http.HttpResponse;

/**
 * Simple example showing basic HMAC client usage.
 */
public class Example {

    public static void main(String[] args) {
        System.out.println("Basic HMAC Client Example");

        // Create client with your configuration
        HmacClient client = new HmacClient(
                "SampleClient",
                "ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",
                "https://localhost:7134"
        );

        try {
            // Test public endpoint
            System.out.println("\n1. Testing public endpoint...");
            HttpResponse<String> response = client.get("/");
            System.out.println("Status: " + response.statusCode());
            System.out.println("Response: " + response.body());

            // Test authenticated endpoint
            System.out.println("\n2. Testing authenticated endpoint...");
            response = client.get("/users");
            if (response.statusCode() == 200) {
                System.out.println("Success! Response: " + response.body());
            } else {
                System.out.println("Failed with status: " + response.statusCode());
                System.out.println("Error: " + response.body());
            }

            // Test authenticated POST
            System.out.println("\n3. Testing authenticated POST...");
            String newUser = """
                    {"first":"Example","last":"User","email":"example@test.com"}""";
            response = client.post("/users", newUser);
            if (response.statusCode() == 200) {
                System.out.println("Success! Created user: " + response.body());
            } else {
                System.out.println("Failed with status: " + response.statusCode());
                System.out.println("Error: " + response.body());
            }

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            System.out.println("\nMake sure the Sample.MinimalApi is running:");
            System.out.println("  cd ../Sample.MinimalApi && dotnet run");
        }
    }
}
