package hashgate.sample;

import java.net.http.HttpResponse;

/**
 * Simple demonstration of HMAC authentication client.
 * <p>
 * Prerequisites:
 * 1. Build: mvn compile
 * 2. Start the Sample.MinimalApi project:
 *    cd samples/Sample.MinimalApi && dotnet run
 * 3. Run this demo: mvn exec:java -Dexec.mainClass="hashgate.sample.Demo"
 */
public class Demo {

    public static void main(String[] args) {
        System.out.println("HMAC Authentication Demo\n");

        // Create HMAC client with sample configuration
        HmacClient client = new HmacClient(
                "SampleClient",
                "ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",
                "https://localhost:7134"
        );

        try {
            System.out.println("1. Testing public endpoint (Hello World)...");
            HttpResponse<String> helloResponse = client.get("/");
            System.out.println("   Status: " + helloResponse.statusCode());
            System.out.println("   Response: " + helloResponse.body() + "\n");

            System.out.println("2. Testing public endpoint (Weather data)...");
            HttpResponse<String> weatherResponse = client.get("/weather");
            System.out.println("   Status: " + weatherResponse.statusCode());
            if (weatherResponse.statusCode() == 200) {
                System.out.println("   Response: " + weatherResponse.body() + "\n");
            } else {
                System.out.println("   Error: " + weatherResponse.body() + "\n");
            }

            System.out.println("3. Testing authenticated endpoint (Users)...");
            HttpResponse<String> usersResponse = client.get("/users");
            if (usersResponse.statusCode() == 200) {
                System.out.println("   Status: " + usersResponse.statusCode() + " (Authentication successful!)");
                System.out.println("   Response: " + usersResponse.body() + "\n");
            } else {
                System.out.println("   Status: " + usersResponse.statusCode() + " (Authentication failed)");
                System.out.println("   Error: " + usersResponse.body() + "\n");
            }

            System.out.println("4. Testing authenticated POST endpoint (Create User)...");
            String newUser = """
                    {"first":"Demo","last":"User","email":"demo.user@example.com"}""";
            HttpResponse<String> createUserResponse = client.post("/users", newUser);
            if (createUserResponse.statusCode() == 200) {
                System.out.println("   Status: " + createUserResponse.statusCode() + " (Authentication successful!)");
                System.out.println("   Created user: " + createUserResponse.body() + "\n");
            } else {
                System.out.println("   Status: " + createUserResponse.statusCode() + " (Authentication failed)");
                System.out.println("   Error: " + createUserResponse.body() + "\n");
            }

            System.out.println("5. Testing authenticated endpoint (Addresses)...");
            HttpResponse<String> addressesResponse = client.get("/addresses");
            if (addressesResponse.statusCode() == 200) {
                System.out.println("   Status: " + addressesResponse.statusCode() + " (Authentication successful!)");
                System.out.println("   Response: " + addressesResponse.body() + "\n");
            } else {
                System.out.println("   Status: " + addressesResponse.statusCode() + " (Authentication failed)");
                System.out.println("   Error: " + addressesResponse.body() + "\n");
            }

        } catch (Exception e) {
            System.out.println("Demo failed: " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("Connection refused")) {
                System.out.println("\nMake sure the Sample.MinimalApi is running:");
                System.out.println("   cd samples/Sample.MinimalApi");
                System.out.println("   dotnet run");
            }
        }

        System.out.println("Demo completed!");
    }
}
