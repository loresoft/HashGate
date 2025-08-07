"""
Simple example showing basic HMAC client usage
"""

from hmac_client import HmacClient


def main():
    print("Basic HMAC Client Example")

    # Create client with your configuration
    client = HmacClient(
        client="SampleClient",              # Your client ID
        secret="ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",      # Your secret key
        base_url="https://localhost:7134"   # API base URL
    )

    try:
        # Test public endpoint
        print("\n1. Testing public endpoint...")
        response = client.get("/")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")

        # Test authenticated endpoint
        print("\n2. Testing authenticated endpoint...")
        response = client.get("/users")
        if response.status_code == 200:
            users = response.json()
            print(f"Success! Found {len(users)} users")
        else:
            print(f"Failed with status: {response.status_code}")
            print(f"Error: {response.text}")

        # Test authenticated POST
        print("\n3. Testing authenticated POST...")
        new_user = {
            "first": "Example",
            "last": "User",
            "email": "example@test.com"
        }

        response = client.post("/users", new_user)
        if response.status_code == 200:
            created = response.json()
            print(f"Success! Created user: {created.get('firstName')} {created.get('lastName')}")
        else:
            print(f"Failed with status: {response.status_code}")
            print(f"Error: {response.text}")

    except Exception as e:
        print(f"Error: {e}")
        print("\nMake sure the Sample.MinimalApi is running:")
        print("  cd ../Sample.MinimalApi && dotnet run")


if __name__ == "__main__":
    main()
