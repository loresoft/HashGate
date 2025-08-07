"""
Simple demonstration of HMAC authentication client
This example shows how to make authenticated requests to the Sample.MinimalApi

Prerequisites:
1. Install dependencies: pip install -r requirements.txt
2. Start the Sample.MinimalApi project:
   cd samples/Sample.MinimalApi && dotnet run
3. Run this demo: python demo.py
"""

from hmac_client import HmacClient
import json


def demonstrate_hmac_authentication():
    print("HMAC Authentication Demo\n")

    # Create HMAC client with sample configuration
    client = HmacClient(
        client="SampleClient",              # Client ID (matches server config)
        secret="ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",      # Secret key (matches server config)
        base_url="https://localhost:7134"   # API base URL
    )

    try:
        print("1. Testing public endpoint (Hello World)...")
        hello_response = client.get("/")
        print(f"   Status: {hello_response.status_code}")
        print(f"   Response: {hello_response.text}\n")

        print("2. Testing public endpoint (Weather data)...")
        weather_response = client.get("/weather")
        print(f"   Status: {weather_response.status_code}")
        if weather_response.status_code == 200:
            weather_data = weather_response.json()
            print(f"   Weather count: {len(weather_data)} items\n")
        else:
            print(f"   Error: {weather_response.text}\n")

        print("3. Testing authenticated endpoint (Users)...")
        users_response = client.get("/users")

        if users_response.status_code == 200:
            users_data = users_response.json()
            print(f"   Status: {users_response.status_code} (Authentication successful!)")
            print(f"   Users count: {len(users_data)} items\n")
        else:
            print(f"   Status: {users_response.status_code} (Authentication failed)")
            print(f"   Error: {users_response.text}\n")

        print("4. Testing authenticated POST endpoint (Create User)...")
        new_user = {
            "first": "Demo",
            "last": "User",
            "email": "demo.user@example.com"
        }

        create_user_response = client.post("/users", new_user)

        if create_user_response.status_code == 200:
            created_user = create_user_response.json()
            print(f"   Status: {create_user_response.status_code} (Authentication successful!)")
            print(f"   Created user: {created_user.get('firstName', 'N/A')} {created_user.get('lastName', 'N/A')}\n")
        else:
            print(f"   Status: {create_user_response.status_code} (Authentication failed)")
            print(f"   Error: {create_user_response.text}\n")

        print("5. Testing authenticated endpoint (Addresses)...")
        addresses_response = client.get("/addresses")

        if addresses_response.status_code == 200:
            addresses_data = addresses_response.json()
            print(f"   Status: {addresses_response.status_code} (Authentication successful!)")
            print(f"   Addresses count: {len(addresses_data)} items\n")
        else:
            print(f"   Status: {addresses_response.status_code} (Authentication failed)")
            print(f"   Error: {addresses_response.text}\n")

    except Exception as error:
        print(f"Demo failed: {str(error)}")

        if "Connection refused" in str(error) or "ConnectTimeout" in str(error):
            print("\nMake sure the Sample.MinimalApi is running:")
            print("   cd samples/Sample.MinimalApi")
            print("   dotnet run")

    print("Demo completed!")
    print("\nFor interactive testing, run: python interactive.py")


if __name__ == "__main__":
    demonstrate_hmac_authentication()
