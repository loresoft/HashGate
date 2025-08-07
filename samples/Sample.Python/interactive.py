"""
Interactive HMAC client for testing API endpoints
Provides a simple menu-driven interface to test various endpoints
"""

from hmac_client import HmacClient
import json


def print_menu():
    print("\n=== HMAC Client Interactive Menu ===")
    print("1. Test Hello World (Public)")
    print("2. Get Weather Data (Public)")
    print("3. Get Users (Authenticated)")
    print("4. Create User (Authenticated)")
    print("5. Get Addresses (Authenticated)")
    print("6. Create Address (Authenticated)")
    print("7. Custom GET Request")
    print("8. Custom POST Request")
    print("9. Exit")
    print("=====================================")


def get_user_input():
    first = input("Enter first name: ").strip()
    last = input("Enter last name: ").strip()
    email = input("Enter email: ").strip()
    return {"first": first, "last": last, "email": email}


def get_address_input():
    street = input("Enter street: ").strip()
    city = input("Enter city: ").strip()
    state = input("Enter state: ").strip()
    zip_code = input("Enter zip code: ").strip()
    return {"street": street, "city": city, "state": state, "zip": zip_code}


def print_response(response, description="Response"):
    print(f"\n{description}:")
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")

    try:
        if response.headers.get('content-type', '').startswith('application/json'):
            data = response.json()
            print(f"JSON Body: {json.dumps(data, indent=2)}")
        else:
            print(f"Text Body: {response.text}")
    except Exception as e:
        print(f"Body (raw): {response.text}")
    print("-" * 50)


def main():
    print("HMAC Client Interactive Testing Tool")
    print("Connecting to Sample.MinimalApi at https://localhost:7134")

    # Create HMAC client
    client = HmacClient(
        client="SampleClient",
        secret="ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",
        base_url="https://localhost:7134"
    )

    while True:
        print_menu()
        choice = input("\nEnter your choice (1-9): ").strip()

        try:
            if choice == "1":
                print("\n--- Testing Hello World ---")
                response = client.get("/")
                print_response(response, "Hello World Response")

            elif choice == "2":
                print("\n--- Getting Weather Data ---")
                response = client.get("/weather")
                print_response(response, "Weather Data Response")

            elif choice == "3":
                print("\n--- Getting Users ---")
                response = client.get("/users")
                print_response(response, "Users Response")

            elif choice == "4":
                print("\n--- Creating User ---")
                user_data = get_user_input()
                if all(user_data.values()):
                    response = client.post("/users", user_data)
                    print_response(response, "Create User Response")
                else:
                    print("All fields are required!")

            elif choice == "5":
                print("\n--- Getting Addresses ---")
                response = client.get("/addresses")
                print_response(response, "Addresses Response")

            elif choice == "6":
                print("\n--- Creating Address ---")
                address_data = get_address_input()
                if all(address_data.values()):
                    response = client.post("/addresses", address_data)
                    print_response(response, "Create Address Response")
                else:
                    print("All fields are required!")

            elif choice == "7":
                print("\n--- Custom GET Request ---")
                path = input("Enter path (starting with /): ").strip()
                if path.startswith("/"):
                    response = client.get(path)
                    print_response(response, f"GET {path} Response")
                else:
                    print("Path must start with /")

            elif choice == "8":
                print("\n--- Custom POST Request ---")
                path = input("Enter path (starting with /): ").strip()
                if path.startswith("/"):
                    print("Enter JSON data (or press Enter for empty body):")
                    json_input = input().strip()
                    try:
                        data = json.loads(json_input) if json_input else {}
                        response = client.post(path, data)
                        print_response(response, f"POST {path} Response")
                    except json.JSONDecodeError:
                        print("Invalid JSON format!")
                else:
                    print("Path must start with /")

            elif choice == "9":
                print("\nGoodbye!")
                break

            else:
                print("Invalid choice. Please enter 1-9.")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
            if "Connection refused" in str(e) or "ConnectTimeout" in str(e):
                print("Make sure the Sample.MinimalApi is running:")
                print("   cd samples/Sample.MinimalApi && dotnet run")


if __name__ == "__main__":
    main()
