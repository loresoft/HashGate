"""
Setup script for the Python HMAC client sample
Run this script to verify your environment and dependencies
"""

import sys
import subprocess
import importlib.util


def check_python_version():
    """Check if Python version is 3.7 or higher"""
    print("Checking Python version...")
    if sys.version_info < (3, 7):
        print(f"❌ Python 3.7 or higher is required. Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version}")
    return True


def check_dependencies():
    """Check if required dependencies are installed"""
    print("\nChecking dependencies...")

    required_packages = ['requests', 'urllib3']
    missing_packages = []

    for package in required_packages:
        spec = importlib.util.find_spec(package)
        if spec is None:
            missing_packages.append(package)
            print(f"❌ {package} is not installed")
        else:
            print(f"✅ {package} is installed")

    if missing_packages:
        print(f"\nTo install missing packages, run:")
        print(f"pip install {' '.join(missing_packages)}")
        print("or:")
        print("pip install -r requirements.txt")
        return False

    return True


def test_hmac_client():
    """Test basic functionality of the HMAC client"""
    print("\nTesting HMAC client...")

    try:
        from hmac_client import HmacClient

        # Create a test client
        client = HmacClient("test", "test-secret", "https://example.com")

        # Test basic functionality
        test_string = client.create_string_to_sign("GET", "/test", ["example.com", "123", "abc"])
        expected = "GET\n/test\nexample.com;123;abc"

        if test_string == expected:
            print("✅ HMAC client basic functionality test passed")
            return True
        else:
            print("❌ HMAC client basic functionality test failed")
            return False

    except ImportError as e:
        print(f"❌ Failed to import HMAC client: {e}")
        return False
    except Exception as e:
        print(f"❌ HMAC client test failed: {e}")
        return False


def main():
    print("Python HMAC Client Setup Verification")
    print("=" * 40)

    success = True

    # Check Python version
    if not check_python_version():
        success = False

    # Check dependencies
    if not check_dependencies():
        success = False

    # Test HMAC client
    if not test_hmac_client():
        success = False

    print("\n" + "=" * 40)

    if success:
        print("🎉 Setup verification completed successfully!")
        print("\nYou can now run:")
        print("  python demo.py        - Run the demonstration")
        print("  python interactive.py - Start interactive testing")
        print("  python example.py     - Run basic example")
        print("  python test.py        - Run unit tests")
    else:
        print("❌ Setup verification failed!")
        print("\nPlease resolve the issues above and run this script again.")

    return success


if __name__ == "__main__":
    main()
