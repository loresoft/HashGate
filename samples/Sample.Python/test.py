"""
Test suite for HMAC client functionality
Run with: python test.py
"""

import unittest
from unittest.mock import patch, Mock
from hmac_client import HmacClient
import time


class TestHmacClient(unittest.TestCase):

    def setUp(self):
        """Set up test client"""
        self.client = HmacClient(
            client="TestClient",
            secret="test-secret",
            base_url="https://api.example.com"
        )

    def test_initialization(self):
        """Test client initialization"""
        self.assertEqual(self.client.client, "TestClient")
        self.assertEqual(self.client.secret, b"test-secret")
        self.assertEqual(self.client.base_url, "https://api.example.com")

    def test_base_url_trailing_slash_removal(self):
        """Test that trailing slash is removed from base URL"""
        client = HmacClient("test", "secret", "https://api.example.com/")
        self.assertEqual(client.base_url, "https://api.example.com")

    def test_create_string_to_sign(self):
        """Test string to sign creation"""
        method = "GET"
        path = "/api/test"
        headers = ["example.com", "1234567890", "abc123"]

        result = self.client.create_string_to_sign(method, path, headers)
        expected = "GET\n/api/test\nexample.com;1234567890;abc123"

        self.assertEqual(result, expected)

    def test_generate_signature(self):
        """Test HMAC signature generation"""
        string_to_sign = "GET\n/api/test\nexample.com;1234567890;abc123"
        signature = self.client.generate_signature(string_to_sign)

        # Signature should be base64 encoded
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

        # Same input should produce same signature
        signature2 = self.client.generate_signature(string_to_sign)
        self.assertEqual(signature, signature2)

    def test_generate_authorization_header(self):
        """Test authorization header generation"""
        signed_headers = ["host", "x-timestamp", "x-content-sha256"]
        signature = "test-signature"

        auth_header = self.client.generate_authorization_header(signed_headers, signature)
        expected = "HMAC Client=TestClient&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=test-signature"

        self.assertEqual(auth_header, expected)

    def test_calculate_content_hash_empty(self):
        """Test content hash calculation for empty content"""
        hash_result = self.client.calculate_content_hash(None)
        self.assertEqual(hash_result, self.client.EMPTY_CONTENT_HASH)

        hash_result = self.client.calculate_content_hash("")
        self.assertEqual(hash_result, self.client.EMPTY_CONTENT_HASH)

    def test_calculate_content_hash_with_content(self):
        """Test content hash calculation with actual content"""
        content = '{"test": "data"}'
        hash_result = self.client.calculate_content_hash(content)

        self.assertIsInstance(hash_result, str)
        self.assertNotEqual(hash_result, self.client.EMPTY_CONTENT_HASH)

        # Same content should produce same hash
        hash_result2 = self.client.calculate_content_hash(content)
        self.assertEqual(hash_result, hash_result2)

    def test_create_authenticated_headers(self):
        """Test authenticated headers creation"""
        with patch('time.time', return_value=1234567890):
            headers = self.client.create_authenticated_headers("GET", "/api/test")

            self.assertIn("Host", headers)
            self.assertIn("x-timestamp", headers)
            self.assertIn("x-content-sha256", headers)
            self.assertIn("Authorization", headers)

            self.assertEqual(headers["Host"], "api.example.com")
            self.assertEqual(headers["x-timestamp"], "1234567890")
            self.assertEqual(headers["x-content-sha256"], self.client.EMPTY_CONTENT_HASH)
            self.assertTrue(headers["Authorization"].startswith("HMAC Client=TestClient"))

    def test_create_authenticated_headers_with_content(self):
        """Test authenticated headers creation with content"""
        content = '{"test": "data"}'

        with patch('time.time', return_value=1234567890):
            headers = self.client.create_authenticated_headers("POST", "/api/test", content)

            self.assertIn("Content-Type", headers)
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertNotEqual(headers["x-content-sha256"], self.client.EMPTY_CONTENT_HASH)

    @patch('requests.Session.request')
    def test_request_method(self, mock_request):
        """Test generic request method"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        response = self.client.request("GET", "/api/test")

        self.assertEqual(response, mock_response)
        mock_request.assert_called_once()

        # Verify the call arguments
        call_args = mock_request.call_args
        self.assertEqual(call_args[1]['method'], "GET")
        self.assertEqual(call_args[1]['url'], "https://api.example.com/api/test")
        self.assertIn('headers', call_args[1])

    @patch('requests.Session.request')
    def test_get_method(self, mock_request):
        """Test GET convenience method"""
        mock_response = Mock()
        mock_request.return_value = mock_response

        response = self.client.get("/api/test")

        mock_request.assert_called_once()
        call_args = mock_request.call_args
        self.assertEqual(call_args[1]['method'], "GET")
        self.assertIsNone(call_args[1]['data'])

    @patch('requests.Session.request')
    def test_post_method(self, mock_request):
        """Test POST convenience method"""
        mock_response = Mock()
        mock_request.return_value = mock_response

        test_data = {"key": "value"}
        response = self.client.post("/api/test", test_data)

        mock_request.assert_called_once()
        call_args = mock_request.call_args
        self.assertEqual(call_args[1]['method'], "POST")
        self.assertIn('"key": "value"', call_args[1]['data'])


class TestHmacClientIntegration(unittest.TestCase):
    """Integration tests that require actual network calls"""

    def setUp(self):
        self.client = HmacClient(
            client="SampleClient",
            secret="sample-client-secret",
            base_url="https://httpbin.org"
        )

    @unittest.skip("Requires network access")
    def test_real_request(self):
        """Test actual HTTP request (requires network)"""
        response = self.client.get("/get")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
