"""
HMAC Authentication utilities for Python clients
Based on HashGate.AspNetCore implementation
"""

import hashlib
import hmac
import base64
import time
from urllib.parse import urlparse, urlencode
from typing import Optional, Dict, Any, List
import requests


class HmacClient:
    """
    HMAC Authentication client for Python

    This client implements the same authentication scheme as HashGate.AspNetCore
    for making authenticated HTTP requests to APIs protected with HMAC authentication.
    """

    # Constants from the .NET implementation
    DEFAULT_SCHEME_NAME = "HMAC"
    TIME_STAMP_HEADER_NAME = "x-timestamp"
    CONTENT_HASH_HEADER_NAME = "x-content-sha256"
    EMPTY_CONTENT_HASH = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    DEFAULT_SIGNED_HEADERS = ["host", TIME_STAMP_HEADER_NAME, CONTENT_HASH_HEADER_NAME]

    def __init__(self, client: str, secret: str, base_url: str = "https://localhost:7134"):
        """
        Initialize HMAC client

        Args:
            client: The client identifier
            secret: The secret key for HMAC signing
            base_url: The base URL of the API
        """
        self.client = client
        self.secret = secret.encode('utf-8')
        self.base_url = base_url.rstrip('/')  # Remove trailing slash
        self.session = requests.Session()

        # Disable SSL verification for development (localhost)
        if "localhost" in base_url or "127.0.0.1" in base_url:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def create_string_to_sign(self, method: str, path_and_query: str, header_values: List[str]) -> str:
        """
        Creates a canonical string for signing based on HTTP method, path, and header values

        Args:
            method: HTTP method (GET, POST, etc.)
            path_and_query: Request path with query string
            header_values: Array of header values in order

        Returns:
            Canonical string for signing
        """
        upper_method = method.upper()
        header_string = ";".join(header_values)
        return f"{upper_method}\n{path_and_query}\n{header_string}"

    def generate_signature(self, string_to_sign: str) -> str:
        """
        Generates HMAC-SHA256 signature for the string to sign

        Args:
            string_to_sign: The canonical string to sign

        Returns:
            Base64-encoded signature
        """
        signature = hmac.new(
            self.secret,
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return base64.b64encode(signature).decode('utf-8')

    def generate_authorization_header(self, signed_headers: List[str], signature: str) -> str:
        """
        Generates the Authorization header value

        Args:
            signed_headers: Array of signed header names
            signature: Base64-encoded signature

        Returns:
            Authorization header value
        """
        signed_headers_string = ";".join(signed_headers)
        return f"{self.DEFAULT_SCHEME_NAME} Client={self.client}&SignedHeaders={signed_headers_string}&Signature={signature}"

    def calculate_content_hash(self, content: Optional[str]) -> str:
        """
        Calculates SHA256 hash of content and returns base64-encoded result

        Args:
            content: Content to hash (None for empty content)

        Returns:
            Base64-encoded SHA256 hash
        """
        if not content:
            return self.EMPTY_CONTENT_HASH

        content_bytes = content.encode('utf-8')
        hash_digest = hashlib.sha256(content_bytes).digest()
        return base64.b64encode(hash_digest).decode('utf-8')

    def create_authenticated_headers(self, method: str, path: str, content: Optional[str] = None) -> Dict[str, str]:
        """
        Creates authenticated request headers

        Args:
            method: HTTP method
            path: Request path with query string
            content: Request body content

        Returns:
            Headers dictionary with authentication
        """
        url = urlparse(self.base_url + path)
        host = url.netloc
        path_and_query = url.path + ("?" + url.query if url.query else "")

        # Generate timestamp (Unix timestamp)
        timestamp = str(int(time.time()))

        # Calculate content hash
        content_hash = self.calculate_content_hash(content)

        # Create header values in the order of DEFAULT_SIGNED_HEADERS
        header_values = [host, timestamp, content_hash]

        # Create string to sign
        string_to_sign = self.create_string_to_sign(method, path_and_query, header_values)

        # Generate signature
        signature = self.generate_signature(string_to_sign)

        # Generate authorization header
        authorization_header = self.generate_authorization_header(self.DEFAULT_SIGNED_HEADERS, signature)

        # Build final headers
        headers = {
            "Host": host,
            self.TIME_STAMP_HEADER_NAME: timestamp,
            self.CONTENT_HASH_HEADER_NAME: content_hash,
            "Authorization": authorization_header
        }

        # Add content-type for requests with content
        if content:
            headers["Content-Type"] = "application/json"

        return headers

    def request(self, method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> requests.Response:
        """
        Makes an authenticated HTTP request

        Args:
            method: HTTP method
            path: Request path
            json_data: Request body as dictionary (will be JSON serialized)

        Returns:
            requests.Response object
        """
        import json
        content = json.dumps(json_data) if json_data else None
        headers = self.create_authenticated_headers(method, path, content)

        url = self.base_url + path

        response = self.session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=content
        )

        return response

    def get(self, path: str) -> requests.Response:
        """
        Makes a GET request

        Args:
            path: Request path

        Returns:
            requests.Response object
        """
        return self.request("GET", path, None)

    def post(self, path: str, json_data: Dict[str, Any]) -> requests.Response:
        """
        Makes a POST request

        Args:
            path: Request path
            json_data: Request body as dictionary

        Returns:
            requests.Response object
        """
        return self.request("POST", path, json_data)

    def put(self, path: str, json_data: Dict[str, Any]) -> requests.Response:
        """
        Makes a PUT request

        Args:
            path: Request path
            json_data: Request body as dictionary

        Returns:
            requests.Response object
        """
        return self.request("PUT", path, json_data)

    def delete(self, path: str) -> requests.Response:
        """
        Makes a DELETE request

        Args:
            path: Request path

        Returns:
            requests.Response object
        """
        return self.request("DELETE", path, None)
