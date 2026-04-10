package hashgate.sample;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for HMAC client functionality.
 * Run with: mvn test
 */
class HmacClientTest {

    private HmacClient client;

    @BeforeEach
    void setUp() {
        client = new HmacClient("TestClient", "test-secret", "https://api.example.com");
    }

    @Test
    void testCreateStringToSign() {
        String method = "GET";
        String path = "/api/test";
        List<String> headers = List.of("example.com", "1234567890", "abc123");

        String result = client.createStringToSign(method, path, headers);
        String expected = "GET\n/api/test\nexample.com;1234567890;abc123";

        assertEquals(expected, result);
    }

    @Test
    void testCreateStringToSignUppercasesMethod() {
        String result = client.createStringToSign("get", "/test", List.of("host", "ts", "hash"));
        assertTrue(result.startsWith("GET\n"));
    }

    @Test
    void testGenerateSignature() {
        String stringToSign = "GET\n/api/test\nexample.com;1234567890;abc123";
        String signature = client.generateSignature(stringToSign);

        assertNotNull(signature);
        assertFalse(signature.isEmpty());

        // Same input should produce same signature
        String signature2 = client.generateSignature(stringToSign);
        assertEquals(signature, signature2);
    }

    @Test
    void testGenerateSignatureDifferentInputs() {
        String sig1 = client.generateSignature("input1");
        String sig2 = client.generateSignature("input2");

        assertNotEquals(sig1, sig2);
    }

    @Test
    void testGenerateAuthorizationHeader() {
        List<String> signedHeaders = List.of("host", "x-timestamp", "x-content-sha256");
        String signature = "test-signature";

        String authHeader = client.generateAuthorizationHeader(signedHeaders, signature);
        String expected = "HMAC Client=TestClient&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=test-signature";

        assertEquals(expected, authHeader);
    }

    @Test
    void testCalculateContentHashEmpty() {
        String hashNull = client.calculateContentHash(null);
        assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", hashNull);

        String hashEmpty = client.calculateContentHash("");
        assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", hashEmpty);
    }

    @Test
    void testCalculateContentHashWithContent() {
        String content = "{\"test\": \"data\"}";
        String hash = client.calculateContentHash(content);

        assertNotNull(hash);
        assertFalse(hash.isEmpty());
        assertNotEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", hash);

        // Same content should produce same hash
        String hash2 = client.calculateContentHash(content);
        assertEquals(hash, hash2);
    }

    @Test
    void testCreateAuthenticatedHeaders() {
        Map<String, String> headers = client.createAuthenticatedHeaders("GET", "/api/test", null);

        assertTrue(headers.containsKey("Host"));
        assertTrue(headers.containsKey("x-timestamp"));
        assertTrue(headers.containsKey("x-content-sha256"));
        assertTrue(headers.containsKey("Authorization"));

        assertEquals("api.example.com", headers.get("Host"));
        assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", headers.get("x-content-sha256"));
        assertTrue(headers.get("Authorization").startsWith("HMAC Client=TestClient"));
    }

    @Test
    void testCreateAuthenticatedHeadersWithContent() {
        String content = "{\"test\": \"data\"}";
        Map<String, String> headers = client.createAuthenticatedHeaders("POST", "/api/test", content);

        assertTrue(headers.containsKey("Content-Type"));
        assertEquals("application/json", headers.get("Content-Type"));
        assertNotEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", headers.get("x-content-sha256"));
    }

    @Test
    void testCreateAuthenticatedHeadersWithPort() {
        HmacClient portClient = new HmacClient("TestClient", "test-secret", "https://localhost:7134");
        Map<String, String> headers = portClient.createAuthenticatedHeaders("GET", "/test", null);

        assertEquals("localhost:7134", headers.get("Host"));
    }

    @Test
    void testBaseUrlTrailingSlashRemoval() {
        HmacClient slashClient = new HmacClient("test", "secret", "https://api.example.com/");
        Map<String, String> headers = slashClient.createAuthenticatedHeaders("GET", "/test", null);

        assertEquals("api.example.com", headers.get("Host"));
    }
}
