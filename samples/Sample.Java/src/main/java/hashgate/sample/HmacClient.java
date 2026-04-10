package hashgate.sample;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HMAC Authentication client for Java.
 * <p>
 * This client implements the same authentication scheme as HashGate.AspNetCore
 * for making authenticated HTTP requests to APIs protected with HMAC authentication.
 */
public class HmacClient {

    private static final String DEFAULT_SCHEME_NAME = "HMAC";
    private static final String TIME_STAMP_HEADER_NAME = "x-timestamp";
    private static final String CONTENT_HASH_HEADER_NAME = "x-content-sha256";
    private static final String EMPTY_CONTENT_HASH = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    private static final List<String> DEFAULT_SIGNED_HEADERS = List.of("host", TIME_STAMP_HEADER_NAME, CONTENT_HASH_HEADER_NAME);

    private final String client;
    private final String secret;
    private final String baseUrl;
    private final HttpClient httpClient;

    /**
     * Initialize HMAC client.
     *
     * @param client  the client identifier
     * @param secret  the secret key for HMAC signing
     * @param baseUrl the base URL of the API
     */
    public HmacClient(String client, String secret, String baseUrl) {
        this.client = client;
        this.secret = secret;
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.httpClient = createHttpClient();
    }

    private static HttpClient createHttpClient() {
        try {
            // Trust all certificates for local development (localhost only)
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                    }
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            return HttpClient.newBuilder().sslContext(sslContext).build();
        } catch (Exception e) {
            // Fall back to default client if SSL setup fails
            return HttpClient.newBuilder().build();
        }
    }

    /**
     * Creates a canonical string for signing based on HTTP method, path, and header values.
     *
     * @param method       HTTP method (GET, POST, etc.)
     * @param pathAndQuery request path with query string
     * @param headerValues list of header values in order
     * @return canonical string for signing
     */
    public String createStringToSign(String method, String pathAndQuery, List<String> headerValues) {
        String upperMethod = method.toUpperCase();
        String headerString = String.join(";", headerValues);
        return upperMethod + "\n" + pathAndQuery + "\n" + headerString;
    }

    /**
     * Generates HMAC-SHA256 signature for the string to sign.
     *
     * @param stringToSign the canonical string to sign
     * @return base64-encoded signature
     */
    public String generateSignature(String stringToSign) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] signature = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate HMAC signature", e);
        }
    }

    /**
     * Generates the Authorization header value.
     *
     * @param signedHeaders list of signed header names
     * @param signature     base64-encoded signature
     * @return authorization header value
     */
    public String generateAuthorizationHeader(List<String> signedHeaders, String signature) {
        String signedHeadersString = String.join(";", signedHeaders);
        return DEFAULT_SCHEME_NAME + " Client=" + client + "&SignedHeaders=" + signedHeadersString + "&Signature=" + signature;
    }

    /**
     * Calculates SHA256 hash of content and returns base64-encoded result.
     *
     * @param content content to hash (null for empty content)
     * @return base64-encoded SHA256 hash
     */
    public String calculateContentHash(String content) {
        if (content == null || content.isEmpty()) {
            return EMPTY_CONTENT_HASH;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate content hash", e);
        }
    }

    /**
     * Creates authenticated request headers.
     *
     * @param method  HTTP method
     * @param path    request path with query string
     * @param content request body content (null for no body)
     * @return headers map with authentication
     */
    public Map<String, String> createAuthenticatedHeaders(String method, String path, String content) {
        URI uri = URI.create(baseUrl + path);
        String host = uri.getHost() + (uri.getPort() != -1 ? ":" + uri.getPort() : "");
        String pathAndQuery = uri.getRawPath() + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");

        // Generate timestamp (Unix timestamp)
        String timestamp = String.valueOf(Instant.now().getEpochSecond());

        // Calculate content hash
        String contentHash = calculateContentHash(content);

        // Create header values in the order of DEFAULT_SIGNED_HEADERS
        List<String> headerValues = List.of(host, timestamp, contentHash);

        // Create string to sign
        String stringToSign = createStringToSign(method, pathAndQuery, headerValues);

        // Generate signature
        String signature = generateSignature(stringToSign);

        // Generate authorization header
        String authorizationHeader = generateAuthorizationHeader(DEFAULT_SIGNED_HEADERS, signature);

        // Build final headers
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", host);
        headers.put(TIME_STAMP_HEADER_NAME, timestamp);
        headers.put(CONTENT_HASH_HEADER_NAME, contentHash);
        headers.put("Authorization", authorizationHeader);

        if (content != null && !content.isEmpty()) {
            headers.put("Content-Type", "application/json");
        }

        return headers;
    }

    /**
     * Makes an authenticated HTTP request.
     *
     * @param method   HTTP method
     * @param path     request path
     * @param jsonBody request body as JSON string (null for no body)
     * @return HTTP response
     */
    public HttpResponse<String> request(String method, String path, String jsonBody) throws Exception {
        Map<String, String> headers = createAuthenticatedHeaders(method, path, jsonBody);
        String url = baseUrl + path;

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url));

        // Add headers (skip Host — it's a restricted header managed by HttpClient)
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (!header.getKey().equalsIgnoreCase("Host")) {
                requestBuilder.header(header.getKey(), header.getValue());
            }
        }

        // Set method and body
        if (jsonBody != null && !jsonBody.isEmpty()) {
            requestBuilder.method(method.toUpperCase(), HttpRequest.BodyPublishers.ofString(jsonBody));
        } else {
            requestBuilder.method(method.toUpperCase(), HttpRequest.BodyPublishers.noBody());
        }

        return httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Makes a GET request.
     *
     * @param path request path
     * @return HTTP response
     */
    public HttpResponse<String> get(String path) throws Exception {
        return request("GET", path, null);
    }

    /**
     * Makes a POST request.
     *
     * @param path     request path
     * @param jsonBody request body as JSON string
     * @return HTTP response
     */
    public HttpResponse<String> post(String path, String jsonBody) throws Exception {
        return request("POST", path, jsonBody);
    }

    /**
     * Makes a PUT request.
     *
     * @param path     request path
     * @param jsonBody request body as JSON string
     * @return HTTP response
     */
    public HttpResponse<String> put(String path, String jsonBody) throws Exception {
        return request("PUT", path, jsonBody);
    }

    /**
     * Makes a DELETE request.
     *
     * @param path request path
     * @return HTTP response
     */
    public HttpResponse<String> delete(String path) throws Exception {
        return request("DELETE", path, null);
    }
}
