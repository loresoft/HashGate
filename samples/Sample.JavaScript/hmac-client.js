import crypto from 'crypto';

/**
 * HMAC Authentication utilities for JavaScript clients
 * Based on AspNetCore.HmacAuthentication implementation
 */
export class HmacClient {
    /**
     * @param {string} client - The client identifier
     * @param {string} secret - The secret key for HMAC signing
     * @param {string} baseUrl - The base URL of the API
     */
    constructor(client, secret, baseUrl = 'https://localhost:7134') {
        this.client = client;
        this.secret = secret;
        this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash

        // Constants from the .NET implementation
        this.DEFAULT_SCHEME_NAME = 'HMAC';
        this.TIME_STAMP_HEADER_NAME = 'x-timestamp';
        this.CONTENT_HASH_HEADER_NAME = 'x-content-sha256';
        this.EMPTY_CONTENT_HASH = '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
        this.DEFAULT_SIGNED_HEADERS = ['host', this.TIME_STAMP_HEADER_NAME, this.CONTENT_HASH_HEADER_NAME];
    }

    /**
     * Creates a canonical string for signing based on HTTP method, path, and header values
     * @param {string} method - HTTP method (GET, POST, etc.)
     * @param {string} pathAndQuery - Request path with query string
     * @param {string[]} headerValues - Array of header values in order
     * @returns {string} Canonical string for signing
     */
    createStringToSign(method, pathAndQuery, headerValues) {
        const upperMethod = method.toUpperCase();
        const headerString = headerValues.join(';');
        return `${upperMethod}\n${pathAndQuery}\n${headerString}`;
    }

    /**
     * Generates HMAC-SHA256 signature for the string to sign
     * @param {string} stringToSign - The canonical string to sign
     * @returns {string} Base64-encoded signature
     */
    generateSignature(stringToSign) {
        const hmac = crypto.createHmac('sha256', this.secret);
        hmac.update(stringToSign, 'utf8');
        return hmac.digest('base64');
    }

    /**
     * Generates the Authorization header value
     * @param {string[]} signedHeaders - Array of signed header names
     * @param {string} signature - Base64-encoded signature
     * @returns {string} Authorization header value
     */
    generateAuthorizationHeader(signedHeaders, signature) {
        const signedHeadersString = signedHeaders.join(';');
        return `${this.DEFAULT_SCHEME_NAME} Client=${this.client}&SignedHeaders=${signedHeadersString}&Signature=${signature}`;
    }

    /**
     * Calculates SHA256 hash of content and returns base64-encoded result
     * @param {string|null} content - Content to hash (null for empty content)
     * @returns {string} Base64-encoded SHA256 hash
     */
    calculateContentHash(content) {
        if (!content) {
            return this.EMPTY_CONTENT_HASH;
        }

        const hash = crypto.createHash('sha256');
        hash.update(content, 'utf8');
        return hash.digest('base64');
    }

    /**
     * Creates authenticated request headers
     * @param {string} method - HTTP method
     * @param {string} path - Request path with query string
     * @param {string|null} content - Request body content
     * @returns {Object} Headers object with authentication
     */
    createAuthenticatedHeaders(method, path, content = null) {
        const url = new URL(this.baseUrl + path);
        const host = url.host;
        const pathAndQuery = url.pathname + url.search;

        // Generate timestamp (Unix timestamp)
        const timestamp = Math.floor(Date.now() / 1000).toString();

        // Calculate content hash
        const contentHash = this.calculateContentHash(content);

        // Create header values in the order of DEFAULT_SIGNED_HEADERS
        const headerValues = [host, timestamp, contentHash];

        // Create string to sign
        const stringToSign = this.createStringToSign(method, pathAndQuery, headerValues);

        // Generate signature
        const signature = this.generateSignature(stringToSign);

        // Generate authorization header
        const authorizationHeader = this.generateAuthorizationHeader(this.DEFAULT_SIGNED_HEADERS, signature);

        // Build final headers
        const headers = {
            'Host': host,
            [this.TIME_STAMP_HEADER_NAME]: timestamp,
            [this.CONTENT_HASH_HEADER_NAME]: contentHash,
            'Authorization': authorizationHeader
        };

        // Add content-type for POST requests if not provided
        if (content) {
            headers['Content-Type'] = 'application/json';
        }

        return headers;
    }

    /**
     * Makes an authenticated HTTP request
     * @param {string} method - HTTP method
     * @param {string} path - Request path
     * @param {Object|null} body - Request body (will be JSON stringified)
     * @returns {Promise<Response>} Fetch response
     */
    async request(method, path, body = null) {
        const content = body ? JSON.stringify(body) : null;
        const headers = this.createAuthenticatedHeaders(method, path, content);

        const url = this.baseUrl + path;

        const requestOptions = {
            method: method.toUpperCase(),
            headers
        };

        if (content) {
            requestOptions.body = content;
        }

        // Import fetch dynamically for Node.js compatibility
        const fetch = (await import('node-fetch')).default;
        return fetch(url, requestOptions);
    }

    /**
     * Makes a GET request
     * @param {string} path - Request path
     * @returns {Promise<Response>} Fetch response
     */
    async get(path) {
        return this.request('GET', path, null);
    }

    /**
     * Makes a POST request
     * @param {string} path - Request path
     * @param {Object} body - Request body
     * @returns {Promise<Response>} Fetch response
     */
    async post(path, body) {
        return this.request('POST', path, body);
    }

    /**
     * Makes a PUT request
     * @param {string} path - Request path
     * @param {Object} body - Request body
     * @returns {Promise<Response>} Fetch response
     */
    async put(path, body) {
        return this.request('PUT', path, body);
    }

    /**
     * Makes a DELETE request
     * @param {string} path - Request path
     * @returns {Promise<Response>} Fetch response
     */
    async delete(path) {
        return this.request('DELETE', path, null);
    }
}
