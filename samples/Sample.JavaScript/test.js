import { HmacClient } from './hmac-client.js';
import { strict as assert } from 'assert';

/**
 * Simple test suite for HMAC authentication client
 * Run with: node test.js
 */

console.log('🧪 Running HMAC Authentication Client Tests...\n');

// Test 1: String to Sign Creation
function testStringToSign() {
    console.log('Testing string to sign creation...');

    const client = new HmacClient('TestClient', 'test-secret');
    const method = 'GET';
    const pathAndQuery = '/users?page=1';
    const headerValues = ['localhost:7134', '2023-08-04T12:00:00.000Z', '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='];

    const stringToSign = client.createStringToSign(method, pathAndQuery, headerValues);
    const expected = 'GET\n/users?page=1\nlocalhost:7134;2023-08-04T12:00:00.000Z;47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';

    assert.strictEqual(stringToSign, expected);
    console.log('String to sign creation test passed');
}

// Test 2: Content Hash Calculation
function testContentHash() {
    console.log('Testing content hash calculation...');

    const client = new HmacClient('TestClient', 'test-secret');

    // Test empty content
    const emptyHash = client.calculateContentHash(null);
    assert.strictEqual(emptyHash, '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');

    // Test content hash
    const content = '{"name":"test"}';
    const contentHash = client.calculateContentHash(content);
    // This should be the SHA256 hash of the JSON string
    assert.strictEqual(typeof contentHash, 'string');
    assert.strictEqual(contentHash.length > 0, true);

    console.log('Content hash calculation test passed');
}

// Test 3: Signature Generation
function testSignatureGeneration() {
    console.log('Testing signature generation...');

    const client = new HmacClient('TestClient', 'test-secret');
    const stringToSign = 'GET\n/test\nhost;timestamp;content-hash';

    const signature = client.generateSignature(stringToSign);

    // Should be a base64 string
    assert.strictEqual(typeof signature, 'string');
    assert.strictEqual(signature.length > 0, true);

    // Same input should produce same output
    const signature2 = client.generateSignature(stringToSign);
    assert.strictEqual(signature, signature2);

    console.log('Signature generation test passed');
}

// Test 4: Authorization Header Generation
function testAuthorizationHeader() {
    console.log('Testing authorization header generation...');

    const client = new HmacClient('TestClient', 'test-secret');
    const signedHeaders = ['host', 'x-timestamp', 'x-content-sha256'];
    const signature = 'dGVzdC1zaWduYXR1cmU='; // base64 encoded "test-signature"

    const authHeader = client.generateAuthorizationHeader(signedHeaders, signature);
    const expected = 'HMAC Client=TestClient&SignedHeaders=host;x-timestamp;x-content-sha256&Signature=dGVzdC1zaWduYXR1cmU=';

    assert.strictEqual(authHeader, expected);
    console.log('Authorization header generation test passed');
}

// Test 5: Header Creation
function testHeaderCreation() {
    console.log('Testing authenticated header creation...');

    const client = new HmacClient('TestClient', 'test-secret', 'https://localhost:7134');
    const headers = client.createAuthenticatedHeaders('GET', '/test', null);

    // Check required headers are present
    assert.strictEqual(typeof headers['Host'], 'string');
    assert.strictEqual(typeof headers['x-timestamp'], 'string');
    assert.strictEqual(typeof headers['x-content-sha256'], 'string');
    assert.strictEqual(typeof headers['Authorization'], 'string');

    // Check authorization header format
    assert.strictEqual(headers['Authorization'].startsWith('HMAC Client=TestClient'), true);

    // For empty content, should use empty content hash
    assert.strictEqual(headers['x-content-sha256'], '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');

    console.log('Authenticated header creation test passed');
}

// Run all tests
async function runTests() {
    try {
        testStringToSign();
        testContentHash();
        testSignatureGeneration();
        testAuthorizationHeader();
        testHeaderCreation();

        console.log('\nAll tests passed! The HMAC authentication client is working correctly.');

        console.log('\nSummary:');
        console.log('   - String to sign creation: ');
        console.log('   - Content hash calculation: ');
        console.log('   - Signature generation: ');
        console.log('   - Authorization header generation: ');
        console.log('   - Authenticated header creation: ');

    } catch (error) {
        console.error('\nTest failed:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

runTests();
