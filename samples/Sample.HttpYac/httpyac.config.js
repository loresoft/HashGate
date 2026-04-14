const crypto = require('crypto');
const { URL } = require('url');

module.exports = {
  log: {
    level: 'trace',
    supportAnsiColors: true,
    prettyPrint: true,
  },
  request: {
    https: {
      rejectUnauthorized: false
    }
  },
  environments: {
    local: {
      host: "https://localhost:7134",
      tokenId: "SampleClient",
      tokenSecret: "ci3JaJZRDQGq6juXVvfp89TnAzS43ASaK/uB38R6ndzr7NN/Wlbstvg+2ZaI2qUVHkvvD3+hPvvzL58Z/bPq6A==",
    }
  },
  configureHooks: function (api) {
    api.hooks.replaceVariable.addHook('replaceHmacHeader', replaceHmacHeader);
  }
}

function replaceHmacHeader(text, type, context) {
  if (type.toLowerCase() !== 'authorization')
    return text;

  if (!text.startsWith('HMAC'))
    return text;

  const { request } = context;
  if (!request)
    return text;

  // format: HMAC client:myclient secret:mysecret
  const hmacRegex = /^hmac\s*client\s*[:=]\s*(?<client>\S+)[\s&]+secret\s*[:=]\s*(?<secret>\S+)\s*$/i;
  const match = hmacRegex.exec(text);
  if (!match || !match.groups)
    return text;

  const client = match.groups.client;
  const secretKey = match.groups.secret;

  const timestamp = Math.floor(Date.now() / 1000);

  const url = new URL(request.url);
  const host = url.hostname;
  const pathAndQuery = url.pathname + url.search;

  const method = request.method.toUpperCase();
  const body = request.body ? request.body.toString() : '';

  // Create content hash
  const contentHash = crypto
    .createHash('sha256')
    .update(body, 'utf8')
    .digest('base64');

  // Generate unique nonce
  const nonce = crypto.randomUUID();

  // Create signed headers and string to sign
  const headerValues = `${host};${timestamp};${contentHash};${nonce}`;
  const stringToSign = `${method}\n${pathAndQuery}\n${headerValues}`;

  // Generate signature
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(stringToSign, 'utf8')
    .digest('base64');

  // Construct Authorization header
  const signedHeader = 'host;x-timestamp;x-content-sha256;x-nonce';
  const authorization = `HMAC Client=${client}&SignedHeaders=${signedHeader}&Signature=${signature}`;

  // Set required headers
  request.headers['host'] = host;
  request.headers['x-timestamp'] = timestamp.toString();
  request.headers['x-content-sha256'] = contentHash;
  request.headers['x-nonce'] = nonce;

  console.info('Generated HMAC Authorization Header:', authorization);
  // Return the new Authorization header
  return authorization;

}
