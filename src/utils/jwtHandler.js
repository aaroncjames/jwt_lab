const CryptoJS = require('crypto-js');

// Secure-by-default JWT implementation with optional vulnerabilities
const createJWT = (payload, secret, options = {}) => {
  console.log('createJWT payload:', payload);
  console.log('createJWT secret:', secret);
  console.log('createJWT options:', options);
  const header = {
    alg: options.alg || 'HS256', // Default to HMAC-SHA256
    typ: 'JWT',
  };
  console.log('Resolved header.alg:', header.alg);

  // Set expiration (secure by default)
  const finalPayload = {
    ...payload,
    exp: Math.floor(Date.now() / 1000) + (options.expiresIn || 3600), // Default 1 hour
  };

  // VULNERABILITY: Allow 'none' algorithm if --allow-none is enabled
  if (global.vulnerabilities.allowNone && options.alg === 'none') {
    header.alg = 'none';
  } else if (options.alg === 'none') {
    throw new Error('Algorithm "none" is not allowed unless --allow-none is enabled');
  }

  // VULNERABILITY: Allow algorithm confusion if --allow-alg-confusion is enabled
  if (global.vulnerabilities.allowAlgConfusion && options.alg && options.alg !== 'HS256' && options.alg !== 'none') {
    header.alg = options.alg; // Allow other algorithms like RS256
  } else if (options.alg && options.alg !== 'HS256') { // FIX: Only throw if alg is explicitly set
    console.log('Algorithm check failed: options.alg =', options.alg);
    throw new Error('Only HS256 is allowed unless --allow-alg-confusion is enabled');
  }

  // VULNERABILITY: Allow weak secret if --weak-secret is enabled
  let finalSecret = secret;
  if (global.vulnerabilities.weakSecret && (!secret || secret.length < 32)) {
    finalSecret = 'secret'; // Default to weak secret
  } else if (!secret || secret.length < 32) {
    throw new Error('Secret must be at least 32 characters long');
  }

  // Base64 encode header and payload
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(finalPayload)).toString('base64url');

  // Create signature
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  let signature;

  if (header.alg === 'none') {
    signature = ''; // VULNERABILITY: No signature if 'none' algorithm is allowed
  } else {
    signature = CryptoJS.HmacSHA256(signatureInput, finalSecret).toString(CryptoJS.enc.Base64url);
  }

  return `${encodedHeader}.${encodedPayload}.${signature}`;
};

const verifyJWT = (token, secret) => {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');

    // Decode header and payload
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());

    // VULNERABILITY: Allow 'none' algorithm if --allow-none is enabled
    // Exploit: Attackers can submit unsigned tokens
    // Expansion: Add logging to detect 'none' algorithm usage or test with forged tokens
    if (global.vulnerabilities.allowNone && header.alg === 'none') {
      return payload;
    }

    // VULNERABILITY: Allow algorithm confusion if --allow-alg-confusion is enabled
    // Exploit: Attackers can use a public key as the HMAC secret for RS256-signed tokens
    // Expansion: Simulate RS256 signing with a public key and test verification
    if (!global.vulnerabilities.allowAlgConfusion && header.alg !== 'HS256') {
      throw new Error('Invalid algorithm: Only HS256 is allowed');
    }

    // VULNERABILITY: Skip expiration check if --no-expiration is enabled
    // Exploit: Tokens never expire, enabling replay attacks
    // Expansion: Store tokens in a database to demonstrate replay attacks or add revocation
    if (!global.vulnerabilities.noExpiration && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }

    // VULNERABILITY: Use weak secret if --weak-secret is enabled
    // Exploit: Weak secrets can be brute-forced
    // Expansion: Simulate a brute-force attack or log signature verification failures
    const finalSecret = global.vulnerabilities.weakSecret && (!secret || secret.length < 32) ? 'secret' : secret;
    if (!finalSecret || finalSecret.length < 32) {
      throw new Error('Secret must be at least 32 characters long');
    }

    // Verify signature
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const computedSignature = CryptoJS.HmacSHA256(signatureInput, finalSecret).toString(CryptoJS.enc.Base64url);

    if (computedSignature !== signature) {
      throw new Error('Invalid signature');
    }

    return payload;
  } catch (error) {
    throw new Error(`Invalid token: ${error.message}`);
  }
};

module.exports = { createJWT, verifyJWT };
