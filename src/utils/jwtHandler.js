const fs = require("fs");
const crypto = require("crypto");

// Load RSA keys
const privateKey = fs.readFileSync("./keys/private.pem", "utf8");
const publicKey = fs.readFileSync("./keys/public.pem", "utf8");

// Secure-by-default JWT implementation with optional vulnerabilities
const secret = process.env.JWT_SECRET // symmetric key stored in .env
console.log('secret:', secret);
const options = { 
  expiresIn: 3600
}

const createJWT = (payload) => {
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

  // 1.) VULNERABILITY: no validation - this won't affect the creation of the JWT, just whether it's validated, so we'll stick with defaults

  // 2.) VULNERABILITY: Allow weak secret if --weak-secret is enabled (WORKING AS EXPECTED)
  if (global.vulnerabilities.weakSecret) {
    finalSecret = 'supersecret'; // set weak secret
    // finalSecret = 'sUpErS3Cr3t'; // i'd like to make this discoverable with rules
  } else {
    finalSecret = secret;
  }
  
  // 3.) VULNERABILITY: Allow 'none' algorithm if --allow-none is enabled (WORKING AS EXPECTED)
  // sign with HS256, the vulnerabilitiy is in the verification
  
  // VULNERABILITY: Allow algorithm confusion if --allow-alg-confusion is enabled
  if (global.vulnerabilities.allowAlgConfusion) {
    header.alg = 'RS256'; // Create the JWT with RS256
  }

  // Base64 encode header and payload
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(finalPayload)).toString('base64url');

  // Create signature
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  let signature;
  console.log(header.alg)
  if (header.alg === 'none') {
    signature = ''; // VULNERABILITY: No signature if 'none' algorithm is allowed
  } else if (header.alg === 'HS256') {
    console.log('signing with: %s', finalSecret)
    signature = crypto.createHmac("sha256", finalSecret).update(signatureInput).digest("base64url");
  } else if (header.alg === 'RS256') {
    signature = crypto.createSign("RSA-SHA256").update(signatureInput).sign(privateKey, "base64");
  }

  return `${encodedHeader}.${encodedPayload}.${signature}`;
};

const verifyJWT = (token, secret) => {
  try {
    const [encodedHeader, encodedPayload, signature] = token.split('.');

    // Decode header and payload
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());

    // 1.) VULNERABILITY: no validation
    // TO DO: it would be cool to have absolutely no validation, and validation of only signature length and/or char set
    if (global.vulnerabilities.disableValidation){
      return payload;
    }

    // VULNERABILITY: Allow 'none' algorithm if --allow-none is enabled
    // Exploit: Attackers can submit unsigned tokens
    // Expansion: Add logging to detect 'none' algorithm usage or test with forged tokens
    if (global.vulnerabilities.allowNone && header.alg === 'none') {
      return payload;
    }

    // VULNERABILITY: Allow algorithm confusion if --allow-alg-confusion is enabled
    // Exploit: Attackers can use a public key as the HMAC secret for RS256-signed tokens
    if (global.vulnerabilities.allowAlgConfusion) {
      // use public key to verify token
    }

    // VULNERABILITY: Skip expiration check if --no-expiration is enabled
    // Exploit: Tokens never expire, enabling replay attacks
    // Expansion: Store tokens in a database to demonstrate replay attacks or add revocation
    if (!global.vulnerabilities.disableValidation && payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }

    // VULNERABILITY: Use weak secret if --weak-secret is enabled
    // Exploit: Weak secrets can be brute-forced
    // Expansion: Simulate a brute-force attack or log signature verification failures
    if (global.vulnerabilities.weakSecret) {
      const finalSecret = global.vulnerabilities.weakSecret;
    }

    // Verify signature
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const computedSignature = crypto.createHmac("sha256", finalSecret).update(signatureInput).digest("base64url");

    if (computedSignature !== signature) {
      throw new Error('Invalid signature');
    }

    return payload;
  } catch (error) {
    throw new Error(`Invalid token: ${error.message}`);
  }
};

module.exports = { createJWT, verifyJWT };
