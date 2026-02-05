const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const DEBUG_JWT = process.env.DEBUG_JWT === 'true';
function debug(...args) {
  if (DEBUG_JWT) console.log('[JWT DEBUG]', ...args);
}

const PRIV_PATH = path.resolve(__dirname, '../../certs/private.pem');
const PUB_PATH  = path.resolve(__dirname, '../../certs/public.pem');
const HMAC_KEY_DIR = path.resolve(__dirname, '../../keys');

const KEY_ID = 'lab-key-1';

let privKeyObj, pubKeyObj, jwksCache;

/* -------------------- KEY HELPERS -------------------- */

function getPrivateKey() {
  if (!privKeyObj) {
    privKeyObj = crypto.createPrivateKey(
      fs.readFileSync(PRIV_PATH, 'utf8')
    );
  }
  return privKeyObj;
}

function getPublicKey() {
  if (!pubKeyObj) {
    pubKeyObj = crypto.createPublicKey(
      fs.readFileSync(PUB_PATH, 'utf8')
    );
  }
  return pubKeyObj;
}

function loadHmacKeyFromKid(kid) {
  const keyPath = path.join(HMAC_KEY_DIR, kid);
  debug('Loading HMAC key from:', keyPath);
  return fs.readFileSync(keyPath);
}

/* -------------------- JWKS -------------------- */

function getLocalJWKS() {
  if (!jwksCache) {
    const jwk = getPublicKey().export({ format: 'jwk' });
    jwksCache = {
      keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid: KEY_ID }]
    };
  }
  return jwksCache;
}

async function fetchRemoteJWKS(jku) {
  debug('Fetching remote JWKS from:', jku);
  const res = await fetch(jku);
  if (!res.ok) throw new Error('Failed to fetch JWKS');
  return res.json();
}

async function fetchRemoteX5U(x5u) {
  debug('Fetching remote x5u cert from:', x5u);
  const res = await fetch(x5u);
  if (!res.ok) throw new Error('Failed to fetch x5u cert');
  return res.text();
}

/* -------------------- BASE64URL -------------------- */

const b64url = (buf) =>
  buf.toString('base64')
     .replace(/=/g, '')
     .replace(/\+/g, '-')
     .replace(/\//g, '_');

/* -------------------- CREATE -------------------- */

function signingConfig(rawPayload, expiresInSeconds = 3600) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + expiresInSeconds;
  const claims = { ...rawPayload, iat, exp };

  if (global.vulnerabilities.kidInjection) {
    const kid = 'default.key';
    return {
      alg: 'HS256',
      kid,
      key: loadHmacKeyFromKid(kid),
      claims
    };
  }

  if (global.vulnerabilities.weakSecret) {
    return {
      alg: 'HS256',
      key: Buffer.from(process.env.JWT_SECRET_WEAK || 'weak-secret'),
      claims
    };
  }

  return {
    alg: 'RS256',
    kid: KEY_ID,
    key: getPrivateKey(),
    claims
  };
}

function sign(header, payload, { alg, key }) {
  const h = b64url(Buffer.from(JSON.stringify(header)));
  const p = b64url(Buffer.from(JSON.stringify(payload)));
  const data = `${h}.${p}`;

  const sig =
    alg === 'HS256'
      ? crypto.createHmac('sha256', key).update(data).digest()
      : crypto.sign('RSA-SHA256', Buffer.from(data), key);

  return `${data}.${b64url(sig)}`;
}

async function createJWT(rawPayload, expiresInSeconds) {
  const { alg, key, claims, kid } = signingConfig(rawPayload, expiresInSeconds);
  return sign(
    { alg, typ: 'JWT', ...(kid && { kid }) },
    claims,
    { alg, key }
  );
}

/* -------------------- VERIFY -------------------- */

async function verificationConfig(header) {
  const alg = header.alg ?? 'RS256';
  debug('Verification alg:', alg);

  if (global.vulnerabilities.disableValidation) {
    return { skipSig: true };
  }

  /* -------- HS256 -------- */
  if (alg === 'HS256') {
    if (global.vulnerabilities.algConfusion) {
      return {
        alg,
        key: getPublicKey().export({ type: 'spki', format: 'pem' })
      }
    }
    
    if (global.vulnerabilities.kidInjection) {
      return {
        alg,
        key: loadHmacKeyFromKid(header.kid)
      };
    }

    if (global.vulnerabilities.weakSecret) {
      return {
        alg,
        key: Buffer.from(process.env.JWT_SECRET_WEAK || 'weak-secret')
      };
    }

    return {
      alg,
      key: Buffer.from(process.env.JWT_SECRET || 'fallback-strong')
    };
  }

  /* -------- RS256 -------- */

  // Embedded JWK
  if (global.vulnerabilities.jwkInjection && header.jwk) {
    debug('Using embedded JWK');
    return {
      alg,
      key: crypto.createPublicKey({ key: header.jwk, format: 'jwk' })
    };
  }

  // Embedded x5u (remote PEM)
if (global.vulnerabilities.x5uInjection && header.x5u) {
  debug('Using remote x5u certificate');
  const pem = await fetchRemoteX5U(header.x5u);
  return {
    alg,
    key: crypto.createPublicKey(pem)
  };
}

  // Remote JKU
  if (global.vulnerabilities.jkuInjection && header.jku) {
    const jwks = await fetchRemoteJWKS(header.jku);
    const jwk = jwks.keys.find(k => k.kid === header.kid);
    if (!jwk) throw new Error('kid not found in remote JWKS');
    return {
      alg,
      key: crypto.createPublicKey({ key: jwk, format: 'jwk' })
    };
  }

  // Local JWKS
  const jwk = getLocalJWKS().keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Unknown kid');

  return {
    alg,
    key: crypto.createPublicKey({ key: jwk, format: 'jwk' })
  };
}

function verifySignature(parts, { alg, key, skipSig }) {
  if (skipSig) return true;

  const [h, p, s] = parts;
  const data = `${h}.${p}`;
  const sig = Buffer.from(
    s.replace(/-/g, '+').replace(/_/g, '/'),
    'base64'
  );

  if (alg === 'HS256') {
    const expected = crypto.createHmac('sha256', key).update(data).digest();
    return crypto.timingSafeEqual(expected, sig);
  }

  return crypto.verify(
    'RSA-SHA256',
    Buffer.from(data),
    key,
    sig
  );
}

async function verifyJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed JWT');

  const header  = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));

  debug('HEADER:', header);
  debug('PAYLOAD:', payload);

    // ---- alg: none vulnerability
  if (
    global.vulnerabilities.allowNone &&
    header.alg === 'none'
  ) {
    debug('Allowing unsigned JWT (alg=none)');
    return payload;
  }

  const cfg = await verificationConfig(header);
  if (!verifySignature(parts, cfg)) {
    throw new Error('Invalid signature');
  }

  if (
    !global.vulnerabilities.disableExpiration &&
    payload.exp &&
    payload.exp < Math.floor(Date.now() / 1000)
  ) {
    throw new Error('Expired');
  }

  return payload;
}

function decodeJWT(token) {
  return JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString()
  );
}

module.exports = {
  createJWT,
  verifyJWT,
  decodeJWT,
  getJWKS: getLocalJWKS
};