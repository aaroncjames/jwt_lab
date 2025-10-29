// src/utils/jwtHandler.js
/* --------------------------------------------------------------
   Tiny, pure‑crypto JWT handler – RS256 default, HS256 only for vulns
   -------------------------------------------------------------- */
   const crypto = require('crypto');
   const fs    = require('fs');
   const path  = require('path');
   
   const PRIV_PATH = path.resolve(__dirname, '../../certs/private.pem');
   const PUB_PATH  = path.resolve(__dirname, '../../certs/public.pem');
   
   let privKey, pubKey;
   function getPriv() { return privKey ??= fs.readFileSync(PRIV_PATH, 'utf8'); }
   function getPub()  { return pubKey  ??= fs.readFileSync(PUB_PATH,  'utf8'); }
   
   /* ----------------------- BASE64URL -------------------------- */
   const b64url = (buf) =>
     buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
   
   /* -------------------------- CREATE -------------------------- */
   function signingConfig(rawPayload, expiresInSeconds = 3600) { // default: 1 hour
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + expiresInSeconds;
    const claims = { ...rawPayload, iat, exp };

     // HS256 only when a vuln flag demands it
     if (global.vulnerabilities.weakSecret) {
       console.log('using weak secret') // temporary debug
       return { alg: 'HS256', key: Buffer.from(global.vulnerabilities.weakSecret ? process.env.JWT_SECRET_WEAK : process.env.JWT_SECRET || 'fallback'), claims };
     }
     // DEFAULT: RS256
     return { alg: 'RS256', key: getPriv(), claims };
   }
   
   function sign(header, payload, { alg, key }) {
     const h = b64url(Buffer.from(JSON.stringify(header)));
     const p = b64url(Buffer.from(JSON.stringify(payload)));
     const data = `${h}.${p}`;
   
     let sig;
     console.log('using alg:', alg) // temporary debug
     if (alg === 'HS256') {
       sig = b64url(crypto.createHmac('sha256', key).update(data).digest());
     } else {
       const s = crypto.createSign('RSA-SHA256');
       s.update(data);
       s.end();
       sig = b64url(s.sign(key, 'base64'));
     }
     return `${data}.${sig}`;   // ← pure string
   }
   
   async function createJWT(rawPayload, expiresInSeconds) {
    const { alg, key, claims } = signingConfig(rawPayload, expiresInSeconds);
    const header = { alg, typ: 'JWT' };
    return sign(header, claims, { alg, key });
  }
   
   /* -------------------------- VERIFY -------------------------- */
  function verificationConfig(header) {
    const alg = header.alg ?? 'RS256';
   
    if (global.vulnerabilities.allowNone && alg === 'none') return { skipSig: true };
   
     // THIS WAS ORIGINAL ALG CONFUSION CODE - SAVING FOR REFERENCE
     //if (global.vulnerabilities.allowAlgConfusion && alg === 'HS256') {
     //  const pub = getPub().replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, '');
     //  return { alg: 'HS256', key: Buffer.from(pub, 'base64') };
     //}

    if (alg === 'HS256') {
      let key;
  
      if (global.vulnerabilities.allowAlgConfusion) {
        key = getPub();                                          // Option 3
      } else if (global.vulnerabilities.weakSecret) {
        key = process.env.JWT_SECRET_WEAK || 'secret';           // Option 2
      } else {
        key = process.env.JWT_SECRET || 'fallback-strong';       // Option 1
      }
  
      const finalKey = typeof key === 'string' ? Buffer.from(key) : key;
      return { alg: 'HS256', key: finalKey };
    }
   
     if (alg === 'RS256') return { alg: 'RS256', key: getPub() };
     
     // THIS WAS ORIGINAL HS256 HANDLING - SAVING FOR REFERENCE
     // if (alg === 'HS256') return { alg: 'HS256', key: Buffer.from(process.env.JWT_SECRET || 'fallback') };
   
     throw new Error(`Unsupported alg ${alg}`);
  }
   
   function verifySignature(parts, { alg, key, skipSig }) {
     const [h, p, s] = parts;
     const data = `${h}.${p}`;
     if (skipSig) return true;
   
     const sig = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
   
     if (alg === 'HS256') {
        console.log('key:', key);
       const expected = crypto.createHmac('sha256', key).update(data).digest();
       return crypto.timingSafeEqual(expected, sig);
     }
   
     const v = crypto.createVerify('RSA-SHA256');
     v.update(data);
     v.end();
     return v.verify(key, sig);
   }
   
   async function verifyJWT(token) {
     const parts = token.split('.');
     if (parts.length !== 3) throw new Error('Malformed JWT');
   
     const header  = JSON.parse(Buffer.from(parts[0], 'base64url'));
     const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
   
     const cfg = verificationConfig(header);
     const ok  = verifySignature(parts, cfg);
     if (!ok) throw new Error('Invalid signature');
   
     const now = Math.floor(Date.now() / 1000);
     if (!global.vulnerabilities.disableExpiration && payload.exp && payload.exp < now) throw new Error('Expired');
     if (!global.vulnerabilities.skipIssuedAt && payload.iat && payload.iat > now + 60) throw new Error('Future token');
   
     return payload;
   }

   function decodeJWT(token) {
    const [headerB64, payloadB64] = token.split('.');
    if (!payloadB64) throw new Error('Invalid token format');
  
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    return payload;
  }
   
   /* -------------------------- EXPORT -------------------------- */
   module.exports = { createJWT, verifyJWT, decodeJWT};