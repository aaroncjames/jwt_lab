const crypto = require('crypto');

function base64url(input) {
  return Buffer.from(input).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function sign(data, secret) {
  return base64url(crypto.createHmac('sha256', secret).update(data).digest());
}

function generateToken(payload, secret, expiresInSec = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + expiresInSec;
  const tokenPayload = { ...payload, exp };

  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(tokenPayload));
  const signature = sign(`${headerB64}.${payloadB64}`, secret);

  return `${headerB64}.${payloadB64}.${signature}`;
}

function verifyToken(token, secret) {
  const [headerB64, payloadB64, signature] = token.split('.');
  const validSig = sign(`${headerB64}.${payloadB64}`, secret);
  if (signature !== validSig) throw new Error('Invalid signature');
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
  return payload;
}

module.exports = { generateToken, verifyToken };