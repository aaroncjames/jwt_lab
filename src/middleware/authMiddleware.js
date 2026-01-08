// src/middleware/auth.js
const { verifyJWT, decodeJWT } = require('../utils/jwtHandler');  // ← Add decodeJWT

module.exports = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing token' });
  }

  const token = authHeader.split(' ')[1];
  const vuln = global.vulnerabilities || {};

  try {
    let payload;

    if (vuln.disableValidation) {
      console.log('⚠️  --disable-validation: SKIPPING signature check');
      payload = decodeJWT(token);  // ← Only decode, no verify
    } else {
      console.log('Verifying token...');
      payload = await verifyJWT(token);  // ← Full verify
    }

    if (!payload.sub) {
      throw new Error('No user ID (sub) in JWT payload');
    }

    req.user = payload;
    console.log('JWT Payload:', req.user);

    next();
  } catch (err) {
    console.error('JWT failed:', err.message);
    return res.status(401).json({ message: 'Invalid token', error: err.message });
  }
};