// src/middleware/auth.js
const { verifyJWT } = require('../utils/jwtHandler');  // Your custom one

module.exports = async function (req, res, next) {  // Make async for await verifyJWT
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('❌ Missing Bearer header');  // Temp log
    return res.status(401).json({ message: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.split('Bearer ')[1];  // Fix: space after Bearer

  try {
    console.log('🔍 Verifying token...');  // Temp log
    const payload = await verifyJWT(token);  // Await our async custom func
    console.log('✅ Payload claims:', payload);  // Temp: See sub, iat, exp, etc.

    // FIX: Use 'sub' (JWT standard) instead of 'id'
    if (!payload.sub) {
      throw new Error('No user ID (sub) in JWT payload');
    }
    req.user = payload;  // Attach as string for Mongoose
    console.log('✅ Attached req.user:', req.user);  // Temp log

    next();
  } catch (err) {
    console.error('💥 JWT verification failed:', err.message);  // Better logging
    return res.status(401).json({ message: 'Invalid token', error: err.message });
  }
};
