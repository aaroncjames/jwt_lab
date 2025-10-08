const express = require('express');
const { verifyToken } = require('../utils/jwt');

const router = express.Router();

router.get('/', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ msg: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = verifyToken(token, process.env.JWT_SECRET);
    res.json({ msg: 'Welcome to your profile!', user: decoded });
  } catch (err) {
    res.status(401).json({ msg: 'Invalid or expired token', error: err.message });
  }
});

module.exports = router;