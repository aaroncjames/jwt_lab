// src/controllers/authController.js
const bcrypt = require('bcryptjs');
const User   = require('../models/userModel');
const { createJWT } = require('../utils/jwtHandler');

// -----------------------------------------------------------------
// Register
// -----------------------------------------------------------------
exports.register = async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user   = await User.create({ email, password: hashed });

    const payload = { sub: user._id.toString(), email: user.email };
    const token   = await createJWT(payload, 3600); // 1 hour

    res.status(201).json({ token, user: { id: user._id, email } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

// -----------------------------------------------------------------
// Login
// -----------------------------------------------------------------
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const payload = { sub: user._id.toString(), email: user.email };
    const token   = await createJWT(payload, 3600); // 1 hour

    res.json({ token, user: { id: user._id, email } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};