const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const { generateToken } = require('../utils/jwt');

const router = express.Router();

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ msg: 'Missing credentials' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashed });
    await user.save();
    res.json({ msg: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ msg: 'Error registering user', error: err.message });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: 'Invalid credentials' });
    const token = generateToken({ username: user.username }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    res.status(500).json({ msg: 'Login error', error: err.message });
  }
});

module.exports = router;