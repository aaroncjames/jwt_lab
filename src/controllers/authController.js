const bcrypt = require('bcryptjs');
const User = require('../models/userModel');
const { createJWT } = require('../utils/jwtHandler');

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const payload = { id: user._id };
    const token = createJWT(payload, process.env.JWT_SECRET, { expiresIn: 3600 });

    res.json({ token });
  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.register = async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    console.error('Register error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
};
