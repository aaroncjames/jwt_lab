// src/routes/user.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const { getProfile } = require('../controllers/userController');

// Protected route
router.get('/profile', auth, getProfile);  // If getProfile undefined then it will throw an error

module.exports = router; 