// src/routes/user.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');  // Your middleware
const { getProfile } = require('../controllers/userController');  // ← Import here

// Temp debug: Log if getProfile loaded
console.log('🔍 Imported getProfile type:', typeof getProfile);  // Should be 'function'

// Protected route
router.get('/profile', auth, getProfile);  // ← If getProfile undefined → error

module.exports = router;  // Export the router