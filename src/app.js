const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const yargs = require('yargs');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const { connectDB } = require('./config/db');

// Parse command-line arguments
const argv = yargs
  .option('allow-none', {
    type: 'boolean',
    description: 'Allow "none" algorithm for JWT (vulnerable)',
    default: false,
  })
  .option('weak-secret', {
    type: 'boolean',
    description: 'Allow weak JWT secret (vulnerable)',
    default: false,
  })
  .option('no-expiration', {
    type: 'boolean',
    description: 'Skip JWT expiration checks (vulnerable)',
    default: false,
  })
  .option('allow-alg-confusion', {
    type: 'boolean',
    description: 'Allow algorithm confusion for JWT (vulnerable)',
    default: false,
  }).argv;

dotenv.config();
const app = express();

// Middleware
app.use(express.json());

// Make vulnerability flags available globally
global.vulnerabilities = {
  allowNone: argv['allow-none'],
  weakSecret: argv['weak-secret'],
  noExpiration: argv['no-expiration'],
  allowAlgConfusion: argv['allow-alg-confusion'],
};
console.log('Vulnerability settings:', global.vulnerabilities);

// Connect to MongoDB
connectDB();

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
