const express = require('express');
const dotenv = require('dotenv');
const yargs = require('yargs');
const path = require('path');
const { connectDB } = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

dotenv.config();
const app = express();

// Parse command-line arguments
const argv = yargs
  .option('no-validation', { type: 'boolean', default: false })
  .option('weak-secret', { type: 'boolean', default: false })
  .option('allow-none', { type: 'boolean', default: false })
  .option('no-expiration', { type: 'boolean', default: false })
  .option('allow-alg-confusion', { type: 'boolean', default: false })
  .option('embedded-jku', {type: 'boolean', default: false })
  .option('embedded-jwk', {type: 'boolean', default: false })
  .option('embedded-kid', {type: 'boolean', default: false })
  .argv;

global.vulnerabilities = {
  noValidation: argv['no-validation'],
  weakSecret: argv['weak-secret'],
  allowNone: argv['allow-none'],
  noExpiration: argv['no-expiration'],
  allowAlgConfusion: argv['allow-alg-confusion'],
  embeddedJku: argv['embedded-jku'],
  embeddedJwk: argv['embedded-jwk'],
  embeddedKid: argv['embedded-kid'],
};
console.log('Vulnerability settings:', global.vulnerabilities);

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());

// Serve static files from public/
app.use(express.static(path.join(__dirname, '../public')));

// UI Routes
app.get('/', (req, res) => {
  res.redirect('/login');
});
app.get('/login', (req, res) => {
  console.log('Serving login.html from:', path.join(__dirname, '../public/login.html'));
  res.sendFile(path.join(__dirname, '../public/login.html'));
});
app.get('/register', (req, res) => {
  console.log('Serving register.html from:', path.join(__dirname, '../public/register.html'));
  res.sendFile(path.join(__dirname, '../public/register.html'));
});
app.get('/profile', (req, res) => {
  console.log('Serving profile.html from:', path.join(__dirname, '../public/profile.html'));
  res.sendFile(path.join(__dirname, '../public/profile.html'));
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});