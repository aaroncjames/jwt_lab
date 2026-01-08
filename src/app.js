const express = require('express');
const dotenv = require('dotenv');
dotenv.config();
const yargs = require('yargs');
const path = require('path');
const { connectDB } = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const { getJWKS } = require('./utils/jwtHandler');


const app = express();

// Parse command-line arguments
const argv = yargs
  .option('disable-validation', { type: 'boolean', default: false, description: 'Disable validation of JWT signatures' })
  .option('weak-secret', { type: 'boolean', default: false, description: 'Sign tokens with weak secret' })
  .option('allow-none', { type: 'boolean', default: false, description: 'Allow the use of the none algorithm' })
  .option('disable-expiration', { type: 'boolean', default: false, description: 'Skip validating exp claim' })
  .option('alg-confusion', { type: 'boolean', default: false, description: 'Validate tokens with public HMAC key'})
  .option('jku-injection', {type: 'boolean', default: false, description: 'Validate tokens with remote JWKS'})
  .option('jwk-injection', {type: 'boolean', default: false, description: 'Validate tokens with embedded JWKS' })
  .option('kid-injection', {type: 'boolean', default: false, description: 'Load a key via kid path traversal' })
  .option('x5u-injection', {type: 'boolean', default: false, description: 'Validate tokens with remote PEM' })
  .argv;

// Validate for conflicts
function validateArgs(args) {
  if (args['weak-secret'] && args['alg-confusion']) {
    throw new Error('Cannot enable both weak HMAC and algorithm confusion – they conflict (symmetric vs. asymmetric signing).');
  }
  // Add more conflict checks, e.g.:
  // if (args['none-algo'] && args['strong-rsa']) { throw new Error('...'); }
}

// Run validation
try {
  validateArgs(argv);
} catch (error) {
  console.error('Invalid arguments:', error.message);
  process.exit(1); // Exit early
}

global.vulnerabilities = {
  disableValidation: argv['disable-validation'],
  weakSecret: argv['weak-secret'],
  allowNone: argv['allow-none'],
  disableExpiration: argv['disable-expiration'],
  algConfusion: argv['alg-confusion'],
  jkuInjection: argv['jku-injection'],
  jwkInjection: argv['jwk-injection'],
  kidInjection: argv['kid-injection'],
  x5uInjection: argv['x5u-injection'],
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
app.get('/.well-known/jwks.json', (req, res) => {
  res.json(getJWKS());
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running: http://127.0.0.1:${PORT}`);
});