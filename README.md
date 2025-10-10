# JWT Auth Demo (Secure-by-Default with Individual Vulnerability Flags)

A Node.js application demonstrating a secure-by-default JWT system with specific vulnerabilities enabled via command-line flags (`--allow-none`, `--weak-secret`, `--no-expiration`, `--allow-alg-confusion`) for educational purposes.

## Features
- User registration and login with custom JWT implementation
- Protected profile route
- MongoDB for user storage
- Secure JWT handling by default (HMAC-SHA256, expiration checks, strong secret)
- Individual vulnerability toggles for educational demos

## Setup
1. Clone the repository
2. Install dependencies: `npm install`
3. Set up MongoDB locally or use a cloud instance
4. Create a `.env` file with:
PORT=3000 MONGODB_URI=mongodb://localhost:27017/jwt-auth-demo JWT_SECRET=your_strong_jwt_secret_key_here_32_chars_minimum
5. Run the application:
- Secure mode: `npm start` or `node src/app.js`
- Vulnerable modes (combine as needed):
  - `node src/app.js --allow-none` (allows 'none' algorithm)
  - `node src/app.js --weak-secret` (allows weak secret)
  - `node src/app.js --no-expiration` (skips expiration checks)
  - `node src/app.js --allow-alg-confusion` (allows algorithm confusion)
  - Example: `node src/app.js --allow-none --allow-alg-confusion`

## UI Access
- Root (`/`): Redirects to `/login`.
- Login: `http://localhost:4443/login`
- Register: `http://localhost:4443/register`
- Profile: `http://localhost:4443/profile` (requires login)

## Endpoints
- POST `/api/auth/register` - Register a new user
- POST `/api/auth/login` - Login and receive a JWT
- GET `/api/user/profile` - Access protected profile (requires JWT in Authorization header)

## Secure-by-Default Features
- Uses HMAC-SHA256 for signing
- Enforces token expiration (1 hour by default)
- Requires a strong secret (minimum 32 characters)
- Validates algorithm (rejects 'none' and non-HS256)

## Vulnerabilities (Enabled Individually)
The `src/utils/jwtHandler.js` file supports the following vulnerabilities when enabled:
- **'none' Algorithm** (`--allow-none`):
- **Description**: Allows tokens with no signature.
- **Exploit**: Forge tokens by setting `alg: 'none'` and omitting the signature.
- **Expansion**: Add tests to submit forged tokens or log unauthorized access attempts.
- **Weak Secret** (`--weak-secret`):
- **Description**: Falls back to a weak secret ('secret') if none provided or too short.
- **Exploit**: Brute-force the secret to forge or decode tokens.
- **Expansion**: Implement a brute-force attack script or use a dictionary attack.
- **No Expiration Check** (`--no-expiration`):
- **Description**: Skips token expiration validation.
- **Exploit**: Replay old tokens to gain unauthorized access.
- **Expansion**: Store tokens in a database to demonstrate replay attacks or add revocation.
- **Algorithm Confusion** (`--allow-alg-confusion`):
- **Description**: Allows tokens signed with non-HS256 algorithms (e.g., RS256) without validation.
- **Exploit**: Sign a token with RS256 using a public key, then use that public key as the HMAC secret.
- **Expansion**: Generate RSA key pairs and demonstrate forging tokens with a public key.

## Educational Experiments
To expand on vulnerabilities:
- **Algorithm Confusion**: Use a tool like `jwt.io` to create an RS256-signed token and test verification with the public key as the secret.
- **Weak Hashing**: Replace HMAC-SHA256 with a weaker algorithm (e.g., MD5) in `jwtHandler.js`.
- **Token Leakage**: Simulate logging sensitive token data to demonstrate information disclosure.
- **No Secret Validation**: Allow shorter secrets in `verifyJWT` to test weaker configurations.

## Fixes to Implement
- Add refresh tokens to reduce long-lived token risks.
- Implement token revocation (e.g., blacklist in MongoDB).
- Enforce stricter algorithm validation.
- Use environment-specific secrets (e.g., different secrets for dev/prod).

## Usage
1. Register: `POST /api/auth/register` with `{ "email": "user@example.com", "password": "password123" }`
2. Login: `POST /api/auth/login` with the same credentials
3. Access profile: `GET /api/user/profile` with header `Authorization: Bearer <token>`

## Testing Vulnerabilities
1. **'none' Algorithm**:
- Start: `node src/app.js --allow-none`
- Modify `authController.js` to pass `{ alg: 'none' }` to `createJWT`.
- Test accessing `/api/user/profile` with the unsigned token.
2. **Weak Secret**:
- Start: `node src/app.js --weak-secret`
- Set `JWT_SECRET=secret` in `.env` or omit it.
- Attempt to brute-force the secret using a script.
3. **No Expiration**:
- Start: `node src/app.js --no-expiration`
- Generate a token, wait past its expiration, and try reusing it.
4. **Algorithm Confusion**:
- Start: `node src/app.js --allow-alg-confusion`
- Generate an RS256-signed token (e.g., using `jwt.io` or a script) with a public key.
- Set `JWT_SECRET` to the public key and test accessing `/api/user/profile`.

This project is for educational purposes only. Do not use in production.
