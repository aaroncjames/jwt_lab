# JWT Auth Demo – Vulnerable by Design

## Overview

This project is a deliberately vulnerable JWT-based authentication application intended for **security training and experimentation**.

It demonstrates a variety of **real-world JWT implementation flaws**, including algorithm confusion, weak secrets, header injection attacks, and improper validation behavior.

This was created to accompany the cheat sheet at https://trustedsec.com/blog/<BLOG URL>

The application is designed to be run either **locally** or via **Docker Compose**.

> ⚠️ **Warning:** This application is intentionally insecure.

> Do **not** deploy it in production or expose it to untrusted networks.

---
## Vulnerabilities Implemented

The application supports enabling or disabling vulnerabilities at runtime using command-line flags.

| Flag | Description |

|----|----|

| `--disable-validation` | Skips JWT signature verification entirely |

| `--allow-none` | Accepts unsigned tokens using `alg: none` |

| `--weak-secret` | Signs and validates tokens with a weak HMAC secret |

| `--disable-expiration` | Token expiration checks are skipped |

| `--alg-confusion` | Allows RSA public key to be misused as an HMAC secret |

| `--kid-injection` | Allows `kid` path traversal to load HMAC secrets from disk |

| `--jku-injection` | Allows attacker-controlled remote JWKS via `jku` header |

| `--x5u-injection` | Allows attacker-controlled remote JWKS via `x5u` header |

| `--jwk-injection` | Allows embedded `jwk` header to supply verification key |


> Multiple flags may be combined unless explicitly disallowed.
---
## Prerequisites

### For Local Runs

- Node.js (v18+ recommended)

- MongoDB running locally

- npm or yarn
### For Docker Runs

- Docker

- Docker Compose (v2+)

---
## Installation

### Clone the Repository

```bash

git clone https://github.com/yourusername/jwt-auth-demo.git

cd jwt-auth-demo

```

### Configuration

Environment variables are required to run the application.

Create an Environment File

```
cp .env.example .env
```

Edit .env as needed. In particular, pay attention to the MONGODB_URI value, for local runs it should point to your local MongoDB (e.g. ```MONGODB_URI=mongodb://127.0.0.1:27017/jwt-auth-demo```) and for Docker runs it should point to ```
MONGODB_URI=mongodb://mongo:27017/jwt-auth-demo```. The .env.example file notes this as well.
### Running the Application

#### Option 1: Run Locally

Ensure MongoDB is running locally

Set MONGODB_URI to localhost in .env

Start the app:
```
node app.js --alg-confusion
```
  
#### Option 2: Run with Docker (Recommended)

Ensure MONGODB_URI is set to mongo in .env

Build and run:
```
docker compose up --build
```
  
Access the app: http://localhost:4443
### JWT Debugging

JWT debugging output can be enabled by setting:

```
DEBUG_JWT=true
```

This will print detailed verification and key-selection logs to the console.
## Disclaimer

This software is provided for educational purposes only.

The author assumes no responsibility for misuse of this code or any damages resulting from its use.