# JWT Auth Demo – Vulnerable by Design

## Overview

This project is a deliberately vulnerable JWT-based authentication application intended for **security training and experimentation**.

It demonstrates a variety of **real-world JWT implementation flaws**, including algorithm confusion, weak secrets, header injection attacks, and improper validation behavior.  
The application is designed to be run either **locally** or via **Docker Compose**.

> ⚠️ **Warning:** This application is intentionally insecure.  
> Do **not** deploy it in production or expose it to untrusted networks.

---

## Features

- Node.js + Express authentication API
- MongoDB-backed user storage
- Custom JWT implementation (no third-party JWT libraries)
- Toggleable vulnerabilities via command-line flags
- JWKS endpoint (`/.well-known/jwks.json`)
- Dockerized for easy setup

---

## Vulnerabilities Implemented

The application supports enabling or disabling vulnerabilities at runtime using command-line flags.

| Flag | Description |
|----|----|
| `--disable-validation` | Skips JWT signature verification entirely |
| `--allow-none` | Accepts unsigned tokens using `alg: none` |
| `--weak-secret` | Signs and validates tokens with a weak HMAC secret |
| `--alg-confusion` | Allows RSA public key to be misused as an HMAC secret |
| `--kid-injection` | Allows `kid` path traversal to load HMAC secrets from disk |
| `--jku-injection` | Allows attacker-controlled remote JWKS via `jku` header |
| `--jwk-injection` | Allows embedded `jwk` header to supply verification key |

> Multiple flags may be combined unless explicitly disallowed.

---

## Architecture Overview

- **Backend:** Node.js / Express
- **Database:** MongoDB
- **Auth:** Custom JWT handler (`utils/jwtHandler.js`)
- **Key Material:** RSA keys stored in `certs/`
- **Deployment:** Docker + Docker Compose

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
Configuration

Environment variables are required to run the application.

Create an Environment File
cp .env.example .env


Edit .env as needed.

.env, .env.local, and .env.docker are intentionally gitignored.

Running the Application
Option 1: Run Locally

Ensure MongoDB is running locally

Set MONGODB_URI to localhost in .env

Start the app:

node app.js --alg-confusion

Option 2: Run with Docker (Recommended)

Ensure MONGODB_URI is set to mongo in .env

Build and run:

docker compose up --build


Access the app:

http://localhost:4443

JWT Debugging

JWT debugging output can be enabled by setting:

DEBUG_JWT=true


This will print detailed verification and key-selection logs to the console.

Usage Notes

Tokens are issued on login

Protected routes require an Authorization: Bearer <token> header

Vulnerabilities only activate when their corresponding flags are enabled

Some attacks require crafting tokens manually (e.g., Burp Suite JWT Editor)

Educational Goals

This project is intended to help learners:

Understand how JWTs actually work under the hood

Identify common JWT implementation mistakes

Practice exploiting JWT vulnerabilities in a controlled environment

Learn how configuration and deployment affect security

Non-Goals

Production-ready security

Hardened authentication

OAuth / OpenID Connect compliance

Disclaimer

This software is provided for educational purposes only.

The author assumes no responsibility for misuse of this code or any damages resulting from its use.