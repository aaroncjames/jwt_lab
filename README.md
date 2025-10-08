# JWT Practice App

A simple Node.js + Express + MongoDB project to learn about implementing and handling JSON Web Tokens manually.

## Setup

1. Copy `.env.example` to `.env` and configure values.
2. Run `npm install`
3. Start MongoDB locally (e.g., `mongod`)
4. Run the server: `npm start`

## Endpoints
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/profile` (requires JWT in Authorization header)
