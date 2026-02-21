# Node.js Example

This example is an Express server that demonstrates how to use `@guardhouse/core` and `@guardhouse/node` for OAuth flows and protected APIs.

## What it includes

- Authorization Code + PKCE login URL generation
- Callback handler with `state` validation and token exchange
- Client Credentials token endpoint
- Refresh token endpoint
- Protected API endpoint for frontend/mobile examples
- User info endpoint with bearer token

## Setup

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Fill your identity server values in `.env`:

```env
AUTHORITY=https://your-test-identity-server
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
REDIRECT_URI=http://localhost:3001/callback
SCOPE=openid profile email offline_access
AUDIENCE=your-api-audience
PORT=3001
CORS_ORIGINS=http://localhost:5173
```

3. Install dependencies:

```bash
npm install
```

## Run

```bash
npm run dev
```

Server starts on `http://localhost:3001` (or your `PORT`).

## Endpoints

- `GET /` server metadata
- `GET /login` returns `authUrl` and generated `state`
- `GET /callback` exchanges auth code for tokens and returns redacted token data
- `POST /token` supports:
  - `grant_type=client_credentials`
  - `grant_type=refresh_token` with `refresh_token`
- `GET /user` requires `Authorization: Bearer <token>`
- `GET /protected` requires `Authorization: Bearer <token>`

## Quick test

```bash
curl http://localhost:3001/login
curl -X POST http://localhost:3001/token -H "Content-Type: application/json" -d "{\"grant_type\":\"client_credentials\"}"
```

Use a real user token (from auth code flow) against `/user` and `/protected`.
