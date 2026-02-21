# React Example

This example shows `@guardhouse/react` in a Vite app with login, logout, protected screens, and API calls.

## Features

- Authorization Code + PKCE login flow
- Session restore on page load
- Protected route demo
- Protected API call demo
- Environment-based config via `.env`

## Setup

1. Copy env template:

```bash
cp .env.example .env
```

2. Fill `.env` with your test identity server values:

```env
VITE_AUTHORITY=https://your-test-identity-server
VITE_CLIENT_ID=your-client-id
VITE_REDIRECT_URI=http://localhost:5173
VITE_SCOPE=openid profile email offline_access
VITE_API_BASE_URL=http://localhost:3001
```

3. Install dependencies:

```bash
npm install
```

## Run

- `npm start` (alias of `vite`)
- `npm run dev`

App URL: `http://localhost:5173`

## Build

```bash
npm run build
npm run preview
```

## API demo

The API demo calls `${VITE_API_BASE_URL}/protected` with the access token.
Run `examples/node` server to test end-to-end.
