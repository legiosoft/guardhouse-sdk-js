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
VITE_REDIRECT_URI=http://localhost:3000
VITE_POST_LOGOUT_REDIRECT_URI=http://localhost:3000
VITE_SCOPE=openid profile email offline_access
VITE_AUDIENCE=
VITE_ALLOW_AUTH_WITHOUT_AUDIENCE=true
VITE_ALLOW_OFFLINE_ACCESS_SCOPE=true
VITE_API_BASE_URL=http://localhost:3001
```

3. Install dependencies:

```bash
npm install
```

## Run

- `npm start` (alias of `vite`)
- `npm run dev`

App URL: `http://localhost:3000`

## Build

```bash
npm run build
npm run preview
```

## API demo

The API demo calls `${VITE_API_BASE_URL}/protected` with the access token.
Run `examples/node` server to test end-to-end.

## Security defaults in this example

- Uses `@guardhouse/react` session storage only; tokens are not stored in `localStorage`.
- Uses `allowAuthorizationWithoutAudience=true` by default for providers (like OpenIddict defaults) that reject `audience` in authorization requests.
- If your provider supports resource indicators, set `VITE_AUDIENCE` and optionally set `VITE_ALLOW_AUTH_WITHOUT_AUDIENCE=false`.
- Keeps `allowOfflineAccessScope=true` when requesting `offline_access`.
- `VITE_REDIRECT_URI` must exactly match an allowed redirect URI on the client in Guardhouse/OpenIddict.
- `VITE_POST_LOGOUT_REDIRECT_URI` must exactly match an allowed post-logout redirect URI on the client.
- Token requests omit `scope` by default, which matches OpenIddict expectations for authorization-code exchanges.
- Logout is sent to `/connect/logout` by default (via `@guardhouse/core`).

## Troubleshooting

- `ID2043` (`redirect_uri` invalid): make sure `VITE_REDIRECT_URI` exactly matches the client registration (including slash/path differences).
- `ID2052` (`post_logout_redirect_uri` invalid): make sure `VITE_POST_LOGOUT_REDIRECT_URI` exactly matches the client's allowed post-logout URI.
- `ID2074` (`scope` invalid at token endpoint): this example already omits `scope` in token requests; ensure you rebuilt/restarted after updates.
- `ID2193` (`audience` not allowed): keep `VITE_AUDIENCE` empty and `VITE_ALLOW_AUTH_WITHOUT_AUDIENCE=true`.
- After changing `.env`, restart the Vite dev server so new values are loaded.
