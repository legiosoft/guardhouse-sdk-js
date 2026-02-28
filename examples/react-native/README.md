# React Native Example

This example demonstrates `@guardhouse/react-native` with a direct `GuardhouseClient` integration (no provider/hook wrapper).

It includes:

- OAuth Authorization Code + PKCE login
- Browser registration flow with `returnUrl` handoff
- Passkey login
- Refresh/logout
- Deep-link callback handling
- Expo browser + secure storage adapters

## Quick start

1. Copy env template:

```bash
cp .env.example .env
```

2. Fill `.env` with your Guardhouse values.

Minimum values:

```env
GH_AUTHORITY=https://your-guardhouse-domain.com
GH_CLIENT_ID=your-client-id
GH_REDIRECT_URI=com.example.guardhouse://callback
GH_AUTHORIZATION_ENDPOINT=/connect/authorize
GH_REGISTRATION_ENDPOINT=/account/signup?returnUrl=
GH_TOKEN_ENDPOINT=/connect/token
GH_REVOCATION_ENDPOINT=/connect/revocation
```

3. Install dependencies:

```bash
npm install
```

4. Typecheck:

```bash
npm run typecheck
```

5. Run:

```bash
npm start
```

## Registration `returnUrl` behavior

The example and SDK are configured so registration can start at:

`/account/signup?returnUrl=`

The SDK detects the `returnUrl` query key and injects a full authorize URL into it. This keeps the flow inside the auth session and returns to your app deep link callback instead of leaving users in Safari.

## Redirect URI modes

- `GH_REDIRECT_URI=auto`
  - Useful for Expo Go while iterating.
- `GH_REDIRECT_URI=com.example.guardhouse://callback`
  - Recommended for dev builds / production-style testing.

Your app scheme is configured in `app.json`:

- `examples/react-native/app.json`

If you change the redirect URI scheme, update both `GH_REDIRECT_URI` and `app.json` to match.

## Important runtime notes

- Browser auth uses `examples/react-native/src/expoWebBrowserAdapter.ts` (`openAuthSessionAsync`).
- Token/session storage adapters are wired in `examples/react-native/App.tsx`.
- Main app flow is in `examples/react-native/App.tsx`.

## Troubleshooting

- If registration/login opens external Safari and does not return:
  - Ensure `GH_REGISTRATION_ENDPOINT` includes `?returnUrl=`.
  - Ensure `GH_REDIRECT_URI` is registered and matches app scheme.
  - Restart Metro with cache clear:

```bash
npx expo start -c
```

- If you changed local SDK/core code, rebuild from repo root before running example:

```bash
npm run build -w @guardhouse/core
npm run build -w @guardhouse/react-native
```
