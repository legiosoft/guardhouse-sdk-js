# React Native Example

This example demonstrates `@guardhouse/react-native` with a direct `GuardhouseClient` integration (no provider/hook wrapper).

It includes:

- OAuth Authorization Code + PKCE login
- Browser registration flow with `returnUrl` handoff
- Passkey login
- Refresh/logout
- Deep-link callback handling
- Expo browser + secure storage adapters
- Web Crypto bootstrap for signed ID-token verification (native development build)

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
GH_REVOCATION_ENDPOINT=/connect/revoke
```

3. Use Node 22 and install the locked dependencies:

```bash
npm ci
```

4. Typecheck:

```bash
npm run typecheck
```

5. Build and run the native development client (iOS requires macOS/Xcode):

```bash
npx expo run:android
# or, on macOS:
npx expo run:ios
```

For subsequent Metro sessions use `npm run start:dev-client`. Rebuild the native
app after changing native dependencies. Stock Expo Go cannot load this example's
OIDC crypto provider.

## Signed ID-token verification

`index.js` imports `src/installCrypto.ts` before App. The bootstrap calls
`react-native-quick-crypto`'s `install()` to provide Web Crypto for Core/jose. The
example pins Quick Crypto 1.1.7, Nitro Modules 0.33.2 and Quick Base64 3.0.1, enables
the New Architecture, and registers the Expo config plugin in `app.json`.

The existing `expoCryptoAdapter` remains a PKCE adapter only; it is not a
replacement for `crypto.subtle.importKey/verify`. The SDK reports `CONFIG_ERROR`
before OIDC interaction if these required methods are missing. The provider must
also support your issuer's signing algorithm; the SDK never disables signature
verification to accommodate an unsupported runtime.

On both Android and iOS verify login → refresh with an ID token → app restart →
refresh without an ID token → app restart → logout. Use a test issuer to check
that a wrongly signed ID token is rejected. These device checks are required in
addition to TypeScript and the Node-based SDK tests.

## Registration `returnUrl` behavior

The example and SDK are configured so registration can start at:

`/account/signup?returnUrl=`

The SDK detects the `returnUrl` query key and injects a full authorize URL into it. This keeps the flow inside the auth session and returns to your app deep link callback instead of leaving users in Safari.

## Redirect URI modes

- `GH_REDIRECT_URI=auto`
  - Derives the callback from the development build's configured scheme.
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
