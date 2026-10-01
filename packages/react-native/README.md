# @guardhouse/react-native

React Native SDK for Guardhouse OAuth 2.0 Authorization Code + PKCE, passkey authentication, and secure token lifecycle.

## Installation

```bash
npm install @guardhouse/react-native@1.0.2-beta.1
```

### Peer dependencies

- `react >=18.0.0`
- `react-native >=0.70.0`
- `react-native-quick-crypto >=0.7.0` (optional PKCE provider; this peer range does
  not guarantee OIDC/Web Crypto support — see the runtime setup below)

### Required native modules

- `react-native-keychain` – secure token storage
- `react-native-inappbrowser-reborn` – in-app browser auth sessions

```bash
npm install react-native-keychain react-native-inappbrowser-reborn
cd ios && pod install
```

## Platform setup

### iOS

1. Add URL scheme to `ios/YourApp/Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>com.yourapp</string>
    </array>
  </dict>
</array>
```

2. Add to `ios/Podfile`:

```ruby
pod 'RNInAppBrowser', :path => '../node_modules/react-native-inappbrowser-reborn'
```

3. Run `pod install`.

### Android

1. Add intent filter to `android/app/src/main/AndroidManifest.xml`:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data
    android:scheme="com.yourapp"
    android:host="callback" />
</intent-filter>
```

2. Set `launchMode="singleTask"` on your main activity (required to prevent task hijacking):

```xml
<activity
  android:name=".MainActivity"
  android:launchMode="singleTask"
  ...>
```

## Quick start

```tsx
import {
  GuardhouseClient,
  KeychainStorageAdapter,
} from "@guardhouse/react-native";

const client = new GuardhouseClient({
  authority: "https://your-guardhouse-domain.com",
  clientId: "your-client-id",
  redirectUri: "com.yourapp://callback",
  scope: "openid profile offline_access",
  refreshTokenStorage: new KeychainStorageAdapter(),
  browser: yourBrowserAdapter, // see Adapters section
});
```

### Login

```tsx
const result = await client.loginWithBrowser({
  ephemeralSession: true,
  resource: ["urn:guardhouse:api:orders"],
});

console.log(result.session.accessToken);
```

### Restore session on app launch

```tsx
const restored = await client.restoreSession();

if (restored?.session) {
  // User is authenticated
}
```

### Get access token (auto-refresh)

```tsx
const token = await client.getAccessToken();
```

### Refresh with a narrower scope

For a session granted `read write`, request only `read`:

```tsx
const result = await client.refreshToken({ scope: "read" });
```

An override may only keep or narrow the saved session's scope. Native sends the
effective scope to the token endpoint and validates the response against it.
Omitted or blank overrides use the saved scope, including on automatic refresh
and after restarting the app; broader config defaults do not restore dropped
permissions. If the response omits `scope`, the requested scope is saved.
`allowScopeNarrowing` still controls server-selected reductions beyond the request.

Concurrent calls with matching scope options and audience share one refresh.
Different options reject with `REFRESH_OPERATION_CONFLICT`; await the active
refresh before retrying. An explicit scope and an omitted scope are distinct
options even if they currently resolve to the same scopes. No automatic replay
of a potentially consumed refresh token is added.

### Logout

```tsx
await client.logout({
  revoke: true,
  revokeRefreshToken: true,
});
```

## Registration with returnUrl

If your registration endpoint expects a `returnUrl` query parameter, configure it like:

```ts
endpoints: {
  registration: "/account/signup?returnUrl=",
}
```

The SDK will inject the generated authorize URL into `returnUrl` and keep the flow inside the auth session (returns to your app, not Safari).

## Passkey login (headless WebAuthn)

Provide a passkey adapter that wraps a native WebAuthn library (e.g., `react-native-passkey`):

```ts
import type { GuardhousePasskeyAdapter } from "@guardhouse/react-native";

const passkeyAdapter: GuardhousePasskeyAdapter = {
  name: "MyPasskeyAdapter",
  async get(options) {
    // call native passkey library and return assertion
    return nativePasskeyGet(options);
  },
};

const client = new GuardhouseClient({
  // ...
  passkey: passkeyAdapter,
});

const result = await client.loginWithPasskey();
```

## Adapters

### Browser adapter

Implements `GuardhouseBrowserAdapter`:

```ts
interface GuardhouseBrowserAdapter {
  name?: string;
  openAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    options?: { ephemeralSession?: boolean; timeoutMs?: number },
  ): Promise<{ url: string }>;
}
```

Default: `InAppBrowserAuthAdapter` (uses `react-native-inappbrowser-reborn`).

For Expo, use `expo-web-browser`:

```ts
import * as WebBrowser from "expo-web-browser";

export const expoBrowserAdapter = {
  name: "ExpoBrowserAdapter",
  async openAuthSession(authorizationUrl, redirectUri, options) {
    const result = await WebBrowser.openAuthSessionAsync(
      authorizationUrl,
      redirectUri,
      { preferEphemeralSession: options?.ephemeralSession ?? true },
    );

    if (result.type === "success" && result.url) {
      return { url: result.url };
    }

    throw new Error(result.type === "cancel" ? "Cancelled" : "Auth failed");
  },
};
```

### Storage adapters

- `KeychainStorageAdapter` – uses `react-native-keychain` (default for production)
- `ChunkedSecureStore` – wraps any adapter to split large values
- Provide your own `GuardhouseStorageAdapter` for custom runtimes. A storage
  adapter alone does not make OIDC work in Expo Go.

```ts
interface GuardhouseStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}
```

### OIDC Web Crypto and PKCE adapters

`CryptoAdapter` supplies only secure random bytes and SHA-256 for PKCE. OIDC
(`openid` scope) additionally uses Core's `jose` verifier, which requires a
compatible global `crypto.subtle` implementation with `importKey`, `verify` and
`digest`, including support for your issuer's signing algorithm. Providing only
`randomBytes`/`sha256`, `expo-crypto`, or a random-values polyfill is insufficient.

If the runtime already provides compatible Web Crypto, no extra provider is
needed. For React Native 0.75+ using the New Architecture, the Expo example pins:

```bash
npm install --save-exact react-native-quick-crypto@1.1.7 react-native-nitro-modules@0.33.2 react-native-quick-base64@3.0.1
```

Follow the provider's [native setup instructions](https://margelo.github.io/react-native-quick-crypto/docs/introduction/complete-setup).
Initialize it in a separate bootstrap module, imported **before** your app/SDK:

```ts
// installCrypto.ts
import { install } from "react-native-quick-crypto";
install();
```

```ts
// index.js — bootstrap dependency must execute before App's dependencies.
import "./installCrypto";
import App from "./App";
// Register App with AppRegistry / registerRootComponent as usual.
```

The SDK does not replace global crypto on your behalf. A custom PKCE adapter can
still be used alongside the installed Web Crypto implementation. Older React
Native architectures may use another compatible provider; the 1.x setup above
does not support them. Core also expects standard fetch/Response/Headers,
TextEncoder/TextDecoder and base64 APIs; install runtime polyfills before
importing it if your runtime does not supply them.

For Expo, add `react-native-quick-crypto` to `expo.plugins`, use a development build
(`npx expo run:android` or `npx expo run:ios`), and rebuild after adding native
dependencies. This setup does **not** work in stock Expo Go. The example uses
Expo 54 / React Native 0.81.5 and explicitly enables the New Architecture.

Missing Web Crypto operations raise `GuardhouseConfigurationError` (`CONFIG_ERROR`)
before OIDC login/registration/passkey interaction or refresh. OIDC restoration
also rejects before cryptographic verification without deleting stored credentials;
retry after fixing initialization. A configured default OIDC scope is checked in
the constructor, and scope overrides are checked at operation time. OAuth-only
PKCE remains usable without Web Crypto when its adapter supplies the required
primitives. Invalid signatures/claims are still rejected by the unchanged verifier.

The availability check is not a cryptographic self-test: run login, refresh and
cold restoration on Android and iOS with your actual provider/issuer algorithms
before release. Node tests exercise real signatures but cannot validate native
module linking or device-specific algorithm support.

## API

### `GuardhouseClient`

#### Constructor

```ts
new GuardhouseClient(config: GuardhouseClientConfig)
```

#### Methods

- `loginWithBrowser(options?)` – OAuth browser login
- `registerWithBrowser(options?)` – OAuth browser registration
- `loginWithPasskey(options?)` – headless WebAuthn login
- `refreshToken(options?)` – refresh access token
- `restoreSession(options?)` – restore and optionally refresh
- `getSession()` – get current session
- `getAccessToken(options?)` – get access token (auto-refresh)
- `logout(options?)` – logout and optionally revoke tokens

### Types

```ts
interface GuardhouseClientConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  audience?: string;
  cryptoAdapter?: CryptoAdapter;
  refreshTokenStorage?: GuardhouseStorageAdapter;
  sessionStorage?: GuardhouseStorageAdapter;
  browser?: GuardhouseBrowserAdapter;
  passkey?: GuardhousePasskeyAdapter;
  fetch?: FetchLike;
  defaultEphemeralSession?: boolean;
  userInfoOnLogin?: boolean;
  endpoints?: Partial<GuardhouseClientEndpoints>;
  chunkSize?: number;
}

interface GuardhouseSession {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  identity?: OidcIdentityMetadata;
  tokenType: string;
  scope?: string;
  expiresAt: number;
  user: User | null; // Deeply immutable verified/UserInfo claims
}

interface GuardhouseAuthResult {
  session: GuardhouseSession;
  tokenResponse: GuardhouseTokenResponse;
  user: User | null;
  appState?: Record<string, unknown>;
}
```

## Error handling

All errors extend `GuardhouseError`:

- `GuardhouseAuthError` – authentication/protocol errors
- `GuardhouseNetworkError` – HTTP/network failures
- `GuardhouseStorageError` – storage layer failures
- `GuardhouseConfigurationError` – config errors

An operation interrupted by logout rejects with `AUTH_OPERATION_SUPERSEDED`.
Treat it as a cancelled operation; do not restore its previous session or retry
its token grant. A new user-initiated login can start a new operation.

```ts
import { GuardhouseAuthError } from "@guardhouse/react-native";

try {
  await client.loginWithBrowser();
} catch (error) {
  if (error instanceof GuardhouseAuthError) {
    console.log(error.code, error.message, error.statusCode);
  }
}
```

## Security notes

- Tokens stored in iOS Keychain / Android Keystore (via `react-native-keychain`)
- No AsyncStorage/SharedPreferences fallback
- PKCE with S256 enforced
- Callbacks require a live, one-use Core v2 transaction binding state, nonce,
  PKCE, issuer, client, and redirect URI. The callback is runtime-opaque and is
  consumed before token I/O; fabricated, serialized, cross-client, and replayed
  callbacks fail.
- ID-token signatures and claims are verified before identity is exposed;
  UserInfo must have the exact same `sub`. Returned user arrays and nested custom
  claims are recursively copied and frozen, and extension claims are `unknown`
  until your application validates them.
- Manual authorization-code exchange and front-channel token ingestion are not
  exposed
- Deep-link redirects match exact scheme, authority, path, ordered query tuples,
  and fragment. Credentials are rejected and recognized callbacks are sanitized.
- RFC 8707 `resource` values must be absolute URIs (URNs are supported); relative
  values, fragments, whitespace, and controls are rejected.
- Android `launchMode="singleTask"` prevents task hijacking
- Logout invalidates pending login, passkey, restore and refresh completions.
  Storage writes and cleanup are ordered within a client instance so a delayed
  write cannot recreate credentials after logout completes.

## License

Apache-2.0
