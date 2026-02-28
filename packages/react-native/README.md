# @guardhouse/react-native

React Native SDK for Guardhouse OAuth 2.0 Authorization Code + PKCE, passkey authentication, and secure token lifecycle.

## Installation

```bash
npm install @guardhouse/react-native
```

### Peer dependencies

- `react >=18.0.0`
- `react-native >=0.70.0`
- `react-native-quick-crypto >=0.7.0` (optional, if Web Crypto is unavailable)

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
- Provide your own `GuardhouseStorageAdapter` for Expo Go or custom runtimes

```ts
interface GuardhouseStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}
```

### Crypto adapter

PKCE requires SHA-256 and secure random. If your React Native runtime provides `globalThis.crypto.subtle`, no extra setup is needed. Otherwise, install `react-native-quick-crypto` and provide a `CryptoAdapter`:

```ts
import type { CryptoAdapter } from "@guardhouse/core";

const cryptoAdapter: CryptoAdapter = {
  async sha256(data) {
    // return Uint8Array hash
  },
  async randomBytes(count) {
    // return Uint8Array
  },
};

const client = new GuardhouseClient({
  // ...
  cryptoAdapter,
});
```

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
- `exchangeCodeForTokens(code, options?)` – exchange auth code
- `applyRedirectTokens(payload)` – apply tokens from deep link
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
  tokenType: string;
  scope?: string;
  expiresAt: number;
  user: User | null;
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
- State parameter CSRF protection
- Deep link sanitization and strict redirect URI matching
- Android `launchMode="singleTask"` prevents task hijacking

## License

Apache-2.0
