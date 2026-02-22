# Expo React Native Example

This example app demonstrates `@guardhouse/react-native` in an Expo SDK 54+ project with OAuth 2.0 Authorization Code + PKCE, secure storage, and API calls.

## Features

- Login/logout with Guardhouse
- Token storage in secure storage (via SDK)
- Protected screen and API demo screen
- Environment-based config via `.env`
- Expo development workflow (`expo run:*` + Metro)

## Setup

1. Copy env template:

```bash
cp .env.example .env
```

2. Fill `.env` with your test identity server values:

```env
GH_AUTHORITY=https://your-test-identity-server
GH_CLIENT_ID=your-client-id
GH_REDIRECT_URI=com.example.guardhouse://callback
GH_SCOPE=openid profile email offline_access
GH_API_BASE_URL_ANDROID=http://10.0.2.2:3001
GH_API_BASE_URL_IOS=http://localhost:3001
```

3. Install dependencies:

```bash
npm install
```

The example intentionally includes all SDK runtime deps needed when using local `file:` packages in a monorepo (`@guardhouse/core`, `@noble/hashes`, `jwt-decode`, `react-native-keychain`, `react-native-inappbrowser-reborn`, `expo-dev-client`).

4. Verify TypeScript:

```bash
npm run typecheck
```

## Run

This example uses native modules (`react-native-keychain`, `react-native-inappbrowser-reborn`), so use an Expo development build (not Expo Go).

If Expo Go prompts for Motion/Fitness permissions, that prompt is from Expo Go tooling and not required by this app. Run with a dev build (`npm run android` / `npm run ios`) to avoid Expo Go-specific behavior.

```bash
npm start
```

Then in another terminal:

- `npm run android`
- `npm run ios`

On first run, Expo will generate native projects via prebuild.

## Optional explicit prebuild

```bash
npm run prebuild
```

## Important platform config

- **Android**: Expo prebuild creates native files. Confirm deep-link intent filters for your redirect URI if you customize package/scheme.
- **iOS**: Expo prebuild creates native files. Confirm URL scheme if you customize bundle ID/scheme.

Use the same scheme/host as `GH_REDIRECT_URI`.

## Troubleshooting

- If login does nothing, check the error banner on the home screen.
- If you see `Cannot read property 'setGenericPassswordForOptions' of null`, Keychain native module failed to initialize. The SDK now falls back to Expo SecureStore in this example. Rebuild the native app after dependency/plugin changes:

```bash
npm run prebuild
npm run ios
```

- If you see `SHA-256 is not available`, rebuild SDK packages and clear Metro cache:

```bash
cd ../../
npm run build -w @guardhouse/core
npm run build -w @guardhouse/react-native
cd examples/react-native
npm start -- --clear
```

- If login browser does not open, make sure you are running a development build (`npm run ios` / `npm run android`) and not Expo Go.

## API demo

- Android emulator should use `GH_API_BASE_URL_ANDROID` (`10.0.2.2` for localhost).
- iOS simulator should use `GH_API_BASE_URL_IOS` (`localhost` for local API).

Run `examples/node` server to test protected API calls.
