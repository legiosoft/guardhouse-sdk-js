# React Native Example

This example app demonstrates `@guardhouse/react-native` with OAuth 2.0 Authorization Code + PKCE, secure storage, and API calls.

## Features

- Login/logout with Guardhouse
- Token storage in secure storage (via SDK)
- Protected screen and API demo screen
- Environment-based config via `.env`

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

4. Verify TypeScript:

```bash
npm run typecheck
```

## Run

```bash
npm start
```

Then in another terminal:

- `npm run android`
- `npm run ios`

## Important platform config

- **Android**: configure deep link intent filter and set `launchMode="singleTask"` for `MainActivity`.
- **iOS**: register URL scheme in `Info.plist`.

Use the same scheme/host as `GH_REDIRECT_URI`.

## API demo

- Android emulator should use `GH_API_BASE_URL_ANDROID` (`10.0.2.2` for localhost).
- iOS simulator should use `GH_API_BASE_URL_IOS` (`localhost` for local API).

Run `examples/node` server to test protected API calls.
