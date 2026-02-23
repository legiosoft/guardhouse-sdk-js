# Quick Start Guide

This guide helps you quickly set up and run all Guardhouse SDK examples.

## Prerequisites

- Node.js >= 18.0.0
- npm or yarn
- A Guardhouse instance running

## Setup Steps

### 1. Clone and Install

```bash
# Navigate to examples directory
cd examples

# Install all dependencies
npm install
```

### 2. Configure Guardhouse Client

Create a client in your Guardhouse instance with:

**Settings**:

- Client ID: Unique identifier (e.g., `example-web`, `example-mobile`)
- Client Secret: Generate a secret for backend
- Redirect URIs:
  - Web: `http://localhost:3000`
  - Mobile: `com.example.guardhouse://callback`
- Scopes: `openid profile offline_access`
- Grant Types: `authorization_code`, `refresh_token`, `client_credentials`

### 3. Configure Each Example

#### Node Example

```bash
cd node
cp .env.example .env
```

Edit `.env`:

```env
AUTHORITY=https://your-guardhouse-domain.com
CLIENT_ID=your-node-client-id
CLIENT_SECRET=your-node-client-secret
REDIRECT_URI=http://localhost:3001/callback
PORT=3001
```

#### React Example

```bash
cd react
cp .env.example .env
```

Edit `.env`:

```env
VITE_AUTHORITY=https://your-guardhouse-domain.com
VITE_CLIENT_ID=your-web-client-id
VITE_REDIRECT_URI=http://localhost:3000
```

#### React Native Example

```bash
cd react-native
cp .env.example .env
```

Edit `.env`:

```env
GH_AUTHORITY=https://your-guardhouse-domain.com
GH_CLIENT_ID=your-mobile-client-id
GH_REDIRECT_URI=com.example.guardhouse://callback
GH_SCOPE=openid profile email offline_access
GH_API_BASE_URL_ANDROID=http://10.0.2.2:3001
GH_API_BASE_URL_IOS=http://localhost:3001
```

The Expo app already wires native crypto through `src/cryptoAdapter.ts` and passes it to `GuardhouseProvider`.

### 4. Install Dependencies

```bash
# Install all dependencies
npm install

# Or install per example
cd node && npm install
cd ../react && npm install
cd ../react-native && npm install
```

### 5. Run Examples

#### Start Node Backend

```bash
cd node
npm run dev
```

Server runs on `http://localhost:3001`

#### Start React Web App

In a new terminal:

```bash
cd react
npm run dev
```

App runs on `http://localhost:3000`

#### Start React Native App (Expo SDK 54+)

In a new terminal:

```bash
cd react-native
npm start
```

In another terminal:

```bash
# For Android
npm run android

# For iOS
npm run ios
```

Note: this Expo example uses native modules, so run with Expo development builds (not Expo Go).

## Testing the Flow

### 1. Test Web App

1. Open `http://localhost:3000` in browser
2. Click "Login"
3. Authorize the application
4. View your user profile
5. Navigate to "API Demo"
6. Click "Fetch Protected Data"
7. Verify API response

### 2. Test Mobile App

1. Run React Native app (iOS or Android)
2. Tap "Login"
3. Authorize in InAppBrowser
4. View your user profile
5. Navigate to "Protected Page"
6. Test API demo

### 3. Test Backend Directly

```bash
# Get auth URL
curl http://localhost:3001/login

# Get token (client credentials)
curl -X POST http://localhost:3001/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "client_credentials"}'

# Access protected endpoint
curl http://localhost:3001/protected \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Common Issues

### "Client not found"

- Verify CLIENT_ID is correct
- Check client is active in Guardhouse

### "Redirect URI mismatch"

- Ensure redirect URI matches Guardhouse configuration exactly
- Check for trailing slashes or protocol differences

### "CORS errors"

- Add your frontend origin to Guardhouse CORS settings
- For React: `http://localhost:3000`

### "Deep link not working" (React Native / Expo)

**iOS**:

- Run `npm run ios` again after URI/scheme changes to regenerate native config
- Check generated `Info.plist` has your URL scheme

**Android**:

- Run `npm run android` again after URI/scheme changes to regenerate native config
- Verify generated `AndroidManifest.xml` intent filter contains your redirect URI

### "Port already in use"

- Change PORT in Node `.env`
- Change port in React `vite.config.ts`

## Next Steps

1. **Read Documentation**:
   - Node: `examples/node/README.md`
   - React: `examples/react/README.md`
   - React Native: `examples/react-native/README.md`

2. **Explore Code**:
   - Review source code
   - Understand authentication flow
   - See security implementations

3. **Customize**:
   - Modify UI
   - Add custom scopes
   - Integrate with your API

4. **Deploy**:
   - Deploy Node backend
   - Build and deploy React app
   - Build and publish React Native app

## Support

For more help:

- Check individual example README files
- Review Guardhouse SDK documentation
- Open an issue on GitHub

## Quick Commands

```bash
# All at once
cd examples
npm install
cd node && npm run dev &
cd react && npm run dev &
cd react-native && npm start &

# Individual examples
cd examples/node && npm run dev
cd examples/react && npm run dev
cd examples/react-native && npm run android
```

## Summary

You now have three working examples:

- **Node** - Backend server with OAuth 2.0
- **React** - Web frontend with PKCE flow
- **React Native** - Mobile app with secure storage

All examples demonstrate:

- OAuth 2.0 Authorization Code Flow
- PKCE with S256
- Secure token storage
- User authentication
- Protected API calls

Happy coding! 🚀
