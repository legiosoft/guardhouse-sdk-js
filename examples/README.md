# Guardhouse SDK Examples

This directory contains example applications demonstrating how to use the Guardhouse SDKs across different platforms.

## Available Examples

### 1. Node.js Example

**Location**: `node/`

A complete Node.js server using `@guardhouse/node` for OAuth 2.0 server-side authentication.

**Features**:

- OAuth 2.0 Authorization Code Flow with PKCE
- Client Credentials flow
- Token exchange and refresh
- Protected endpoints
- User info fetching

**Tech Stack**:

- Node.js with Express
- TypeScript
- @guardhouse/node

**Getting Started**:

```bash
cd node
cp .env.example .env
npm install
npm run dev
```

**Documentation**: [node/README.md](./node/README.md)

---

### 2. React Example

**Location**: `react/`

A complete React web application using `@guardhouse/react` for OAuth 2.0 browser-based authentication.

**Features**:

- OAuth 2.0 Authorization Code Flow with PKCE
- Protected routes with React Router
- User profile management
- Token auto-refresh
- API integration example
- LocalStorage for tokens

**Tech Stack**:

- React 18
- TypeScript
- Vite
- React Router
- @guardhouse/react

**Getting Started**:

```bash
cd react
cp .env.example .env
npm install
npm run dev
```

**Documentation**: [react/README.md](./react/README.md)

---

### 3. React Native Example

**Location**: `react-native/`

A complete React Native mobile application using `@guardhouse/react-native` for OAuth 2.0 mobile authentication.

**Features**:

- OAuth 2.0 Authorization Code Flow with PKCE
- Secure Keychain/Keystore token storage
- InAppBrowser for secure authentication
- React Navigation
- User profile management
- Token auto-refresh
- API integration example
- Deep link support

**Tech Stack**:

- React Native
- TypeScript
- React Navigation
- @guardhouse/react-native

**Getting Started**:

```bash
cd react-native
npm install

# iOS
cd ios && pod install && cd ..
npm run ios

# Android
npm run android
```

**Documentation**: [react-native/README.md](./react-native/README.md)

---

## Architecture Overview

All examples demonstrate the complete authentication flow:

1. **Login Flow**
   - Generate PKCE parameters
   - Redirect to Guardhouse
   - User authorization
   - Handle callback
   - Exchange code for tokens

2. **Token Management**
   - Store tokens securely
   - Auto-refresh when expired
   - Handle token errors

3. **Protected Resources**
   - Access protected endpoints
   - Validate tokens
   - Handle authentication errors

4. **User Management**
   - Fetch user profile
   - Display user information
   - Handle logout

## Security Features

All examples implement security best practices:

### PKCE Flow

- S256 code challenge method
- CSPRNG for state/nonce generation
- CSRF protection via state parameter

### Secure Storage

- **Node**: Memory or database storage (user-configured)
- **React**: LocalStorage with security considerations
- **React Native**: Keychain/Keystore with hardware backing

### JWT Validation

- Algorithm whitelisting (RS256, HS256, etc.)
- `none` algorithm rejection
- Token expiration checking

### TLS Enforcement

- HTTPS required for all communications
- Strict SSL verification

### Input Validation

- Deep link sanitization
- URL validation
- CSRF protection

## Running All Examples

To run all examples together for a complete demo:

1. **Start Guardhouse Server** (if not already running)

2. **Start Node Example** (Backend):

```bash
cd node
npm run dev
```

Server runs on `http://localhost:3001`

3. **Start React Example** (Frontend):

```bash
cd react
npm run dev
```

App runs on `http://localhost:3000`

4. **Start React Native Example** (Mobile):

```bash
cd react-native
npm start
# In another terminal
npm run ios  # or npm run android
```

## Common Configuration

All examples require the same Guardhouse configuration:

### Environment Variables

| Variable                             | Description               | Example                    |
| ------------------------------------ | ------------------------- | -------------------------- |
| `AUTHORITY` / `VITE_AUTHORITY`       | Guardhouse domain         | `https://auth.example.com` |
| `CLIENT_ID` / `VITE_CLIENT_ID`       | Application client ID     | `your-client-id`           |
| `CLIENT_SECRET`                      | Client secret (Node only) | `your-client-secret`       |
| `REDIRECT_URI` / `VITE_REDIRECT_URI` | OAuth callback URL        | `http://localhost:3000`    |

### Guardhouse Configuration

Create a client in Guardhouse with:

1. **Client ID**: Unique identifier
2. **Client Secret** (for Node backend)
3. **Redirect URIs**:
   - Web: `http://localhost:3000`
   - Mobile: `com.yourapp://callback`
4. **Scopes**: `openid profile email offline_access`
5. **Grant Types**: `authorization_code`, `refresh_token`

## Testing the Examples

### 1. Test with React Example

1. Start Node example on port 3001
2. Start React example on port 3000
3. Open `http://localhost:3000` in browser
4. Click "Login"
5. Authorize the application
6. View user profile
7. Test API demo

### 2. Test with React Native Example

1. Start Node example on port 3001
2. Run React Native app
3. Click "Login"
4. Authorize in InAppBrowser
5. View user profile
6. Test API demo (use `10.0.2.2` for Android emulator)

### 3. Test Node Backend

1. Start Node example
2. Use curl or Postman to test endpoints:

```bash
# Get auth URL
curl http://localhost:3001/login

# Get token (client credentials)
curl -X POST http://localhost:3001/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "client_credentials"}'

# Access protected endpoint
curl http://localhost:3001/protected \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Troubleshooting

### Port Conflicts

If ports are already in use:

- Change `PORT` in Node example `.env`
- Change `port` in React example `vite.config.ts`

### CORS Issues

Ensure Guardhouse allows requests from your origins.

### Deep Link Issues

**React Native**:

- iOS: Check `Info.plist` URL scheme
- Android: Check `AndroidManifest.xml` intent filter
- Android: Set `launchMode="singleTask"`

### Token Errors

- Verify client ID matches
- Check redirect URI matches Guardhouse configuration
- Ensure scopes are correct

## Contributing

When contributing to examples:

1. Follow the existing code style
2. Add security comments
3. Update documentation
4. Test all platforms

## License

MIT

## Support

For issues or questions:

- Check example-specific README files
- Review main SDK documentation
- Open an issue on GitHub
