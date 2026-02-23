# Examples Created

This document summarizes the example projects created for the Guardhouse SDK.

## Directory Structure

```
examples/
├── README.md                           # Main examples documentation
├── node/                              # Node.js backend example
│   ├── .env.example                     # Environment variables template
│   ├── .gitignore                      # Git ignore rules
│   ├── README.md                        # Detailed Node.js documentation
│   ├── package.json                     # Dependencies and scripts
│   ├── tsconfig.json                   # TypeScript configuration
│   └── src/
│       └── index.ts                    # Express server with OAuth 2.0
├── react/                              # React web application example
│   ├── .env.example                     # Environment variables template
│   ├── .gitignore                      # Git ignore rules
│   ├── README.md                        # Detailed React documentation
│   ├── index.html                      # HTML entry point
│   ├── package.json                     # Dependencies and scripts
│   ├── src/
│   │   ├── App.tsx                    # Main React app
│   │   ├── index.css                  # Styles
│   │   └── main.tsx                  # React entry point
│   ├── tsconfig.json                   # TypeScript configuration
│   └── vite.config.ts                 # Vite configuration
└── react-native/                       # React Native mobile example
    ├── .env.example                     # Environment variables template
    ├── .gitignore                      # Git ignore rules
    ├── README.md                        # Detailed React Native documentation
    ├── App.tsx                         # React Native entry point
    ├── app.json                        # React Native app config
    ├── index.js                        # JavaScript entry point
    ├── metro.config.js                  # Metro bundler config
    ├── package.json                     # Dependencies and scripts
    ├── tsconfig.json                   # TypeScript configuration
    └── src/
        ├── AppNavigator.tsx            # React Navigation setup
        └── screens/
            ├── ApiDemoScreen.tsx        # API demo screen
            ├── HomeScreen.tsx          # Home screen
            └── ProtectedScreen.tsx     # Protected route screen
```

## Node.js Example

**Location**: `examples/node/`

**Purpose**: Backend server demonstrating OAuth 2.0 authentication with Guardhouse

**Features**:

- OAuth 2.0 Authorization Code Flow with PKCE
- Client Credentials grant type
- Protected API endpoints
- User info endpoint
- Token management
- Error handling

**Tech Stack**:

- Node.js with Express
- TypeScript
- @guardhouse/node SDK

**Key Files**:

- `src/index.ts` - Express server with OAuth 2.0 endpoints
- `package.json` - Dependencies: express, @guardhouse/node, dotenv
- `.env.example` - Template for environment variables

**Running**:

```bash
cd examples/node
cp .env.example .env
npm install
npm run dev
```

## React Example

**Location**: `examples/react/`

**Purpose**: Frontend web application demonstrating OAuth 2.0 authentication in browsers

**Features**:

- OAuth 2.0 Authorization Code Flow with PKCE
- Protected routes with React Router
- User profile display
- Token auto-refresh
- API integration demo
- LocalStorage for token storage

**Tech Stack**:

- React 18 with TypeScript
- Vite for build tooling
- React Router for routing
- @guardhouse/react SDK

**Key Files**:

- `src/App.tsx` - Main app with GuardhouseProvider and routing
- `src/main.tsx` - React entry point
- `vite.config.ts` - Vite configuration with workspace alias
- `package.json` - Dependencies: react, react-router-dom, @guardhouse/react

**Running**:

```bash
cd examples/react
cp .env.example .env
npm install
npm run dev
```

## React Native Example (Expo)

**Location**: `examples/react-native/`

**Purpose**: Expo SDK 54+ mobile application demonstrating OAuth 2.0 authentication on iOS and Android

**Features**:

- OAuth 2.0 Authorization Code Flow with PKCE
- Secure Keychain/Keystore token storage
- InAppBrowser for secure authentication
- React Navigation
- User profile management
- Token auto-refresh
- API integration demo
- Deep link support

**Tech Stack**:

- Expo + React Native with TypeScript
- React Navigation
- @guardhouse/react-native SDK
- Expo native crypto adapter (`src/cryptoAdapter.ts`)
- react-native-inappbrowser-reborn
- react-native-keychain

**Key Files**:

- `App.tsx` - React Native entry point with GuardhouseProvider
- `src/AppNavigator.tsx` - Navigation setup
- `src/screens/HomeScreen.tsx` - Main screen with login/logout
- `src/screens/ProtectedScreen.tsx` - Protected route
- `src/screens/ApiDemoScreen.tsx` - API demo
- `package.json` - Dependencies: react-native, @guardhouse/react-native

**Running**:

```bash
cd examples/react-native
npm install
npm start

# in another terminal
npm run android
# or
npm run ios
```

## Common Features Across Examples

### Authentication Flow

All examples implement the same authentication flow:

1. **Login Initiation**
   - Generate PKCE parameters (code verifier, code challenge)
   - Generate secure state and nonce
   - Redirect to Guardhouse authorization endpoint

2. **User Authorization**
   - User authenticates with Guardhouse
   - Authorizes the application

3. **Callback Handling**
   - Receive authorization code and state
   - Validate state parameter (CSRF protection)
   - Exchange code for access/refresh tokens

4. **Token Storage**
   - Store tokens securely
   - Store user profile
   - Clean up temporary values

5. **Token Usage**
   - Use access token to authenticate API requests
   - Auto-refresh tokens when expired
   - Handle token errors

### Security Features

All examples implement security best practices:

**PKCE Flow**:

- S256 code challenge method (required)
- CSPRNG for state/nonce generation
- State parameter for CSRF protection

**Secure Storage**:

- **Node**: Memory/database (user-configured)
- **React**: LocalStorage
- **React Native**: Keychain/Keystore (hardware-backed)

**JWT Validation**:

- Algorithm whitelisting
- `none` algorithm rejection
- Token expiration checking

**TLS Enforcement**:

- HTTPS required for all communications

### Configuration

All examples use similar configuration:

**Environment Variables**:

- `AUTHORITY` - Guardhouse domain
- `CLIENT_ID` - Application client ID
- `CLIENT_SECRET` - Client secret (Node only)
- `REDIRECT_URI` - OAuth callback URL

**Guardhouse Setup**:

- Client with appropriate redirect URIs
- Scopes: `openid profile offline_access`
- Grant types: `authorization_code`, `refresh_token`

## Testing the Examples

### Complete Demo Setup

To test all examples together:

1. **Start Guardhouse** (if not already running)

2. **Start Node Backend**:

```bash
cd examples/node
npm run dev
```

Runs on `http://localhost:3001`

3. **Start React Frontend**:

```bash
cd examples/react
npm run dev
```

Runs on `http://localhost:3000`

4. **Start React Native App (Expo)**:

```bash
cd examples/react-native
npm start
npm run android  # or npm run ios
```

### Test Scenarios

1. **Web Authentication**:
   - Open React app at `http://localhost:3000`
   - Click login
   - Authorize with Guardhouse
   - View user profile
   - Test API demo

2. **Mobile Authentication**:
   - Run React Native app
   - Click login
   - Authorize in InAppBrowser
   - View user profile
   - Test API demo

3. **Backend Testing**:
   - Use Node endpoints
   - Test protected routes
   - Verify token handling

## Documentation

Each example has detailed documentation:

- **Node**: `examples/node/README.md`
- **React**: `examples/react/README.md`
- **React Native**: `examples/react-native/README.md`
- **All Examples**: `examples/README.md`

## Dependencies

### Common Dependencies

All examples depend on:

- TypeScript
- Node.js >= 18.0.0

### Platform-Specific Dependencies

**Node Example**:

- `@guardhouse/node`
- `express`
- `dotenv`

**React Example**:

- `@guardhouse/react`
- `react`
- `react-dom`
- `react-router-dom`
- `vite`

**React Native Example**:

- `@guardhouse/react-native`
- `react-native`
- `@react-navigation/native`
- `react-native-inappbrowser-reborn`
- `react-native-keychain`

## Next Steps

1. **Configure Environment Variables**:
   - Copy `.env.example` to `.env` in each example
   - Set your Guardhouse domain and client ID

2. **Install Dependencies**:
   - Run `npm install` in each example directory

3. **Run Examples**:
   - Start Node backend
   - Start React frontend
   - Run React Native app

4. **Explore**:
   - Read example-specific README files
   - Review source code
   - Test all features

## Support

For issues or questions:

- Check example-specific README files
- Review main SDK documentation
- Open an issue on GitHub

## License

MIT
