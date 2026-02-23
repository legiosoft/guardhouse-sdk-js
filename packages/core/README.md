# @guardhouse/core

Universal JavaScript/TypeScript library for OAuth 2.0 Authorization Code Flow with PKCE.

## Features

- **Universal Crypto**: Works in Node.js, Browsers, and React Native
- **PKCE Support**: RFC 7636 compliant Proof Key for Code Exchange
- **JWT Validation**: Claim validation (exp, nbf, iss, aud, nonce)
- **HTTP Client**: Authenticated requests to Guardhouse endpoints
- **Zero Dependencies**: No external crypto libraries
- **Dual Output**: ESM and CommonJS support
- **Strictly Typed**: Full TypeScript support

## Installation

```bash
npm install @guardhouse/core
```

## Quick Start

```typescript
import {
  GuardhouseClient,
  generatePKCE,
  generateAuthUrl,
  generateState,
  generateNonce,
} from "@guardhouse/core";

const client = new GuardhouseClient({
  authority: "https://auth.example.com",
  clientId: "my-app-id",
});

const { codeVerifier, codeChallenge } = await generatePKCE();

const authUrl = await generateAuthUrl({
  authority: "https://auth.example.com",
  clientId: "my-app-id",
  redirectUri: "https://myapp.com/callback",
  responseType: "code",
  scope: "openid profile offline_access",
  state: "random-state",
  nonce: "random-nonce",
  codeChallenge,
  codeChallengeMethod: "S256",
});

const tokens = await client.exchangeCodeForTokens(
  code,
  codeVerifier,
  "https://myapp.com/callback",
);

const user = await client.getUserInfo(tokens.access_token);
```

## API Reference

### GuardhouseClient

Main client class for interacting with Guardhouse.

#### Constructor

```typescript
new GuardhouseClient(config: GuardhouseConfig)
```

#### Methods

##### `fetch<T>(endpoint, options)`

Make authenticated HTTP request to Guardhouse endpoint.

```typescript
const response = await client.fetch("/connect/userinfo", {
  token: accessToken,
});

console.log(response.data);
```

##### `exchangeCodeForTokens(code, codeVerifier, redirectUri, params)`

Exchange authorization code for access and refresh tokens.

```typescript
const tokens = await client.exchangeCodeForTokens(
  authorizationCode,
  codeVerifier,
  "https://myapp.com/callback",
);
```

##### `refreshToken(refreshToken, params)`

Refresh access token using refresh token.

```typescript
const newTokens = await client.refreshToken(tokens.refresh_token);
```

##### `getUserInfo(token)`

Fetch user information from Guardhouse.

```typescript
const user = await client.getUserInfo(accessToken);
console.log(user.name, user.email);
```

##### `revokeToken(token)`

Revoke an access token (if supported by server).

```typescript
await client.revokeToken(accessToken);
```

### PKCE Functions

##### `generatePKCE(options)`

Generate PKCE code verifier and code challenge.

```typescript
const { codeVerifier, codeChallenge } = await generatePKCE({
  length: 43, // default 43 (128 bits)
  method: "S256", // default
});
```

##### `generateState(length)`

Generate random state for CSRF protection.

```typescript
const state = await generateState(); // default 16 bytes (128 bits)
```

##### `generateNonce(length)`

Generate random nonce for JWT replay protection.

```typescript
const nonce = await generateNonce(); // default 16 bytes (128 bits)
```

### Token Functions

##### `decodeJWT(token)`

Decode JWT token (header + payload).

```typescript
const { header, payload } = decodeJWT(accessToken);
console.log(header.alg); // algorithm
console.log(payload.exp); // expiration
console.log(payload.sub); // subject
```

##### `validateToken(decodedJWT, options)`

Validate JWT claims.

```typescript
const result = validateToken(decodedJWT, {
  issuer: "https://auth.example.com",
  audience: "my-app-id",
  nonce: "your-nonce",
  signatureVerified: true,
});

console.log(result.valid);
console.log(result.errors);
```

##### `isTokenExpired(decodedJWT, clockSkewTolerance)`

Check if token is expired.

```typescript
const expired = isTokenExpired(decodedJWT, 30); // 30 second skew tolerance
```

### Crypto Adapter

##### `detectCryptoAdapter()`

Auto-detect and return appropriate crypto adapter for environment.

```typescript
const crypto = await detectCryptoAdapter();
const randomBytes = await crypto.randomBytes(32);
const hash = await crypto.sha256(data);
```

##### `initializeCrypto()`

Initialize crypto adapter (recommended early in app lifecycle).

```typescript
await initializeCrypto();
```

##### `setCryptoAdapter(provider)`

Set custom crypto adapter (for React Native or custom environments).

```typescript
import { setCryptoAdapter } from "@guardhouse/core";

const myAdapter = {
  async randomBytes(length) {
    /* ... */
  },
  async sha256(data) {
    /* ... */
  },
  name: "MyCryptoProvider",
};

setCryptoAdapter(myAdapter);
```

## Configuration

### GuardhouseConfig

```typescript
interface GuardhouseConfig {
  authority: string; // Required: Guardhouse server URL
  clientId: string; // Required: Your application's client ID
  clientSecret?: string; // Optional: For confidential clients
  redirectUri?: string; // Optional: OAuth callback URI
  scope?: string; // Optional: Default scopes
  requestTimeoutMs?: number; // Optional: Request timeout in milliseconds (default: 30000)
  storage?: StorageAdapter; // Optional: Custom storage
  debug?: boolean; // Optional: Enable SDK debug logs
}
```

### Debug Logging

Enable verbose SDK logs by setting `debug: true` in the client config:

```typescript
const client = new GuardhouseClient({
  authority: "https://auth.example.com",
  clientId: "my-app-id",
  debug: true,
});
```

### TokenValidationOptions

```typescript
interface TokenValidationOptions {
  issuer?: string; // Expected issuer
  audience?: string; // Expected audience
  nonce?: string; // Expected nonce
  signatureVerified?: boolean; // Must be true after cryptographic verification
  clockSkewTolerance?: number; // Clock skew tolerance (default: 30s)
}
```

## Security

### PKCE (RFC 7636)

- **Enforced S256**: Plain text PKCE is NOT supported
- **CSPRNG**: Uses cryptographically secure random generation
- **128-bit Minimum**: Recommended minimum for code verifier (43 base64url chars)
- **Base64URL Encoding**: RFC 4648 compliant encoding

### JWT Security

- **Algorithm Whitelisting**: Only RS*, HS*, ES\* algorithms allowed
- **'none' Algorithm**: Explicitly rejected (critical security check)
- **Claim Validation**: exp, nbf, iss, aud, nonce
- **Clock Skew Tolerance**: Default 30 seconds (configurable)

### HTTP Security

- **TLS Enforcement**: HTTPS required (except localhost)
- **Basic Auth**: RFC 7617 compliant (Base64 encoded)
- **Secret Protection**: Never sent in URLs or query params
- **SSL Verification**: Can't be disabled (enforced by fetch API)

### Crypto Security

- **SubtleCrypto API**: Preferred (hardware-accelerated, non-blocking)
- **Node.js Crypto**: Fallback for legacy Node.js
- **No Heavy Polyfills**: Lightweight, environment-specific implementations
- **CSPRNG**: Never uses `Math.random()` for security-critical data

## Platform Support

| Platform        | Crypto Adapter                   | HTTP Support |
| --------------- | -------------------------------- | ------------ |
| Node.js 15+     | SubtleCrypto (globalThis.crypto) | Fetch API    |
| Node.js 14-     | Node.js crypto (require)         | Fetch API    |
| Modern Browsers | SubtleCrypto (globalThis.crypto) | Fetch API    |
| Old Browsers    | Fallback (NOT production-ready)  | Fetch API    |
| React Native    | Custom provider injection        | Fetch API    |

## React Native Integration

For React Native, inject a crypto provider:

```typescript
import { setCryptoAdapter } from "@guardhouse/core";
import { NativeModules } from "react-native";

const RNAdapater = {
  async randomBytes(length) {
    return await NativeModules.GuardhouseCrypto.randomBytes(length);
  },
  async sha256(data) {
    return await NativeModules.GuardhouseCrypto.sha256(data);
  },
  name: "ReactNativeCrypto",
};

setCryptoAdapter(RNAdapater);
```

**Recommended Libraries**:

- `react-native-crypto-js`
- `react-native-quick-crypto`
- `expo-crypto`

## Testing

```bash
npm test              # Run tests
npm run test:watch  # Watch mode
npm run test:coverage  # With coverage
```

## Browser Support

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+
- Node.js 14+

## Examples

### OAuth Flow

```typescript
import {
  GuardhouseClient,
  generatePKCE,
  generateAuthUrl,
} from "@guardhouse/core";

const client = new GuardhouseClient({
  authority: "https://auth.example.com",
  clientId: "my-app-id",
});

const { codeVerifier, codeChallenge } = await generatePKCE();

const authUrl = await generateAuthUrl({
  authority: "https://auth.example.com",
  clientId: "my-app-id",
  redirectUri: "https://myapp.com/callback",
  responseType: "code",
  codeChallenge,
  codeChallengeMethod: "S256",
  state: await generateState(),
  nonce: await generateNonce(),
});

console.log("Authorization URL:", authUrl);
```

### Token Usage

```typescript
const tokens = await client.exchangeCodeForTokens(
  authorizationCode,
  codeVerifier,
  redirectUri,
);

const user = await client.getUserInfo(tokens.access_token);

console.log("User:", user.sub, user.name);
console.log("Access Token:", tokens.access_token);
console.log("Expires In:", tokens.expires_in, "seconds");
```

### Silent Refresh

```typescript
const newTokens = await client.refreshToken(refreshToken);

console.log("New Access Token:", newTokens.access_token);
console.log("New Refresh Token:", newTokens.refresh_token);
```

## License

MIT
