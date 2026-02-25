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

## Source Layout

- `src/auth/`: OAuth URL generation, callback parsing/sanitization, state/CSRF helpers
- `src/client/`: Guardhouse client split by responsibility (base/session/token/advanced)
- `src/token/`: JWT decode/validation, OIDC hash claims, JWK validation, replay cache
- `src/auth.ts`, `src/client.ts`, `src/token.ts`: compatibility entry files that re-export folder modules

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
  allowOfflineAccessScope: true,
  // For providers that reject audience on /authorize (for example some
  // OpenIddict configurations), omit audience and set:
  // allowAuthorizationWithoutAudience: true,
  state: await generateState(),
  nonce: await generateNonce(),
  acrValues: ["phrh"],
  uiLocales: ["en-US"],
  loginHint: "alice@example.com",
  audience: "https://api.example.com",
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

##### `exchangeCodeForTokensUsingHandle(code, codeVerifierHandle, redirectUri, params)`

Consumes a one-time PKCE verifier handle and exchanges code without keeping verifier values in long-lived application memory.

```typescript
const tokens = await client.exchangeCodeForTokensUsingHandle(
  authorizationCode,
  verifierHandle,
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

##### `assertAuthorizationPageClickjackingProtection(endpoint?)`

Verify the authorization page exposes anti-clickjacking headers before starting browser login.

```typescript
await client.assertAuthorizationPageClickjackingProtection();
```

##### `buildLogoutUrl(request)`

Builds a validated logout URL (defaults to `/connect/logout`) and enforces safe `post_logout_redirect_uri` handling.

```typescript
const logoutUrl = client.buildLogoutUrl({
  postLogoutRedirectUri: "https://app.example.com/logout",
  idTokenHint: idToken,
  state: "logout-state",
});
```

##### `discoverOpenIdConfiguration(endpoint?)`

Fetches OIDC discovery metadata from the configured authority origin using `Cache-Control: no-store` and validates critical endpoint origins.

```typescript
const metadata = await client.discoverOpenIdConfiguration();
```

##### `resolveHomeRealmIssuer(loginHint, trustedIssuersByDomain)`

Resolves issuer for Home Realm Discovery using a strict domain allowlist.

```typescript
const hrd = client.resolveHomeRealmIssuer("alice@contoso.com", {
  "contoso.com": "https://idp.contoso.com",
});
```

##### `openAuthorizationPopup(url, name?, features?)`

Opens auth popup with `noopener,noreferrer` protections and resets `window.opener`.

```typescript
client.openAuthorizationPopup(authUrl);
```

##### `postMessageToPopup(targetWindow, message, targetOrigin)`

Posts messages to popup windows only when `targetOrigin` is an explicit trusted origin (wildcard `*` is rejected).

```typescript
client.postMessageToPopup(
  popupRef,
  { type: "guardhouse_auth_result" },
  "https://app.example.com",
);
```

##### `prepareSharedDeviceLogout(request?)`

Clears local session and returns a federated logout URL for shared device scenarios.

```typescript
const logoutUrl = await client.prepareSharedDeviceLogout({
  postLogoutRedirectUri: "https://app.example.com/logout",
});
```

##### `validateOAuthCallback(callbackUrl, expectedState, prompt?)`

Parse callback parameters safely, validate `state`, and auto-clear session for `prompt=none` interaction errors.

```typescript
const callback = await client.validateOAuthCallback(
  window.location.href,
  expectedState,
  "none",
);
```

##### `getSessionState()` / `clearSessionState()`

Read or clear sanitized local session state. Refresh token values are never persisted by the SDK.

```typescript
const session = await client.getSessionState();
await client.clearSessionState();
```

##### `registerClient(metadata, initialAccessToken, endpoint?)`

Perform authenticated dynamic client registration. Initial Access Token is required.

```typescript
const registered = await client.registerClient(
  {
    client_name: "My App",
    redirect_uris: ["https://app.example.com/callback"],
  },
  initialAccessToken,
);
```

##### `createPushedAuthorizationRequest(params, endpoint?)`

Creates a PAR `request_uri` so sensitive auth parameters (like `code_challenge`) are sent via POST instead of front-channel query strings.

```typescript
const par = await client.createPushedAuthorizationRequest({
  response_type: "code",
  redirect_uri: "https://app.example.com/callback",
  code_challenge,
  code_challenge_method: "S256",
  scope: "openid profile",
  state,
  nonce,
});
```

##### `buildHostOnlyCookie(name, value, options?)`

Builds a secure host-only cookie string and blocks `Domain` usage to reduce sub-domain leakage risk.

```typescript
const cookie = client.buildHostOnlyCookie("gh_session", token, {
  maxAgeSeconds: 300,
  sameSite: "Strict",
});
```

##### `assertAccountLinkingPreconditions(context)`

Verifies both sessions are active before account-linking operations.

```typescript
client.assertAccountLinkingPreconditions({
  primarySessionActive: true,
  secondarySessionActive: true,
  primarySubject,
  secondarySubject,
});
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

##### `stashCodeVerifier(codeVerifier)` / `consumeCodeVerifier(handle)`

Store `code_verifier` behind one-time in-memory handles to avoid exposing verifier values in global scope.

```typescript
const handle = await stashCodeVerifier(codeVerifier);
const verifier = consumeCodeVerifier(handle); // one-time read
```

##### `stashExpectedState(state)` / `consumeStateBinding(handle, returnedState)`

Store per-request state bindings using one-time in-memory handles to avoid multi-tab collisions.

```typescript
const stateHandle = stashExpectedState(state);
consumeStateBinding(stateHandle, returnedStateFromCallback);
```

##### `validateAndConsumeState(expectedState, returnedState)`

Validate callback `state` and mark it as consumed to prevent replay/session fixation.

```typescript
validateAndConsumeState(expectedStateFromStorage, stateFromCallback);
```

##### `parseOAuthCallbackUrl(callbackUrl)` / `sanitizeOAuthCallbackUrl(callbackUrl)`

Safely parse OAuth callback query/fragment params and remove sensitive values from URLs to reduce referer leakage risk.

```typescript
const callback = parseOAuthCallbackUrl(window.location.href);
const sanitized = sanitizeOAuthCallbackUrl(window.location.href);
history.replaceState(null, "", sanitized);
```

##### `sanitizeAuthorizationUrlForHistory(authUrl)`

Removes sensitive auth request params (like `code_challenge`, `state`, and `nonce`) from URLs stored in app history/logs.

```typescript
const safeUrl = sanitizeAuthorizationUrlForHistory(authUrl);
```

##### `validateFormPostCsrfToken(expected, actual)`

Validates CSRF token binding for `response_mode=form_post` handling.

```typescript
validateFormPostCsrfToken(expectedCsrfToken, csrfTokenFromCookie);
```

##### `validateFrontChannelLogoutRequest(url, options)`

Verifies `iss` and optional `sid` for front-channel logout requests.

```typescript
validateFrontChannelLogoutRequest(logoutUrl, {
  expectedIssuer: "https://auth.example.com",
  expectedSessionId: "session-123",
});
```

##### `createLocationHeaderRedirect(url)`

Builds a redirect response using HTTP `Location` headers instead of HTML meta refresh pages.

```typescript
const redirect = createLocationHeaderRedirect(
  "https://app.example.com/callback",
);
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

##### `validateOidcHashClaims(decodedJWT, options)`

Verifies OIDC `at_hash` and `c_hash` claim bindings to prevent token/code substitution.

```typescript
const hashResult = await validateOidcHashClaims(decodedIdToken, {
  accessToken,
  authorizationCode,
  requireAtHash: true,
  requireCHash: true,
});
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
  discoveryCacheTtlMs?: number; // Optional: Discovery cache TTL in milliseconds
  allowUnsafeHttpMethods?: boolean; // Optional: Allow PUT/PATCH/DELETE in fetch (default: false)
  requireDpopForAccessTokenRequests?: boolean; // Optional: Require DPoP when access token is used
  allowScopeNarrowing?: boolean; // Optional: Allow missing granted scopes (default: false)
  maxAuthorizationHeaderBytes?: number; // Optional: Authorization/DPoP header size limit (default: 8192)
  maxSilentAuthAttempts?: number; // Optional: Silent auth retry ceiling (default: 3)
  requireUserInteractionForSensitiveOperations?: boolean; // Optional: Require recent user interaction
  allowedPostLogoutRedirectUris?: string[]; // Optional: Logout redirect allowlist
  sessionStorageKey?: string; // Optional: Storage key for sanitized session cache
  dpopProofFactory?: (ctx) => string | Promise<string>; // Optional: DPoP proof generator
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
  clientId?: string; // Expected OAuth client_id for azp checks
  nonce?: string; // Expected nonce
  signatureVerified?: boolean; // Must be true after cryptographic verification
  trustedJkuOrigins?: string[]; // Allowlist of trusted JKU origins
  supportedCriticalHeaders?: string[]; // Allowed JWT crit extensions
  expectedKid?: string; // Expected JWT kid header
  allowedKids?: string[]; // Optional allowlist of kid values
  resolvedJwk?: JwkMetadata; // Optional resolved JWK metadata for use/alg/key_ops checks
  expectedKeyType?: "RSA" | "EC" | "oct" | "OKP"; // Enforce alg/key-type compatibility
  requiredAcrValues?: string[]; // Required ACR assurance values
  maxAgeSeconds?: number; // Enforce auth_time freshness from max_age policy
  enforceUniqueJti?: boolean; // Enable replay protection using jti cache
  requiredAmrValues?: string[]; // Required authentication methods
  requirePhishingResistantMfa?: boolean; // Require WebAuthn/FIDO-like amr values
  requiredCnfJkt?: string; // Enforce cnf.jkt token binding thumbprint
  trustedNestedClaimPaths?: string[]; // Allowlist of nested claim paths
  allowUntrustedNestedClaims?: boolean; // Disable strict nested-claim trust policy
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
- **Cryptographic Agility**: Supports EdDSA and configurable allowed algorithms
- **'none' Algorithm**: Explicitly rejected (critical security check)
- **Claim Validation**: exp, nbf, iss, aud, nonce, acr, auth_time, amr, cnf
- **Replay Protection**: Optional one-time `jti` tracking cache
- **OIDC Hash Claims**: Supports `at_hash` and `c_hash` verification helpers
- **Clock Skew Tolerance**: Default 30 seconds (configurable)

### HTTP Security

- **TLS Enforcement**: HTTPS required (except localhost)
- **TLS Override Guard**: Blocks `NODE_TLS_REJECT_UNAUTHORIZED=0`
- **Unicode Hostname Hardening**: Blocks IDN/punycode hostnames to reduce homograph spoofing risk
- **Basic Auth**: RFC 7617 compliant (Base64 encoded)
- **PAR Support**: Optional pushed authorization requests to reduce front-channel parameter exposure
- **DPoP Support**: Optional proof-of-possession via `dpopProofFactory`
- **Discovery Hardening**: Fetches discovery with no-store cache controls and validates endpoint origin consistency
- **Header Size Guardrails**: Configurable max authorization header size
- **Method Tampering Guardrails**: PUT/PATCH/DELETE blocked unless `allowUnsafeHttpMethods=true`
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
  codeChallenge,
  codeChallengeMethod: "S256",
  state: await generateState(),
  nonce: await generateNonce(),
  audience: "https://api.example.com",
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
