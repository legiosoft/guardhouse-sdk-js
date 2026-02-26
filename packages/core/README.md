# @guardhouse/core

`@guardhouse/core` is the runtime-agnostic Guardhouse SDK for OAuth 2.0 / OIDC flows with PKCE.

It is built for Node.js, browsers, and React Native, with security-first defaults around callback handling, token validation helpers, request hardening, and safe state/PKCE lifecycle management.

## Install

```bash
npm install @guardhouse/core
```

## What You Get

- OAuth 2.0 Authorization Code + PKCE helpers (`generateAuthUrl`, `generatePKCE`, `generateState`, `generateNonce`)
- `GuardhouseClient` for token exchange, refresh, userinfo, introspection, revocation, discovery, PAR, logout, and session helpers
- OIDC/JWT helpers (`decodeJWT`, `validateToken`, `validateOidcHashClaims`, `validateJwkMetadataForToken`)
- Stateful security primitives with TTL cleanup (`OAuthStateManager`, `OAuthPKCEManager`, `JtiReplayCache`)
- Hardened request behavior (HTTPS enforcement, strict endpoint origin checks, redirect rejection)

## Quick Start

```ts
import {
  GuardhouseClient,
  generateAuthUrl,
  generateNonce,
  generatePKCE,
  generateState,
} from "@guardhouse/core";

const authority = "https://auth.example.com";
const clientId = "my-app-id";
const redirectUri = "https://app.example.com/callback";

const client = new GuardhouseClient({
  authority,
  clientId,
});

const { codeVerifier, codeChallenge } = await generatePKCE();
const state = await generateState();
const nonce = await generateNonce();

const authUrl = generateAuthUrl({
  authority,
  authorizationEndpoint: "/connect/authorize",
  clientId,
  redirectUri,
  responseType: "code",
  scope: "openid profile offline_access",
  allowOfflineAccessScope: true,
  state,
  nonce,
  codeChallenge,
  codeChallengeMethod: "S256",
  audience: "https://api.example.com",
});

// Redirect user to authUrl, then receive callback code
const tokenResponse = await client.exchangeCodeForTokens(
  "authorization-code",
  codeVerifier,
  redirectUri,
);

const userInfo = await client.getUserInfo(tokenResponse.access_token);
console.log(userInfo.sub);
```

## Core APIs

### `GuardhouseClient`

Main SDK client for browser/server compatible OAuth/OIDC operations.

Common methods:

- `fetch(endpoint, options)`
- `exchangeCodeForTokens(code, codeVerifier, redirectUri, params?)`
- `exchangeCodeForTokensUsingHandle(code, codeVerifierHandle, redirectUri, params?)`
- `refreshToken(refreshToken, params?)`
- `getUserInfo(token, expectedSubject?)`
- `introspectToken(token)`
- `revokeToken(token, tokenTypeHint?)`
- `validateOAuthCallback(callbackUrl, expectedState, prompt?)`
- `getSessionState()` / `clearSessionState()`
- `discoverOpenIdConfiguration(endpoint?)`
- `createPushedAuthorizationRequest(params, endpoint?)`
- `buildLogoutUrl(request?)`
- `prepareSharedDeviceLogout(request?)`
- `registerClient(metadata, initialAccessToken, endpoint?)`
- `buildHostOnlyCookie(name, value, options?)`

### Auth + PKCE Utilities

- `generateAuthUrl(options)`
  - `authorizationEndpoint` is required
  - `state` is required
  - `nonce` is required when requesting `openid`
  - `codeChallenge` is required for code flow unless using `requestUri`
- `parseOAuthCallbackUrl(callbackUrl)`
- `sanitizeOAuthCallbackUrl(callbackUrl)`
- `sanitizeAuthorizationUrlForHistory(authUrl)`
- `createLocationHeaderRedirect(url)`
- `validateFrontChannelLogoutRequest(url, options)`
- `validateFormPostCsrfToken(expected, actual)`

### Stateful Managers

- `OAuthPKCEManager`
  - `stashCodeVerifier(codeVerifier)`
  - `consumeCodeVerifier(handle)`
  - `dropCodeVerifier(handle)`
- `OAuthStateManager`
  - `stashExpectedState(expectedState)`
  - `consumeStateBinding(handle, returnedState)`
  - `validateAndConsumeState(expectedState, returnedState)`

### Token Helpers

- `decodeJWT(token)`
  - Decodes only. It does **not** verify signatures.
- `validateToken(decodedJWT, options)`
  - Validates claims and security constraints after cryptographic verification.
- `validateOidcHashClaims(decodedJWT, options)`
  - Validates `at_hash` and `c_hash` bindings.
- `validateJwkMetadataForToken(jwk, options)`
- `JtiReplayCache`

## Security Defaults

- HTTPS required for authority and absolute endpoints (localhost exceptions for local development paths where applicable)
- HTTP redirects are rejected in client requests (`fetch` uses `redirect: "error"`)
- Authorization and DPoP headers are size-limited (`maxAuthorizationHeaderBytes`, default `4096`)
- Callback parsing and URL sanitization block parameter confusion and sensitive data leakage
- Host-only cookie helper blocks `Domain` attribute usage
- Discovery metadata is origin-validated against configured authority
- Token/body/auth parameter sanitization protects reserved and unsafe keys

## Config (Selected)

```ts
interface GuardhouseConfig {
  authority: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scope?: string;

  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  introspectionEndpoint?: string;
  revocationEndpoint?: string;

  requestTimeoutMs?: number; // default: 30000
  discoveryCacheTtlMs?: number; // default: 3600000 (1 hour)
  maxAuthorizationHeaderBytes?: number; // default: 4096
  maxSilentAuthAttempts?: number; // default: 3

  // Backward-compatible flag. Effective request methods are GET/HEAD/POST.
  allowUnsafeHttpMethods?: boolean;

  allowScopeNarrowing?: boolean;
  requireDpopForAccessTokenRequests?: boolean;
  requireUserInteractionForSensitiveOperations?: boolean;
  allowedPostLogoutRedirectUris?: string[];
  sessionStorageKey?: string;
  dpopProofFactory?: (context: {
    method: string;
    url: string;
    accessToken?: string;
  }) => string | Promise<string>;
  storage?: {
    getItem(key: string): Promise<string | null>;
    setItem(key: string, value: string): Promise<void>;
    removeItem(key: string): Promise<void>;
  };
  debug?: boolean;
}
```

## Release Checklist

From the monorepo root:

```bash
npm run build
npm run typecheck
npm run test -w @guardhouse/core
npm pack --dry-run -w @guardhouse/core
npm pack --dry-run -w @guardhouse/node
npm pack --dry-run -w @guardhouse/react
npm pack --dry-run -w @guardhouse/react-native
```

This verifies build output, typings, tests, and publishable package contents for all workspace packages.

## License

Apache-2.0
