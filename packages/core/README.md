# @guardhouse/core

`@guardhouse/core` is the runtime-agnostic Guardhouse SDK for OAuth 2.0 / OIDC flows with PKCE.

It is built for Node.js, browsers, and React Native, with security-first defaults around callback handling, token validation helpers, request hardening, and safe state/PKCE lifecycle management.

## Install

```bash
npm install @guardhouse/core@2.0.0-beta.1
```

## What You Get

- Transaction-bound OAuth 2.0 Authorization Code + PKCE requests and callback validation
- `GuardhouseClient` for token exchange, refresh, userinfo, introspection, revocation, discovery, PAR, logout, and session helpers
- OIDC/JWT verification (`OidcIdTokenVerifier`, `verifyIdToken`) plus explicitly untrusted decoding (`decodeJWT`)
- Stateful security primitives with TTL cleanup (`OAuthStateManager`, `OAuthPKCEManager`, `JtiReplayCache`)
- Hardened request behavior (HTTPS enforcement, strict endpoint origin checks, redirect rejection)

## Quick Start

```ts
import { GuardhouseClient } from "@guardhouse/core";

const authority = "https://auth.example.com";
const clientId = "my-app-id";
const redirectUri = "https://app.example.com/callback";

const client = new GuardhouseClient({
  authority,
  clientId,
});

const { authorizationUrl, transaction } =
  await client.createAuthorizationRequest({
    redirectUri,
    scope: "openid profile offline_access",
    allowOfflineAccessScope: true,
    audience: "https://api.example.com",
    audiencePolicy: "guardhouse-required",
  });

// Persist each transaction atomically under its state before redirecting.
sessionStorage.setItem(
  `oauth:${encodeURIComponent(transaction.state)}`,
  JSON.stringify(transaction),
);
window.location.assign(authorizationUrl);

// On the callback, locate and restore the transaction using the returned state.
const returnedState = new URL(window.location.href).searchParams.get("state");
if (!returnedState) throw new Error("No active authorization transaction");
const serialized = sessionStorage.getItem(
  `oauth:${encodeURIComponent(returnedState)}`,
);
if (!serialized) throw new Error("No active authorization transaction");
const restoredTransaction = client.restoreAuthorizationTransaction(
  JSON.parse(serialized),
);
const callback = await client.validateOAuthCallback(
  { mode: "query", url: window.location.href },
  restoredTransaction,
);
window.history.replaceState({}, document.title, callback.sanitizedUrl);
sessionStorage.removeItem(`oauth:${encodeURIComponent(returnedState)}`);

if (callback.type === "error") throw new Error(callback.error);
const result = await client.exchangeAuthorizationCode(callback);
if (result.mode !== "oidc") throw new Error("OIDC response required");

const userInfo = await client.getUserInfo(
  result.tokens.access_token,
  result.identity,
);
console.log(userInfo.sub);
```

See [`MIGRATION-2.0.md`](../../MIGRATION-2.0.md) for a complete callback and
transaction restoration example.

## Core APIs

### `GuardhouseClient`

Main SDK client for browser/server compatible OAuth/OIDC operations.

Common methods:

- `fetch(endpoint, options)`
- `createAuthorizationRequest(options)`
- `restoreAuthorizationTransaction(value)`
- `validateOAuthCallback(input, transaction)`
- `exchangeAuthorizationCode(callback)` accepts the exact, one-use callback
  object returned by the same client's `validateOAuthCallback()` call.
- `refreshOAuthToken(refreshToken, options?)`
- `refreshOidcSession(refreshToken, options)`
- `requestClientCredentialsToken(options?)`
- `getUserInfo(token, identityEvidence)`
- `introspectToken(token)`
- `revokeToken(token, tokenTypeHint?)`
- `getSessionState()` / `clearSessionState()`
- `discoverOpenIdConfiguration(endpoint?)`
- `createPushedAuthorizationRequest(transaction, additionalParameters?)`
- `buildPushedAuthorizationUrl(request, transaction)`
- `await buildLogoutUrl(request?)`
- `prepareSharedDeviceLogout(request?)`
- `registerClient(metadata, initialAccessToken)`
- `buildHostOnlyCookie(name, value, options?)`

### Refresh scope

Use typed `scope` and `audience` options on `refreshOAuthToken` or
`refreshOidcSession`; both remain blocked in the extension-only
`requestParameters` object. An explicit `scope` requires the previously granted
`grantedScope` and may only keep or narrow it. `audience` is a token-endpoint
extension, not an override of the expected ID-token audience.

```ts
const tokens = await client.refreshOAuthToken(refreshToken, {
  grantedScope: "read write",
  scope: "read",
});
```

If the response omits `scope`, an explicitly sent scope is reflected in the
returned tokens and saved session, per RFC 6749 section 5.1. A response granting
more than requested is rejected. `allowScopeNarrowing` still governs whether the
server may grant fewer scopes than requested. Calls without the new typed fields
keep their previous request/response behavior. Typed scope/audience values must
be nonempty strings of at most 4096 characters; invalid values reject rather
than silently disappear from the request.

Refresh tokens are opaque credentials issued by the server. The 4096-character
extension-parameter limit does not apply to them; encrypted refresh tokens may
be longer. Their contents are sent unchanged through form encoding.

### Auth + PKCE Utilities

- Application login flows use `createAuthorizationRequest()` so PKCE, state,
  nonce, issuer, client, redirect, scope, and expiry stay bound to one
  transaction. The old standalone authorization URL builder is no longer part
  of the package-root API.
- `parseUntrustedOAuthCallback(callbackUrl)` parses but does not validate
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
  - Returns `UntrustedDecodedJWT`. It does **not** verify signatures or claims.
- `OidcIdTokenVerifier` / `verifyIdToken(token, options)`
  - Produce opaque `VerifiedIdToken` values after discovery/JWKS signature and
    purpose-specific claim validation.
  - Require `purpose: "authorization_code"`, `"refresh"`, or `"session"`.
  - Reject `clockSkewToleranceSeconds` above 300 seconds.
- `validateOidcHashClaims(decodedJWT, options)`
  - Validates `at_hash` and `c_hash` bindings.
- `validateJwkMetadataForToken(jwk, options)`
- `JtiReplayCache`
  - Custom replay caches may return `boolean` or `Promise<boolean>` from
    `consume()`. Verification succeeds only when the settled result is exactly
    `true`; failures and malformed results fail closed. Expiration and
    `max_age` are rechecked after asynchronous consumption.

## Security Defaults

- HTTPS required for authority and absolute endpoints (localhost exceptions for local development paths where applicable)
- HTTP redirects are rejected in client requests (`fetch` uses `redirect: "error"`)
- Authorization and DPoP headers are size-limited (`maxAuthorizationHeaderBytes`, default `4096`)
- Transaction-bound callback validation and URL sanitization block unsolicited responses, parameter confusion, and sensitive data leakage
- Host-only cookie helper blocks `Domain` attribute usage
- Discovery metadata is origin-validated against configured authority
- PAR, registration, and logout require endpoints advertised by discovery
- RFC 8707 resource indicators must be absolute URIs (URNs are supported) and
  cannot contain fragments, raw whitespace, or controls
- Verified token claims and UserInfo JSON are detached and deeply frozen;
  named claim shapes are validated and extension claims remain `unknown`. The
  standard OIDC `profile` claim is typed and validated as a URL string.
- UserInfo requires live `OidcIdentityEvidence` and exact `sub` equality
- Historical ID-token evidence may relax expiration only; future `nbf` values
  and validity windows that never opened are rejected before refresh I/O
- Malformed JWT content and unrecognized response-controlled OAuth error values
  are never copied into exceptions or logs
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
    compareAndRemoveItem?(
      key: string,
      expectedValue: string,
    ): boolean | Promise<boolean>;
  };
  debug?: boolean;
}
```

Implement `compareAndRemoveItem` atomically whenever separate SDK adapter
instances share one durable backend. It prevents stale-session cleanup from
deleting a newer login written by another client.

## Release Checklist

From the monorepo root:

```bash
npm test
npm run typecheck
npm run lint
npm run build
npm audit --omit=dev
npm pack --dry-run -w @guardhouse/core
npm pack --dry-run -w @guardhouse/react
npm pack --dry-run -w @guardhouse/node
npm pack --dry-run -w @guardhouse/react-native
```

This verifies build output, typings, tests, production dependencies, and
publishable package contents for all workspace packages.

## License

Apache-2.0
