# Migrating to Guardhouse JavaScript SDK v2 Beta

This guide covers the security-breaking changes in `@guardhouse/core` and
`@guardhouse/react` `2.0.0-beta.1`. The release deliberately removes APIs that
allowed an authorization response or decoded token to be trusted without the
request and cryptographic context that produced it.

## Release Set

Use the beta packages as one tested release set:

| Package                    | Version                                           |
| -------------------------- | ------------------------------------------------- |
| `@guardhouse/core`         | `2.0.0-beta.1`                                    |
| `@guardhouse/react`        | `2.0.0-beta.1`                                    |
| `@guardhouse/node`         | `1.0.2-beta.1` with Core pinned to `2.0.0-beta.1` |
| `@guardhouse/react-native` | `1.0.2-beta.1` with Core pinned to `2.0.0-beta.1` |

Install prereleases explicitly:

```bash
npm install @guardhouse/core@2.0.0-beta.1
npm install @guardhouse/react@2.0.0-beta.1
```

Do not mix React v2 with Core v1. Existing browser sessions and pending login
records are not compatible with the new schemas; the SDK discards them and the
user must authenticate again.

## Core API Replacements

| Removed or changed API                                                                                                    | v2 replacement                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Manually combine `generatePKCE()`, `generateState()`, `generateNonce()`, and `generateAuthUrl()` for an application login | `client.createAuthorizationRequest()` and persist its returned `transaction` under its `state`                                             |
| `exchangeCodeForTokens(code, verifier, redirectUri, ...)`                                                                 | Validate with `client.validateOAuthCallback(input, transaction)`, then call the one-argument `client.exchangeAuthorizationCode(callback)`  |
| `exchangeAuthorizationCode(callback, transaction)`                                                                        | `exchangeAuthorizationCode(callback)`; Core privately recovers and consumes the transaction bound to that callback                         |
| `exchangeCodeForTokensUsingHandle(...)`                                                                                   | Restore the complete transaction with `client.restoreAuthorizationTransaction(...)`, validate the callback, then consume the opaque result |
| `validateOAuthCallback(callbackUrl, expectedState, ...)`                                                                  | `validateOAuthCallback({ mode: "query", url }, transaction)` or the `form_post` input variant                                              |
| `refreshToken(refreshToken, params?)`                                                                                     | `refreshOAuthToken(...)` for OAuth-only sessions or `refreshOidcSession(...)` for OIDC sessions                                            |
| Generic public `postForm<T>(...)`                                                                                         | `exchangeAuthorizationCode`, `refreshOAuthToken`, `refreshOidcSession`, `requestClientCredentialsToken`, or `introspectToken`              |
| `getUserInfo(token, expectedSubject?)`                                                                                    | `getUserInfo(token, verifiedIdentity)`                                                                                                     |
| `validateToken(...)`, `TokenValidationOptions`, `signatureVerified`, and `VerifiedSignatureProof`                         | `OidcIdTokenVerifier.verify(...)` or `verifyIdToken(...)`, which alone produce `VerifiedIdToken`                                           |
| Treating `decodeJWT()` as authenticated data                                                                              | Treat its `UntrustedDecodedJWT` result only as untrusted diagnostic data                                                                   |
| Client-selected PAR or registration endpoint overrides                                                                    | Discovery-driven `createPushedAuthorizationRequest(...)` and `registerClient(...)`                                                         |
| Synchronous logout URL construction or `logoutEndpoint` override                                                          | Await discovery-driven `buildLogoutUrl(...)` or `prepareSharedDeviceLogout(...)`                                                           |

`responseType` is now typed and enforced as `"code"`. Implicit and hybrid
responses, front-channel tokens, duplicate parameters, mixed response channels,
and callbacks without a matching active transaction are rejected.

## Core Authorization Code Flow

Create one transaction for each login attempt and store the complete record
atomically under its generated state. Namespace your storage by canonical issuer
and client ID. Never use one global verifier/state slot.

```ts
import { GuardhouseClient, GuardhouseError } from "@guardhouse/core";

const authority = "https://auth.example.com";
const clientId = "web-app";
const client = new GuardhouseClient({ authority, clientId });

const { authorizationUrl, transaction } =
  await client.createAuthorizationRequest({
    redirectUri: "https://app.example.com/callback",
    scope: "openid profile email",
    audience: "https://api.example.com",
    audiencePolicy: "guardhouse-required",
    resource: ["https://api.example.com"],
    maxAgeSeconds: 3600,
  });

sessionStorage.setItem(
  `oauth:${encodeURIComponent(transaction.state)}`,
  JSON.stringify(transaction),
);
window.location.assign(authorizationUrl);
```

On return, use the untrusted state only to locate the candidate record. Restoring
the transaction and validating the response perform the security checks.

```ts
const callbackUrl = window.location.href;
const returnedState = new URL(callbackUrl).searchParams.get("state");
if (!returnedState) throw new Error("No active authorization transaction");

const key = `oauth:${encodeURIComponent(returnedState)}`;
const serialized = sessionStorage.getItem(key);
if (!serialized) throw new Error("No active authorization transaction");

const restored = client.restoreAuthorizationTransaction(JSON.parse(serialized));
const callback = await client.validateOAuthCallback(
  { mode: "query", url: callbackUrl },
  restored,
);

// The URL should be replaced with callback.sanitizedUrl after any recognized
// success or error response, before rendering application content.
window.history.replaceState({}, document.title, callback.sanitizedUrl);
sessionStorage.removeItem(key);

if (callback.type === "error") {
  throw new GuardhouseError(
    callback.errorDescription ?? callback.error,
    callback.error,
  );
}

const result = await client.exchangeAuthorizationCode(callback);
if (result.mode !== "oidc") throw new Error("An OIDC response was required");

const user = await client.getUserInfo(
  result.tokens.access_token,
  result.identity,
);
```

The validated callback is runtime-opaque evidence owned by the client instance
that validated it. It cannot be fabricated, serialized for later use, moved to
another client, or exchanged twice. Core consumes that private evidence before
starting the token request, so even a failed network exchange cannot replay it.

Redirect matching is exact across scheme, authority, path, ordered query tuples,
and fragment. This applies to HTTPS and native custom-scheme callbacks alike.
Redirects containing credentials are rejected; recognized callback sanitation
removes credentials and OAuth response parameters.

For `responseMode: "form_post"`, pass
`{ mode: "form_post", url, body }`, where `body` is `URLSearchParams` or a
string-valued record. Do not accept query, fragment, and form parameters in the
same response.

### Audience and resource policy

The default `audiencePolicy` is `"guardhouse-required"`; at least one Guardhouse
`audience` or RFC 8707 `resource` value is required. Use
`"oidc-optional"` only for a standards-compliant identity-only OIDC request that
intentionally has neither value.

`resource` accepts one absolute URI or a readonly array and is emitted as a
repeatable parameter. URNs are valid resource indicators. Relative references,
fragments, leading/trailing whitespace, and control characters are rejected.
The same validation is used for authorization, restored transactions, PAR, and
client credentials. Do not overload `scope` with resource identifiers.

## Verified OIDC Identity

`VerifiedIdToken` is opaque and readonly. Only successful signature and claim
verification can create it. Verification discovers the issuer metadata and JWKS,
restricts algorithms and token `typ`, validates the key/signature, and enforces
issuer, audience/`azp`, time, nonce, and purpose-specific identity rules.

Core deliberately separates serializable identity data from live verification
evidence:

- `OidcIdentityMetadata` is a plain, serializable claim snapshot. It is safe to
  persist, but it is never proof of authentication and cannot be passed back to
  security-sensitive APIs.
- `OidcIdentity` is runtime-opaque evidence for a currently valid ID token.
- `HistoricalOidcIdentity` is runtime-opaque evidence recovered from the prior
  signed token during refresh. It may bind the refresh and a fresh UserInfo
  response, but it is not a current authentication credential.
- `OidcIdentityEvidence` is the current-or-historical union accepted by
  UserInfo and refresh identity binding.

Never cast deserialized `OidcIdentityMetadata` to an evidence type. Reverify the
signed ID token with the appropriate purpose instead.

Identity metadata describes the current signed token exactly. When a refresh ID
token omits `nonce` or `auth_time`, the corresponding metadata value is `null`;
it is not copied from an older token. The verifier retains the original
continuity constraints privately when live identity evidence is passed through
successive refresh verifications. Those constraints are not serialized claims
and cannot be recreated by casting a stored object to an evidence type.
After a cold start, fresh evidence is established from the stored signed token;
private refresh history is not recovered from serialized metadata.

Choose an explicit verification purpose:

```ts
import { OidcIdTokenVerifier } from "@guardhouse/core";

const verifier = new OidcIdTokenVerifier({ authority, clientId });

const initial = await verifier.verify(rawIdToken, {
  purpose: "authorization_code",
  nonce: transaction.nonce,
  maxAgeSeconds: transaction.maxAgeSeconds,
});

const refreshed = await verifier.verify(replacementIdToken, {
  purpose: "refresh",
  previousIdentity: initial.identity,
});

const current = await verifier.verify(storedIdToken, {
  purpose: "session",
});
```

- `authorization_code` requires the transaction nonce and optionally enforces
  `max_age`. Supply an `IdTokenReplayCache` to opt into issuer-plus-`jti`
  replay detection when the issuer provides that claim.
- `refresh` requires the prior verified identity and rejects issuer, subject,
  audience/`azp`, nonce-semantic, or `auth_time` changes.
- `session` fully revalidates the current token before restoring identity.
- UserInfo now requires live `OidcIdentityEvidence`; its `sub` must exactly
  match. Plain or deserialized `OidcIdentityMetadata` is rejected.
- `requiredAcrValues` and `requiredAmrValues` are exact, case-sensitive
  requirements. The SDK does not infer phishing resistance from a generic
  `amr: ["mfa"]` claim.

Verification snapshots its complete purpose, audience, assurance, identity, and
replay-cache context before any discovery or JWKS work. `IdTokenReplayCache`
may return `boolean` or `Promise<boolean>`; only the exact value `true` accepts
an entry. Rejections, exceptions, malformed results, or capacity exhaustion fail
closed. `clockSkewToleranceSeconds` must be between 0 and 300 seconds, and replay
entries are retained through token expiry plus that skew. After an asynchronous
replay-cache operation, Core rechecks expiration and `max_age` before issuing
verified evidence. Historical verification relaxes expiration only; a future
`nbf` or a validity window that never opened still rejects before refresh I/O.

Verified payloads, identity metadata, UserInfo arrays, and nested JSON claim
values are recursively copied and frozen. Named claims are runtime-validated;
unrecognized extension claims are exposed as `unknown`, not implicitly trusted.
The standard OIDC `profile` claim is a URL string, not a nested object.

If all you need is to inspect a token while debugging, `decodeJWT()` remains
available, but its result must never drive authentication or authorization.
Malformed token bytes are never copied into decoder errors or logs. Likewise,
HTTP OAuth failures expose only recognized standardized error identifiers;
untrusted or vendor-controlled values become the generic `server_error`.

## Explicit Token Operations

Use the operation that matches the grant and identity model:

```ts
const serviceTokens = await confidentialClient.requestClientCredentialsToken({
  scope: "orders.read",
  resource: "https://api.example.com",
});

const oauthTokens = await client.refreshOAuthToken(refreshToken, {
  grantedScope: previousScope,
});

const oidcRefresh = await client.refreshOidcSession(refreshToken, {
  previousIdToken: rawPreviousIdToken,
  grantedScope: previousScope,
  requiredAcrValues: ["urn:guardhouse:acr:strong"],
  requiredAmrValues: ["pwd", "otp"],
});

const refreshedUser = await client.getUserInfo(
  oidcRefresh.tokens.access_token,
  oidcRefresh.identity,
);

if (oidcRefresh.identityStatus === "current") {
  // The response supplied a replacement, currently valid ID token.
  const signedIdToken = oidcRefresh.tokens.id_token;
  if (!signedIdToken) throw new Error("Missing replacement ID token");
  persistCurrentSignedIdToken(signedIdToken);
} else {
  // The previous signed token is historical evidence only. Keep it private,
  // never expose it as a current credential, and require reauthentication when
  // a current identity cannot be re-established.
}
```

An authorization-code request containing `openid` must return an ID token.
When refresh omits `id_token`, React and React Native can restore the session
after a reload or cold start while its access token is still valid. Core's
additive `restoreOidcSession(accessToken, { idToken, requiredAcrValues,
requiredAmrValues })` API re-verifies the old token's signature, issuer, client,
temporal consistency and assurance requirements, then requires a successful
UserInfo response with the same subject. It returns historical identity evidence
and fresh UserInfo, not a current ID token, and does not rotate refresh tokens or
write Core session state. Ordinary `verifyIdToken(..., { purpose: "session" })`
continues to reject expired tokens.

Historical restoration requires online UserInfo validation; old ID-token claims
and serialized user/role data are not restored as current profile information.
Native also performs this validation when `userInfoOnLogin: false`, but returns
only the subject in that case. Its same-instance historical session cache remains
available. Current-token login and restoration keep their existing behavior.
React adds an optional `idTokenCurrent` flag to v3 records; earlier v3 records
remain readable, and expired ID tokens follow the historical restoration path.
Storage namespaces and the v3 schema version are unchanged.

### Recovering from temporary restoration failures

Network failures, metadata timeouts and HTTP 408/429/5xx availability failures
during session verification preserve stored credentials. They do not authenticate
the user. Signature, identity, subject-binding and revoked-token failures still
reject and clear the invalid session. Invalid metadata is not treated as a network
outage merely because verification could not complete.

React reports restoration failures in `auth.error`. Calling `getAccessToken()` or
`getAccessTokenSilently()` again revalidates the saved session; neither returns a
token from a record that has not been verified in this provider. A successfully
verified, unchanged record can still use the existing fast path. ProtectedRoute
shows Retry for temporary restoration failures instead of starting a new login;
its existing `onRedirectError` renderer also receives these errors and a retry
callback that repeats restoration.

Core `getSessionState()` now rejects with the availability error instead of
silently returning null and deleting the record. Native restoration/getter methods
also preserve credentials and reject on temporary failure. Callers can use the
additive `isTransientAuthError(error)` helper to decide when to offer another
attempt. Retry is explicit; this change adds no background retry loop.

This classification does not authorize replaying a refresh grant that might have
already consumed its token. Existing cleanup after a successful refresh response
followed by validation/UserInfo failure remains unchanged; the old rotated refresh
token must not be reused.

OAuth-only exchanges and refreshes reject an unexpected ID token. Refresh scope
may narrow but must not escalate beyond the previously granted scope.

## Discovery-Driven PAR, Registration, and Logout

PAR, dynamic client registration, and logout no longer fall back to hardcoded
paths. The issuer metadata must advertise the corresponding endpoint or the
operation fails with `GuardhouseError.code === "UNSUPPORTED_FEATURE"` before a
feature request is sent.

```ts
const created = await client.createAuthorizationRequest(options);
const pushed = await client.createPushedAuthorizationRequest(
  created.transaction,
);
const parAuthorizationUrl = client.buildPushedAuthorizationUrl(
  pushed,
  created.transaction,
);

const registration = await client.registerClient(metadata, initialAccessToken);

const logoutUrl = await client.buildLogoutUrl({
  idTokenHint,
  postLogoutRedirectUri: "https://app.example.com/signed-out",
});
```

The PAR authorization URL contains only `client_id` and the one-use
`request_uri`. Configure every permitted post-logout URL in
`allowedPostLogoutRedirectUris`; matching is exact.

## Durable Storage Cleanup

Core and React storage adapters now accept an optional atomic conditional
remove operation:

```ts
interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  compareAndSetItem?(
    key: string,
    expectedValue: string,
    value: string,
  ): boolean | Promise<boolean>;
  compareAndRemoveItem?(
    key: string,
    expectedValue: string,
  ): boolean | Promise<boolean>;
}
```

Implement the conditional operations when separate adapter instances can share
one backend. They must modify only when the current raw serialized value exactly
matches `expectedValue`. Core uses compare-and-remove for stale cleanup; React
also uses compare-and-set so a refresh cannot overwrite a newer login. Fallbacks
are serialized inside one SDK process, but only the backend can make
cross-wrapper updates atomic. Explicit logout remains an intentional
unconditional clear.

## React v2 Migration

### Provider configuration

Remove `responseType`, `requestUri`, and
`allowAuthorizationWithoutAudience`. Authorization Code + PKCE is the only
browser response type.

```tsx
<GuardhouseProvider
  config={{
    authority: "https://auth.example.com",
    clientId: "web-app",
    redirectUri: `${window.location.origin}/callback`,
    logoutRedirectUri: `${window.location.origin}/signed-out`,
    allowedPostLogoutRedirectUris: [`${window.location.origin}/signed-out`],
    audience: "https://api.example.com",
    resource: ["https://api.example.com"],
    audiencePolicy: "guardhouse-required",
    maxAgeSeconds: 3600,
    requiredAcrValues: ["urn:guardhouse:acr:strong"],
    requiredAmrValues: ["pwd", "otp"],
    onRedirectCallback: async (appState) => {
      await router.navigate(appState?.returnTo ?? "/");
    },
  }}
>
  <App />
</GuardhouseProvider>
```

Use `audiencePolicy: "oidc-optional"` for an intentional identity-only OIDC
request. `resource`, `maxAgeSeconds`, and exact ACR/AMR requirements can be
configured on the provider; `audience`, `resource`, and `maxAgeSeconds` may also
be supplied to `loginWithRedirect()`.

### Session behavior

React uses session schema v3 and namespaces records by canonical issuer and
client ID. Legacy, malformed, or cross-tenant records are discarded. The SDK
persists tokens and verified identity metadata, not trusted serialized user or
role claims. On restore and refresh it verifies the signed identity again and
rebuilds the user from subject-bound UserInfo.

Cleanup carries the exact raw session snapshot through restore and refresh. If
another provider writes a newer session, stale cleanup preserves it and performs
one bounded restore attempt. Browser session storage implements synchronous CAS,
and provider locks are keyed by the storage namespace so separate wrappers over
the same browser backend coordinate.

Applications must tolerate a one-time sign-in after upgrading. Do not copy old
`gh_oidc_session` data into the v3 namespace.

`useAuth().error` is now `Error | GuardhouseError | null`, rather than a string.
Read `error.message` for display and `GuardhouseError.code` for stable handling.
`loginWithRedirect()` rejects with the original error, so event handlers that
start login without awaiting it should explicitly handle rejection.

### Redirects and protected routes

The provider preserves `pathname + search + hash` by default and accepts only a
same-origin relative `returnTo`. If no `onRedirectCallback` is supplied, callback
navigation uses `window.location.replace()`.

`ProtectedRoute` now has a discriminated rendering API: use either `children` or
`component` together with `componentProps`.

```tsx
<ProtectedRoute
  component={BillingPage}
  componentProps={{ orgId }}
  onRedirectError={({ error, retry }) => (
    <div role="alert">
      <p>{error.message}</p>
      <button type="button" onClick={retry}>
        Retry sign in
      </button>
    </div>
  )}
/>
```

The existing child form remains valid:

```tsx
<ProtectedRoute>
  <SettingsPage />
</ProtectedRoute>
```

Provider-level deduplication prevents React Strict Mode or multiple guards from
starting competing login transactions. A failed redirect clears the latch so a
route can retry.

## Node and React Native Consumers

The Node and React Native package versions remain `1.0.2-beta.1`, but they pin
Core `2.0.0-beta.1` and are part of the same beta release train.

- Node integrations and direct Core consumers must use the explicit client
  credentials, refresh, and introspection operations instead of `postForm<T>`.
- Node `requiredScopes` are unique, valid OAuth scope tokens and are enforced as
  an exact, case-sensitive all-of requirement after JWT or introspection
  validation, including cached introspection results. Missing scope data fails.
- React Native authorization must retain the complete transaction until the
  deep-link callback is validated. Code exchange without an active transaction
  and accepting tokens directly from a front channel are no longer supported.
- React Native persisted sessions must be issuer/client-bound and rebuilt from a
  verified identity. Legacy records should cause reauthentication. User and
  nested custom claims returned by the SDK are immutable.

Rebuild and typecheck all workspaces after updating; a successful Core build is
required before packages that consume its generated declarations.

## Upgrade Checklist

- Remove imports of the deleted token-validation and raw form APIs.
- Convert every authorization-code flow to create, persist, restore, validate,
  and consume one `AuthorizationTransaction`; pass only the resulting opaque
  callback to the one-argument exchange method.
- Store concurrent transactions separately by state and namespace storage by
  normalized issuer plus client ID.
- Pass only live `OidcIdentityEvidence` produced by Core verification to
  UserInfo and refresh identity binding. Persist only `OidcIdentityMetadata`;
  never cast it back into evidence.
- Select `refreshOAuthToken` or `refreshOidcSession` explicitly and retain the
  previously granted scope.
- Configure exact post-logout redirect allowlists and ensure discovery advertises
  PAR, registration, or logout before depending on those features.
- Implement storage CAS when distinct adapter wrappers share a durable backend.
- Keep verifier clock skew at or below 300 seconds and make custom replay caches
  return exactly `true` only after an issuer-plus-`jti` entry is consumed.
- Treat unknown extension claims as untrusted and never mutate verified or
  authenticated claim objects.
- Configure Node `requiredScopes` as the complete case-sensitive all-of set.
- Remove React v1/v2 session data and handle object-valued auth errors.
- Exercise callback, refresh, logout, protected-route retry, and multi-tenant
  session cases before deploying the beta.

Package preparation and beta publishing order are documented in
[`DEPLOYMENT.md`](./DEPLOYMENT.md). Publish in the order Core, React, Node, then
React Native.
