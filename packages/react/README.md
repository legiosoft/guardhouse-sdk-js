# @guardhouse/react

React SDK for adding Guardhouse/OIDC authentication to React 18+ browser apps.

## Installation

```bash
npm install @guardhouse/react@2.0.0-beta.1
```

## Example Project

- Reference implementation: [`examples/react`](../../examples/react)

## What You Get

- `GuardhouseProvider` for auth state and callback handling
- `useAuth()` hook for login, logout, user state, and token access
- `ProtectedRoute` and `withAuthenticationRequired` route guards
- Session persistence in `sessionStorage` (not `localStorage`)

## Quick Start

### 1) Wrap your app with `GuardhouseProvider`

```tsx
import { GuardhouseProvider } from "@guardhouse/react";
import { BrowserRouter } from "react-router-dom";

export function Root() {
  return (
    <GuardhouseProvider
      config={{
        authority: "https://auth.example.com",
        clientId: "your-client-id",
        audience: "https://api.example.com",
        resource: "https://api.example.com",
        audiencePolicy: "guardhouse-required",
        redirectUri: `${window.location.origin}/callback`,
        logoutRedirectUri: `${window.location.origin}/callback`,
        allowedPostLogoutRedirectUris: [`${window.location.origin}/callback`],
      }}
    >
      <BrowserRouter>{/* your routes */}</BrowserRouter>
    </GuardhouseProvider>
  );
}
```

### 2) Use `useAuth()` in your UI

```tsx
import { useAuth } from "@guardhouse/react";

export function AccountPanel() {
  const { isLoading, isAuthenticated, user, loginWithRedirect, logout } =
    useAuth();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <button onClick={() => void loginWithRedirect()}>Sign in</button>;
  }

  return (
    <div>
      <div>Signed in as {user?.name ?? user?.sub}</div>
      <button onClick={() => void logout()}>Sign out</button>
    </div>
  );
}
```

## Route Guards

### `ProtectedRoute`

```tsx
import { ProtectedRoute } from "@guardhouse/react";

<Route
  path="/settings"
  element={
    <ProtectedRoute
      onRedirecting={() => <div>Redirecting...</div>}
      onRedirectError={({ error, retry }) => (
        <div role="alert">
          <p>{error.message}</p>
          <button type="button" onClick={retry}>
            Retry sign in
          </button>
        </div>
      )}
    >
      <SettingsPage />
    </ProtectedRoute>
  }
/>;
```

### `withAuthenticationRequired`

```tsx
import { withAuthenticationRequired } from "@guardhouse/react";

type BillingProps = {
  orgId: string;
};

function BillingPage({ orgId }: BillingProps) {
  return <div>Billing for {orgId}</div>;
}

export const ProtectedBillingPage = withAuthenticationRequired<BillingProps>(
  BillingPage,
  {
    returnTo: "/billing",
    onRedirecting: () => <div>Redirecting...</div>,
  },
);
```

Both guards include React 18 Strict Mode safeguards to avoid duplicate login redirects.

## `useAuth()` API

`useAuth()` returns:

- `isLoading`: `boolean`
- `isAuthenticated`: `boolean`
- `user`: OIDC user profile or `null`
- `error`: `Error | GuardhouseError | null`
- `loginWithRedirect(options?)`: starts login redirect
- `logout(options?)`: starts logout redirect
- `getAccessToken()`: returns a valid access token or `null`
- `getAccessTokenSilently()`: silent token retrieval/refresh or `null`

## Provider Configuration (Most Used)

| Option                          | Required      | Purpose                                                                                               |
| ------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------- |
| `authority`                     | Yes           | OIDC issuer base URL                                                                                  |
| `clientId`                      | Yes           | OAuth/OIDC client ID                                                                                  |
| `redirectUri`                   | Yes           | Callback URI registered at your IdP                                                                   |
| `audience`                      | Usually       | Guardhouse API audience                                                                               |
| `resource`                      | No            | One or more RFC 8707 resource indicators                                                              |
| `audiencePolicy`                | No            | Defaults to `guardhouse-required`; use `oidc-optional` only for identity-only OIDC                    |
| `logoutRedirectUri`             | No            | Exact allowlisted post-logout redirect URI                                                            |
| `allowedPostLogoutRedirectUris` | For redirects | Exact post-logout redirect allowlist used to validate runtime `returnTo` values                       |
| `scope`                         | No            | Defaults to `openid profile email`                                                                    |
| `maxAgeSeconds`                 | No            | Requires sufficiently recent authentication                                                           |
| `requiredAcrValues`             | No            | Exact accepted ACR values                                                                             |
| `requiredAmrValues`             | No            | Exact AMR values that must all be present                                                             |
| `onRedirectCallback`            | No            | Async-capable callback receiving optional `appState`; overrides default `location.replace` navigation |
| `allowOfflineAccessScope`       | No            | Required if requesting `offline_access`                                                               |
| `debug`                         | No            | Enables SDK debug logs                                                                                |

For advanced options (timeouts, endpoint overrides, DPoP, hardening flags), use the fields available in `GuardhouseConfig`.

## SSR / Next.js / Remix

- `GuardhouseProvider` and `useAuth()` are client-side APIs (they use browser storage/location).
- Place auth components behind a client boundary (`"use client"` in Next.js).
- First render starts with `isLoading: true`, then auth state is restored on the client.
- Always branch on `isLoading` before rendering auth-required UI.

```tsx
"use client";

import { useAuth } from "@guardhouse/react";

export function AuthGate() {
  const { isLoading, isAuthenticated } = useAuth();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return isAuthenticated ? <Dashboard /> : <LoginScreen />;
}
```

## Security and Runtime Notes

- Session schema v3 records are stored only in `sessionStorage`, namespaced by
  canonical issuer and client ID. Legacy and mismatched records are discarded.
- The SDK does not use `localStorage` for auth session persistence.
- Callback handling requires an active transaction and uses `@guardhouse/core`
  signature and claim verification before restoring identity. The validated
  callback is client-owned, one-use evidence and is consumed before token I/O.
- Users and roles are rebuilt from verified identity plus subject-bound UserInfo;
  serialized user claims are not trusted across restore or refresh. Returned
  users, arrays, and nested custom claims are immutable; extension claims remain
  typed as `unknown` until the application validates them.
- Callback redirect matching is exact, including native-safe scheme/authority,
  path, ordered query tuples, and fragment semantics. Credentials and OAuth
  response parameters are removed from recognized callback URLs.
- Every restore and refresh completion is bound to the original raw session
  snapshot. If another provider has already stored a newer session, React never
  publishes or overwrites the stale identity and makes one bounded restore
  attempt for the winner.
- The browser adapter implements atomic compare-and-set and compare-and-remove.
  Custom adapters that wrap one shared backend should implement optional
  `compareAndSetItem` and `compareAndRemoveItem` so commits and cleanup remain
  atomic across separate provider instances.
- Concurrent refresh requests are deduplicated to avoid refresh-token rotation races.
- `loginWithRedirect()` rejects with the original error. Handle rejection when
  starting login from an event handler.

## Integration Checklist

- Register exact `redirectUri` and `logoutRedirectUri` in your IdP client settings.
- Set a valid `audience` or `resource`, or explicitly choose
  `audiencePolicy: "oidc-optional"` for identity-only OIDC.
- If requesting `offline_access`, set `allowOfflineAccessScope: true`.
- Ensure protected pages handle `isLoading` and unauthenticated states explicitly.

See [`MIGRATION-2.0.md`](../../MIGRATION-2.0.md) for the v2 breaking changes,
session migration, and transaction-bound callback flow.

## License

See the repository `LICENSE` file.
