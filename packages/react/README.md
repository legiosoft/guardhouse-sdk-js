# @guardhouse/react

React SDK for adding Guardhouse/OIDC authentication to React 18+ browser apps.

## Installation

```bash
npm install @guardhouse/react
```

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
        redirectUri: `${window.location.origin}/callback`,
        logoutRedirectUri: `${window.location.origin}/callback`,
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
    <ProtectedRoute onRedirecting={() => <div>Redirecting...</div>}>
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
- `error`: auth error message or `null`
- `loginWithRedirect(options?)`: starts login redirect
- `logout(options?)`: starts logout redirect
- `getAccessToken()`: returns a valid access token or `null`
- `getAccessTokenSilently()`: silent token retrieval/refresh or `null`

## Provider Configuration (Most Used)

| Option                              | Required | Purpose                                         |
| ----------------------------------- | -------- | ----------------------------------------------- |
| `authority`                         | Yes      | OIDC issuer base URL                            |
| `clientId`                          | Yes      | OAuth/OIDC client ID                            |
| `redirectUri`                       | Yes      | Callback URI registered at your IdP             |
| `audience`                          | Usually  | API audience for code flow                      |
| `logoutRedirectUri`                 | No       | Post-logout redirect URI                        |
| `scope`                             | No       | Defaults to `openid profile email`              |
| `onRedirectCallback`                | No       | Receives optional `appState` after callback     |
| `allowAuthorizationWithoutAudience` | No       | Set `true` only for IdPs that reject `audience` |
| `allowOfflineAccessScope`           | No       | Required if requesting `offline_access`         |
| `debug`                             | No       | Enables SDK debug logs                          |

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

- Tokens/session are stored only in `sessionStorage` under `gh_oidc_session`.
- The SDK does not use `localStorage` for auth session persistence.
- Callback handling uses `@guardhouse/core` validation and secure JWT decoding.
- Concurrent refresh requests are deduplicated to avoid refresh-token rotation races.
- If your app reads `id_token`, validate signature/claims with a proper JWT/OIDC validation library before trusting claims.

## Integration Checklist

- Register exact `redirectUri` and `logoutRedirectUri` in your IdP client settings.
- If using code flow and your IdP requires it, set a valid `audience`.
- If requesting `offline_access`, set `allowOfflineAccessScope: true`.
- Ensure protected pages handle `isLoading` and unauthenticated states explicitly.

## License

See the repository `LICENSE` file.
