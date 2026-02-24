# @guardhouse/react

Frontend SDK for React 18+ web applications with hooks and protected routes.

## Features

- **Auth Context**: GuardhouseProvider component for managing authentication state
- **React Hooks**: useAuth hook for accessing user profile and auth methods
- **Session-Only Storage**: OIDC session + token data is persisted in `sessionStorage`
- **Debug Mode**: Set `config.debug = true` to trace SDK activity
- **Protected Routes**: ProtectedRoute component to secure routes
- **Core Security Policies**: React provider uses `@guardhouse/core` client flows (strict endpoint/origin checks, callback validation, silent-auth safeguards, DPoP/security config support)
- **React 18 Compatible**: Supports Concurrent Mode and Server Components

## Installation

```bash
npm install @guardhouse/react
```

## Usage

```typescript
import { GuardhouseProvider, useAuth, ProtectedRoute } from '@guardhouse/react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <GuardhouseProvider
      config={{
        authority: 'https://auth.guardhouse.io',
        clientId: 'your-client-id',
        audience: 'https://api.guardhouse.io',
        // Set to true for providers that reject audience
        // allowAuthorizationWithoutAudience: true,
        redirectUri: window.location.origin + '/callback',
        debug: true,
      }}
    >
      <BrowserRouter>
        <Routes>
          <Route path="/protected" element={
            <ProtectedRoute>
              <ProtectedPage />
            </ProtectedRoute>
          } />
        </Routes>
      </BrowserRouter>
    </GuardhouseProvider>
  );
}

function ProtectedPage() {
  const { user, loginWithRedirect, logout } = useAuth();

  return (
    <div>
      <h1>Hello, {user?.name}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## Security Notes

- The React SDK does not use `localStorage` for tokens or OIDC session persistence.
- OIDC session data (access token, refresh token, ID token, expiry, user claims, issuer/audience context) is stored in `sessionStorage` only.
- Callback handling and token operations are delegated to `@guardhouse/core` so the same hardened security checks are consistently applied.
- For IdPs that reject `audience` on `/authorize`, set `allowAuthorizationWithoutAudience: true` and omit `audience`.

## License

See LICENSE file for details.
