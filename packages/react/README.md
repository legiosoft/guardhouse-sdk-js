# @guardhouse/react

Frontend SDK for React 18+ web applications with hooks and protected routes.

## Features

- **Auth Context**: GuardhouseProvider component for managing authentication state
- **React Hooks**: useAuth hook for accessing user profile and auth methods
- **Token Storage**: Customizable storage adapter (defaults to localStorage)
- **Protected Routes**: ProtectedRoute component to secure routes
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
      authority="https://auth.guardhouse.io"
      clientId="your-client-id"
      redirectUri={window.location.origin + '/callback'}
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

## License

See LICENSE file for details.
