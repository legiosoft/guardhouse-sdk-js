# React Example

This is a complete example of a React application using `@guardhouse/react` for OAuth 2.0 authentication.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- Protected routes
- User profile display
- Token management
- API integration example
- React Router for navigation

## Prerequisites

- Node.js >= 18.0.0
- A Guardhouse instance running
- Node example server running (for API demo)

## Setup

1. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

2. Configure your environment variables in `.env`:

```env
VITE_AUTHORITY=https://your-guardhouse-domain.com
VITE_CLIENT_ID=your-client-id
VITE_REDIRECT_URI=http://localhost:3000
```

3. Install dependencies:

```bash
npm install
```

## Running

Development mode:

```bash
npm run dev
```

The app will be available at `http://localhost:3000`.

Production build:

```bash
npm run build
npm run preview
```

## Pages

### Home Page (`/`)

- Shows user profile if authenticated
- Login/logout button
- User information display (name, email, roles, etc.)

### Protected Page (`/protected`)

- Requires authentication
- Shows detailed user information
- Automatically redirects if not authenticated

### API Demo (`/api`)

- Demonstrates calling a protected API endpoint
- Uses access token to authenticate requests
- Displays API response

## Usage Examples

### Basic Usage

```tsx
import { GuardhouseProvider, useAuth } from "@guardhouse/react";

function App() {
  return (
    <GuardhouseProvider
      authority={AUTHORITY}
      clientId={CLIENT_ID}
      redirectUri={REDIRECT_URI}
    >
      <YourApp />
    </GuardhouseProvider>
  );
}

function YourApp() {
  const { user, isAuthenticated, isLoading, loginWithRedirect, logout } =
    useAuth();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <>
      {isAuthenticated ? (
        <>
          <p>Welcome, {user?.name}</p>
          <button onClick={logout}>Logout</button>
        </>
      ) : (
        <button onClick={() => loginWithRedirect()}>Login</button>
      )}
    </>
  );
}
```

### Accessing User Information

```tsx
const { user } = useAuth();

console.log(user?.sub); // Subject ID
console.log(user?.name); // User's name
console.log(user?.email); // User's email
console.log(user?.roles); // User's roles
```

### Calling Protected APIs

```tsx
const { getAccessToken } = useAuth();

const fetchData = async () => {
  const token = await getAccessToken();

  if (token) {
    const response = await fetch("http://api.example.com/protected", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await response.json();
    console.log(data);
  }
};
```

### Custom Redirect After Login

```tsx
const { loginWithRedirect } = useAuth();

const handleLogin = () => {
  loginWithRedirect({
    appState: { returnTo: "/dashboard" },
  });
};
```

### Protected Routes

```tsx
function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/" />;
  }

  return <>{children}</>;
}

// Usage
<Route
  path="/dashboard"
  element={
    <ProtectedRoute>
      <Dashboard />
    </ProtectedRoute>
  }
/>;
```

## Configuration

### GuardhouseProvider Props

```tsx
<GuardhouseProvider
  authority="https://your-domain.com"        // Required: Guardhouse domain
  clientId="your-client-id"                // Required: Application client ID
  redirectUri="http://localhost:3000"       // Required: OAuth callback URL
  onRedirectCallback={(appState) => {        // Optional: Redirect callback
    console.log("Redirected:", appState);
  }}
  scope="openid profile email"               // Optional: Default scopes
>
```

### Environment Variables

| Variable            | Description           | Example                    |
| ------------------- | --------------------- | -------------------------- |
| `VITE_AUTHORITY`    | Guardhouse domain     | `https://auth.example.com` |
| `VITE_CLIENT_ID`    | Application client ID | `your-client-id`           |
| `VITE_REDIRECT_URI` | OAuth callback URL    | `http://localhost:3000`    |

## Features Explained

### OAuth 2.0 Flow

1. **Login**: User clicks login button
2. **Redirect**: Browser redirects to Guardhouse
3. **Authorize**: User authorizes the application
4. **Callback**: Guardhouse redirects back with authorization code
5. **Token Exchange**: Code is exchanged for tokens
6. **Session**: User is logged in and tokens are stored

### Token Management

- Access tokens are stored in localStorage
- Tokens are automatically refreshed when expired
- Session is restored on page load

### Security

- PKCE with S256 for authorization code flow
- State parameter for CSRF protection
- HTTPS required for all requests
- Secure token storage

## Troubleshooting

### "Callback URL mismatch"

Ensure `VITE_REDIRECT_URI` matches exactly what's configured in Guardhouse.

### "Client ID not found"

Verify `VITE_CLIENT_ID` is correct and exists in Guardhouse.

### CORS Errors

Ensure Guardhouse allows requests from your origin.

### API Demo Not Working

Ensure the Node example server is running on port 3001:

```bash
cd ../../examples/node
npm run dev
```

## Building for Production

1. Create production `.env` file with correct values
2. Build the application:

```bash
npm run build
```

3. Preview the build:

```bash
npm run preview
```

4. Deploy the `dist` folder to your hosting provider

## License

MIT
