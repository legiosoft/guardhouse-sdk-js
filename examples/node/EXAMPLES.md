# Node.js Examples

Simple examples demonstrating how to use Guardhouse SDK for Node.js.

## Client Example

Shows how to use Guardhouse as an OAuth 2.0 client to authenticate users and obtain tokens using **Client Credentials flow** (backend-to-backend).

```bash
# Run the client example
npm run client
```

The client example demonstrates:

- Using GuardhouseNodeClient for client credentials flow
- Using GuardhouseClient directly
- Fetching user information
- Making authenticated requests with GuardhouseNodeClient
- GuardhouseAdminClient for administrative operations

**Note:** Client credentials flow doesn't need a redirect URI or PKCE - that's only for the authorization code flow (user login). See the full server example at `src/index.ts` for authorization code flow.

## Resource Example

Shows how to protect API endpoints using Guardhouse middleware with Express.

**Yes, you need a framework!** The resource example uses Express.js because the Guardhouse middleware is designed for Express/Connect-based frameworks.

```bash
# Run the resource server example
npm run resource
```

The resource example demonstrates:

- Setting up an Express server
- Using Guardhouse middleware for JWT validation
- Creating public and protected endpoints
- Role-based access control
- Accessing user information from validated tokens

### Testing the Resource Server

**Public endpoint (no token required):**

```bash
curl http://localhost:3001/public
```

**Protected endpoint (requires valid JWT):**

```bash
curl http://localhost:3001/protected \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Admin endpoint (requires admin role):**

```bash
curl http://localhost:3001/protected/admin \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Environment Variables

Create a `.env` file with your Guardhouse configuration:

```env
# Guardhouse Authority URL
AUTHORITY=https://your-guardhouse-domain.com

# Client Credentials (for backend-to-backend)
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret

# Resource Server (for protected API endpoints)
AUDIENCE=your-api-audience

# Server Port
PORT=3001
```

## Getting a Token

The client example uses the **Client Credentials flow** (backend-to-backend). No redirect URI or PKCE needed.

**Using curl directly:**

```bash
curl -X POST https://your-guardhouse-domain.com/connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=openid profile email"
```

**Using the Node client programmatically:**

```typescript
import { GuardhouseNodeClient } from "@guardhouse/node";

const client = new GuardhouseNodeClient({
  authority: "https://your-guardhouse-domain.com",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  scope: "openid profile email",
});

const accessToken = await client.getAccessToken();
```

## Quick Start

1. **Setup environment:**

   ```bash
   cp .env.example .env
   # Edit .env with your Guardhouse credentials
   ```

2. **Run the client example:**

   ```bash
   npm run client
   ```

3. **Run the resource server:**
   ```bash
   npm run resource
   # In another terminal, test with:
   curl http://localhost:3001/public
   ```

## OAuth 2.0 Flow Differences

### Client Credentials Flow

- **Use case:** Backend-to-backend communication
- **No user login:** Just service authentication
- **No redirect URI:** Not applicable
- **No PKCE:** Not needed
- **How to get token:** Direct request with client_id and client_secret

### Authorization Code Flow

- **Use case:** User login with browser
- **User authentication:** User logs in via browser
- **Redirect URI:** Required - where user is sent after login
- **PKCE:** Required - for security
- **How to get token:** User authorizes, then exchange code for token

For authorization code flow, see the full server example at `src/index.ts`.
