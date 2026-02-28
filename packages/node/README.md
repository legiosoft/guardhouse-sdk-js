# @guardhouse/node

Backend SDK for Node.js with JWT validation middleware and OAuth 2.0 client credentials support.

## Installation

```bash
npm install @guardhouse/node express
```

## Quick Start

### Protect API Endpoints

```typescript
import express from "express";
import { guardhouseMiddleware } from "@guardhouse/node";

const app = express();

app.use(
  guardhouseMiddleware({
    authority: "https://auth.guardhouse.io",
    audience: "your-api-audience",
  }),
);

app.get("/api/protected", (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

### Client Credentials Flow

```typescript
import { GuardhouseNodeClient } from "@guardhouse/node";

const client = new GuardhouseNodeClient({
  authority: "https://auth.guardhouse.io",
  clientId: "your-client-id",
  clientSecret: "your-client-secret",
  scope: "api://your-api/.default",
});

const accessToken = await client.getAccessToken();
```

### Admin API Client

```typescript
import { GuardhouseAdminClient } from "@guardhouse/node";

const admin = new GuardhouseAdminClient({
  authority: "https://auth.guardhouse.io",
  clientId: "admin-client-id",
  clientSecret: "admin-client-secret",
});

await admin.deleteUser("user-id");
const user = await admin.getUser("user-id");
const users = await admin.listUsers({ page: 1, pageSize: 50 });
```

## API Reference

### `guardhouseMiddleware(options)`

Express/Connect middleware for JWT validation. Populates `req.user` with the authenticated user.

```typescript
app.use(
  guardhouseMiddleware({
    authority: string;              // Required: OAuth authority URL
    audience: string;               // Required: Expected audience claim
    validationMode?: "jwt_signature" | "introspection";  // Default: "jwt_signature"
    introspectionClientId?: string; // For introspection mode
    introspectionClientSecret?: string;
    validAlgorithms?: string[];     // Default: ["RS256"]
    tokenTypes?: string[];          // Default: ["JWT", "at+JWT"]
    validateIssuer?: boolean;       // Default: true
    validateAudience?: boolean;     // Default: true
    validateLifetime?: boolean;     // Default: true
    requireHttpsMetadata?: boolean; // Default: true
    maxTokenAgeSeconds?: number;    // Max token age
    requiredScopes?: string[];      // Required scopes
    debug?: boolean;                // Enable debug logging
  })
);
```

### `GuardhouseNodeClient`

OAuth 2.0 client with automatic token caching and refresh.

```typescript
const client = new GuardhouseNodeClient({
  authority: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  enableTokenCaching?: boolean;     // Default: true
  enableTokenRefresh?: boolean;     // Default: true
  cacheExpirationBufferSeconds?: number;
  maxRetryAttempts?: number;
  debug?: boolean;
});

// Methods
await client.getAccessToken(): Promise<string>;
await client.requestToken(): Promise<TokenResponse>;
await client.refreshToken(refreshToken: string): Promise<TokenResponse>;
await client.fetch<T>(url: string, options?: RequestInit): Promise<T>;
await client.get<T>(url: string): Promise<T>;
await client.post<T>(url: string, data?: any): Promise<T>;
await client.put<T>(url: string, data?: any): Promise<T>;
await client.patch<T>(url: string, data?: any): Promise<T>;
await client.delete<T>(url: string): Promise<T>;
await client.clearCache(): Promise<void>;
```

### `GuardhouseAdminClient`

Extends `GuardhouseNodeClient` with user management methods.

```typescript
const admin = new GuardhouseAdminClient(options);

await admin.getUser(userId: string): Promise<any>;
await admin.createUser(userData: any): Promise<any>;
await admin.updateUser(userId: string, userData: any): Promise<any>;
await admin.deleteUser(userId: string): Promise<void>;
await admin.listUsers(params?: { page?: number; pageSize?: number; search?: string }): Promise<any>;
```

### `GuardhouseResourceService`

Low-level token validation service.

```typescript
const service = new GuardhouseResourceService({
  authority: string;
  audience: string;
  validationMode?: "jwt_signature" | "introspection";
  // ... same options as middleware
});

const user: GuardhouseUser = await service.validateToken(token: string);
```

### Types

```typescript
interface GuardhouseUser {
  sub: string;
  name?: string;
  email?: string;
  roles?: string[];
  scopes?: string[];
  aud?: string[];
  iss?: string;
  exp?: number;
  iat?: number;
  [key: string]: any;
}

const TokenValidationMode = {
  JwtSignature: "jwt_signature",
  Introspection: "introspection",
};

const IntrospectionCredentialTransmission = {
  BasicAuth: "basic_auth",
  FormData: "form_data",
};
```

## Token Validation Modes

### JWT Signature (Default)

Validates tokens locally using JWKS:

1. Fetches public keys from `/.well-known/jwks.json`
2. Verifies signature with allowed algorithms
3. Validates issuer, audience, expiration

### Introspection

Validates tokens via the introspection endpoint:

```typescript
app.use(
  guardhouseMiddleware({
    authority: "https://auth.guardhouse.io",
    audience: "your-api-audience",
    validationMode: "introspection",
    introspectionClientId: "introspection-client-id",
    introspectionClientSecret: "introspection-client-secret",
    introspectionCacheTtlSeconds: 300,
  }),
);
```

## Error Handling

The middleware returns standard OAuth 2.0 error responses:

```json
{
  "error": "unauthorized",
  "error_description": "Missing authorization header",
  "correlation_id": "abc123"
}
```

## Requirements

- Node.js >= 18.0.0
- Express 4.x (peer dependency)

## License

Apache-2.0
