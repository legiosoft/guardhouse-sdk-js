# @guardhouse/node

Backend SDK for Node.js (Express/Connect) that validates Guardhouse JWTs and provides an Admin API client.

## Features

- **JWT Validation Middleware**: Strict validation of algorithm, type, signature, issuer, audience, and expiration claims
- **JWKS Integration**: Automatic key fetching from the JWKS endpoint using jwks-rsa
- **Admin API Client**: Client credentials flow for administrative tasks
- **Express/Connect Compatible**: Works with Express and other Connect-based frameworks

## Installation

```bash
npm install @guardhouse/node express
```

## Usage

```typescript
import express from "express";
import { guardhouseMiddleware, GuardhouseNodeClient } from "@guardhouse/node";

const app = express();

// Configure authentication
app.use(
  guardhouseMiddleware({
    authority: "https://auth.guardhouse.io",
    audience: "your-api-audience",
    debug: true,
  }),
);

// Protected route
app.get("/api/protected", (req, res) => {
  res.json({ message: "Hello", user: req.user });
});

// Admin API client
const adminClient = new GuardhouseNodeClient({
  authority: "https://auth.guardhouse.io",
  clientId: "your-admin-client-id",
  clientSecret: "your-admin-client-secret",
  debug: true,
});

await adminClient.deleteUser("user-id");
```

## License

See LICENSE file for details.
