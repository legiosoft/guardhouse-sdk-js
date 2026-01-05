# @guardhouse/core

Environment-agnostic Guardhouse SDK that serves as the shared foundation for the Guardhouse JavaScript ecosystem.

## Features

- **Shared Types**: TypeScript interfaces for GuardhouseConfig, User, TokenResponse, and GuardhouseError
- **API Client**: GuardhouseClient class wrapping the native fetch API with Authorization header injection
- **URL Construction**: Helper functions to build OIDC authorize URLs with PKCE support
- **PKCE Utilities**: Framework-agnostic functions to generate code_verifier and code_challenge

## Installation

```bash
npm install @guardhouse/core
```

## Usage

```typescript
import {
  GuardhouseClient,
  generateAuthUrl,
  generatePKCE,
} from "@guardhouse/core";

// Generate PKCE pair
const { codeVerifier, codeChallenge } = await generatePKCE();

// Build authorize URL
const authUrl = generateAuthUrl({
  authority: "https://auth.guardhouse.io",
  clientId: "your-client-id",
  redirectUri: "https://your-app.com/callback",
  codeChallenge,
  codeChallengeMethod: "S256",
});

// Create API client
const client = new GuardhouseClient({
  authority: "https://auth.guardhouse.io",
  clientId: "your-client-id",
});

const user = await client.getUserProfile();
```

## License

See LICENSE file for details.
