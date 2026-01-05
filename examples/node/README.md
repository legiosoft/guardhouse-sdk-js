# Node.js Example

This is a complete example of a Node.js server using `@guardhouse/node` for OAuth 2.0 authentication.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- Client Credentials flow
- Token exchange and refresh
- User info fetching
- Protected endpoints

## Prerequisites

- Node.js >= 18.0.0
- A Guardhouse instance running

## Setup

1. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

2. Configure your environment variables in `.env`:

```env
AUTHORITY=https://your-guardhouse-domain.com
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
REDIRECT_URI=http://localhost:3001/callback
PORT=3001
```

3. Install dependencies:

```bash
npm install
```

## Running

Development mode with hot reload:

```bash
npm run dev
```

Production mode:

```bash
npm run build
npm start
```

## API Endpoints

### `GET /`

Returns available endpoints and server information.

### `GET /login`

Generates an authorization URL with PKCE parameters.

**Response:**

```json
{
  "authUrl": "https://auth.example.com/connect/authorize?...",
  "codeVerifier": "random-string",
  "state": "random-state"
}
```

### `GET /callback`

OAuth 2.0 callback endpoint for exchanging authorization codes for tokens.

**Query Parameters:**

- `code` - Authorization code from Guardhouse
- `state` - State parameter
- `code_verifier` - PKCE code verifier
- `error` - Error message (if authentication failed)

**Response:**

```json
{
  "message": "Authentication successful",
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "refresh_token": "def50200a4...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### `GET /user`

Fetches user information from Guardhouse.

**Headers:**

- `Authorization: Bearer <access_token>`

**Response:**

```json
{
  "user": {
    "sub": "user-id",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

### `POST /token`

Obtains an access token using different grant types.

**Body (Client Credentials):**

```json
{
  "grant_type": "client_credentials"
}
```

**Body (Password):**

```json
{
  "grant_type": "password",
  "username": "user@example.com",
  "password": "password123"
}
```

**Body (Refresh Token):**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "def50200a4..."
}
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "refresh_token": "def50200a4...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### `POST /protected`

A protected endpoint that requires a valid access token.

**Headers:**

- `Authorization: Bearer <access_token>`

**Response:**

```json
{
  "message": "This is a protected resource",
  "user": {
    "sub": "user-id",
    "name": "John Doe",
    "email": "john@example.com"
  },
  "timestamp": "2024-01-05T00:00:00.000Z"
}
```

## Usage Examples

### Complete Authentication Flow

1. **Generate Authorization URL**

```bash
curl http://localhost:3001/login
```

2. **User Authorizes**

Open the returned `authUrl` in a browser to authorize.

3. **Handle Callback**

After authorization, Guardhouse redirects to your callback URL with an authorization code.

4. **Exchange Code for Token**

```bash
curl "http://localhost:3001/callback?code=...&state=...&code_verifier=..."
```

5. **Access Protected Resource**

```bash
curl http://localhost:3001/protected \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Client Credentials

```bash
curl -X POST http://localhost:3001/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "client_credentials"}'
```

### Refreshing Tokens

```bash
curl -X POST http://localhost:3001/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "refresh_token", "refresh_token": "YOUR_REFRESH_TOKEN"}'
```

## Error Handling

The server returns appropriate HTTP status codes:

- `401` - Unauthorized (missing or invalid token)
- `400` - Bad request (invalid parameters)
- `500` - Internal server error

Error response format:

```json
{
  "error": "Error message",
  "details": "Additional details"
}
```

## Security Notes

- All tokens are redacted in responses for security
- Use HTTPS in production
- Store `CLIENT_SECRET` securely
- Use environment variables for sensitive data
- Implement rate limiting in production
- Add input validation and sanitization
- Configure CORS appropriately

## Development Tips

- The server runs on port 3001 by default
- Use `npm run dev` for development with hot reload
- Use `npm run build` to compile TypeScript
- Logs are printed to the console
- Error details are included in responses for debugging

## License

MIT
