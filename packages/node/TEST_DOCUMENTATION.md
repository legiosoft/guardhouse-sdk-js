# Test Documentation for @guardhouse/node

This document describes the test suite implemented for the @guardhouse/node package.

## Overview

The @guardhouse/node package includes a comprehensive test suite covering:

- **Utils functions** - Encoding/decoding, validation, and helper utilities
- **GuardhouseResourceService** - JWT validation and token introspection
- **guardhouseMiddleware** - Express/Connect middleware for authentication
- **GuardhouseNodeClient** - OAuth 2.0 client with token caching
- **GuardhouseAdminClient** - Admin API client for user management
- **GuardhouseConstants** - Constant values and configurations

## Test Structure

```
packages/node/
├── src/
│   ├── __tests__/
│   │   ├── utils.test.ts          # Tests for utility functions
│   │   ├── middleware.test.ts    # Tests for middleware and resource service
│   │   ├── client.test.ts        # Tests for client classes
│   │   └── constants.test.ts     # Tests for constants
│   └── ...
├── jest.config.json              # Jest configuration
└── jest.setup.js                 # Test setup and mocks
```

## Running Tests

### Install Dependencies

```bash
# From project root
npm install

# Or install jest dependencies manually
npm install -D jest @types/jest ts-jest
```

### Run All Tests

```bash
# From project root
npm run test -w @guardhouse/node

# Or from package directory
cd packages/node
npm test
```

### Run Tests in Watch Mode

```bash
npm run test:watch -w @guardhouse/node
```

### Run Tests with Coverage

```bash
npm run test:coverage -w @guardhouse/node
```

## Test Coverage Goals

The test suite targets 80% coverage across:

- **Branches**: 80%
- **Functions**: 80%
- **Lines**: 80%
- **Statements**: 80%

## Test Files

### 1. Utils Tests (`utils.test.ts`)

Tests all utility functions in `utils.ts`:

- **Encoding/Decoding**: `base64UrlEncode`, `base64UrlDecode`
- **Token Operations**: `getTokenHash`, `sanitizeToken`
- **Validation**: `validateHttpsUrl`, `validateTrustedAuthority`, `validateJwksContentType`, `validateMaxTokenAge`
- **Helpers**: `sleep`, `maskSecret`, `generateCorrelationId`, `parseErrorResponse`, `safeMerge`, `buildClaimsFromIntrospection`, `createWWWAuthenticateHeader`, `stripStackTrace`

**Test Cases**: ~60+ test cases covering success and error scenarios

### 2. Middleware Tests (`middleware.test.ts`)

Tests authentication middleware and resource service:

- **GuardhouseResourceService**:
  - Constructor initialization
  - JWT signature validation
  - Token validation (valid/invalid/expired)
  - Issuer and audience validation
  - Subject validation
  - Role parsing (single, array, space-separated)
  - Scope parsing
  - Max token age validation

- **guardhouseMiddleware**:
  - Valid token authentication
  - Missing authorization header (401)
  - Invalid token (401)
  - Malformed authorization header (401)
  - Multiple authorization headers (400)
  - Token exceeding max length (400)
  - Case-insensitive header handling
  - Correlation ID generation

**Test Cases**: ~25+ test cases covering all authentication scenarios

### 3. Client Tests (`client.test.ts`)

Tests OAuth client and admin client:

- **GuardhouseNodeClient**:
  - Constructor and cache initialization
  - Token caching (hit/miss/expired)
  - Token request with client credentials
  - Token refresh with refresh token
  - HTTP methods (GET, POST, PUT, DELETE, PATCH)
  - Authorization header injection
  - Retry logic on 401 responses
  - Correlation ID injection
  - Cache clearing

- **GuardhouseAdminClient**:
  - Delete user (success/failure)
  - Get user (success/failure)
  - List users (with pagination and search)
  - Create user (success/failure)
  - Update user (success/failure)

**Test Cases**: ~35+ test cases covering all client operations

### 4. Constants Tests (`constants.test.ts`)

Tests all constant values in `constants.ts`:

- **Endpoints**: OAuth 2.0 endpoints
- **Algorithms**: Supported JWT signing algorithms
- **TokenTypes**: JWT token type identifiers
- **Headers**: HTTP header constants
- **JwtClaims**: JWT claim names
- **Defaults**: Default configuration values
- **Validation**: Default validation flags
- **ContentTypes**: Supported content types
- **Schemes**: URL schemes (https, http)
- **ErrorMessages**: Error message constants

**Test Cases**: ~35+ test cases verifying all constant values

## Mocking Strategy

The test suite uses the following mocks:

### jest.setup.js

```javascript
// Mock jsonwebtoken
jest.mock("jsonwebtoken", () => ({
  verify: jest.fn(),
  sign: jest.fn(),
  decode: jest.fn(),
}));

// Mock jwks-rsa
jest.mock("jwks-rsa", () => ({
  __esModule: true,
  default: jest.fn(() => ({
    getSigningKey: jest.fn((kid, callback) => {
      callback(null, { getPublicKey: jest.fn(() => "mock_public_key") });
    }),
  })),
}));

// Mock fetch
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(""),
  }),
);
```

### Helper Functions

- `createMockJwtToken(overrides)` - Create mock JWT tokens
- `mockJwtVerifySuccess(decodedPayload)` - Mock successful JWT verification
- `mockJwtVerifyFailure(error)` - Mock JWT verification errors
- `mockFetchResponse(response)` - Mock fetch responses
- `mockFetchError(error)` - Mock fetch errors

## Test Configuration

### jest.config.json

```json
{
  "testEnvironment": "node",
  "roots": ["<rootDir>/src"],
  "testMatch": [
    "**/__tests__/**/*.test.[jt]s?(x)",
    "**/?(*.)+(spec|test).[jt]s?(x)"
  ],
  "collectCoverageFrom": [
    "src/**/*.{js,ts}",
    "!src/**/*.d.ts",
    "!src/index.ts"
  ],
  "coverageThreshold": {
    "global": {
      "branches": 80,
      "functions": 80,
      "lines": 80,
      "statements": 80
    }
  },
  "moduleNameMapper": {
    "^@guardhouse/core$": "<rootDir>/../core/src",
    "^@guardhouse/core/(.*)$": "<rootDir>/../core/src/$1",
    "^@guardhouse/node/(.*)$": "<rootDir>/src/$1"
  },
  "setupFilesAfterEnv": ["<rootDir>/jest.setup.js"],
  "testTimeout": 10000
}
```

## Package.json Scripts

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "typecheck": "tsc --noEmit"
  }
}
```

## Dependencies Required for Testing

```json
{
  "devDependencies": {
    "@types/jest": "^29.7.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.0"
  }
}
```

## Coverage Summary

Expected coverage across all modules:

| Module        | Expected Coverage | Tests          |
| ------------- | ----------------- | -------------- |
| utils.ts      | 95%+              | ~60 tests      |
| middleware.ts | 90%+              | ~25 tests      |
| client.ts     | 90%+              | ~35 tests      |
| constants.ts  | 100%              | ~35 tests      |
| **Total**     | **90%+**          | **~155 tests** |

## CI/CD Integration

Tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run Tests
  run: npm run test:coverage -w @guardhouse/node

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./packages/node/coverage/lcov.info
```

## Troubleshooting

### Jest not found

```bash
# Install dependencies
npm install -D jest @types/jest ts-jest
```

### TypeScript compilation errors

```bash
# Check TypeScript compilation
npm run typecheck -w @guardhouse/node
```

### Module resolution issues

- Ensure `@guardhouse/core` is built: `npm run build -w @guardhouse/core`
- Check `moduleNameMapper` in jest.config.json

## Contributing

When adding new features to @guardhouse/node:

1. Write tests for new functionality
2. Ensure all tests pass: `npm test`
3. Maintain 80%+ coverage: `npm run test:coverage`
4. Run TypeScript check: `npm run typecheck`
5. Follow existing test patterns and conventions

## Summary

The @guardhouse/node test suite provides comprehensive coverage of:

- ✅ All utility functions
- ✅ JWT validation logic
- ✅ Middleware authentication flow
- ✅ OAuth 2.0 client operations
- ✅ Admin API client operations
- ✅ All configuration constants

Total: **~155 test cases** targeting **90%+ code coverage**
