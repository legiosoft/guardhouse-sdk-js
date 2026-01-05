# Guardhouse JS SDKs - Secure Authentication for the Modern Stack

## Packages

| Package                                             | Description                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------ |
| [@guardhouse/core](./packages/core)                 | Environment-agnostic library with shared types, API client, and PKCE utilities |
| [@guardhouse/node](./packages/node)                 | Backend SDK for Node.js with JWT validation middleware and Admin API client    |
| [@guardhouse/react](./packages/react)               | Frontend SDK for React 18+ with hooks and protected routes                     |
| [@guardhouse/react-native](./packages/react-native) | Mobile SDK for React Native with secure storage and deep linking               |

## Contribution Guide

- The `@guardhouse/core` package must be built before `@guardhouse/node`, `@guardhouse/react`, or `@guardhouse/react-native` packages.
- Run `npm run build:core` to build the core package first.
- Use `npm run build` to build all packages in the correct order.

## License

See LICENSE file for details.
