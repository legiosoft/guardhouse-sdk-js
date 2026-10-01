# npm Deployment Manual

This repository is a monorepo with publishable SDK packages under `packages/*`.

## Publishable Packages

- `@guardhouse/core`
- `@guardhouse/node`
- `@guardhouse/react`
- `@guardhouse/react-native`

`@guardhouse/example-app` is marked `private` and is not published.

## Prerequisites

1. You must have npm access to the `@guardhouse` scope.
2. You must use one of the following auth methods for publish:
   - OTP (`--otp`) from your authenticator, or
   - a granular access token with **Bypass 2FA for publishing** enabled.
3. Node.js 18+.

## Create a Token (Recommended)

1. Open npm account settings: Access Tokens.
2. Create a **Granular Access Token**.
3. Grant permissions:
   - Scope/package access for `@guardhouse/*`
   - Publish permission
   - **Bypass 2FA for package publishing**
4. Save the token securely.

Do not commit tokens to git.

## Local Publish Using Token

### 1) Set token in shell

PowerShell:

```powershell
$env:NPM_TOKEN="<your_token>"
```

Bash:

```bash
export NPM_TOKEN="<your_token>"
```

### 2) Configure npm auth (local machine)

Use user-level config (recommended):

```bash
npm config set //registry.npmjs.org/:_authToken "${NPM_TOKEN}"
npm config set registry "https://registry.npmjs.org/"
```

### 3) Verify auth

```bash
npm whoami
```

If this fails, token is invalid/expired or missing scope permissions.

## Pre-publish Checklist

From repository root:

```bash
npm ci
npm run release:check
```

The release check runs package tests, typechecks, lint, builds, a clean
tarball-consumer smoke test, and a production dependency audit. The same check
runs for pull requests in GitHub Actions.

Before publishing, use a reachable test Guardhouse server with a separate
authorization-code client and service client. In the React example, verify a
protected-route login, callback URL cleanup, return to the original path,
reload, refresh, and logout. For Node, verify service-token issuance and run
`examples/node/resource-example.ts` against a token issued for its audience to
check JWT middleware. A passing mocked test suite cannot establish these live
flows.

The individual commands are:

`npm test` and `npm run typecheck` build Core first so workspace consumers
resolve fresh declarations even in a clean checkout where `dist/` is absent.

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
npm pack --dry-run -w @guardhouse/core
npm pack --dry-run -w @guardhouse/react
npm pack --dry-run -w @guardhouse/node
npm pack --dry-run -w @guardhouse/react-native
```

For this release train, set versions to:

- `@guardhouse/core`: `2.0.0-beta.1`
- `@guardhouse/react`: `2.0.0-beta.1`
- `@guardhouse/node`: `1.0.2-beta.1`
- `@guardhouse/react-native`: `1.0.2-beta.1`

Node and React Native retain their existing prerelease version while pinning the
security-hardened Core `2.0.0-beta.1` exactly. Core and React use a major beta
because this release deliberately removes unsafe public APIs.

## Beta Publish

Publish every prerelease with the `beta` tag so npm's `latest` tag remains on the current stable release. Publish in dependency order (`core` first):

```bash
npm publish -w @guardhouse/core --tag beta --access public
npm publish -w @guardhouse/react --tag beta --access public
npm publish -w @guardhouse/node --tag beta --access public
npm publish -w @guardhouse/react-native --tag beta --access public
```

## Full Publish Order (All SDKs)

When publishing all packages, use this order:

1. `@guardhouse/core`
2. `@guardhouse/react`
3. `@guardhouse/node`
4. `@guardhouse/react-native`

## Verify Published Versions

```bash
npm view @guardhouse/core@beta version
npm view @guardhouse/react@beta version
npm view @guardhouse/node@beta version
npm view @guardhouse/react-native@beta version
npm view @guardhouse/core dist-tags
npm view @guardhouse/react dist-tags
npm view @guardhouse/node dist-tags
npm view @guardhouse/react-native dist-tags
```

## Beta Feedback

Beta packages are feature-complete but may have:

- API changes before stable release
- Additional test coverage needed
- Documentation improvements

Report issues at: https://github.com/legiosoft/guardhouse-sdk-js/issues

## Pull-request verification

`.github/workflows/release-check.yml` runs `npm run release:check` and builds
the maintained examples. It has read-only repository permissions and no npm
publishing credentials.

## Common Errors

- `ENEEDAUTH`: npm is not authenticated. Configure token or run `npm login`.
- `E403 ... bypass 2fa enabled is required`: token is missing bypass-2FA permission, or account/org policy requires it.
- `E404` on `npm view`: package may not exist yet, or your account lacks scope visibility.
