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
npm run build
npm pack --dry-run -w @guardhouse/core
npm pack --dry-run -w @guardhouse/react
```

For the first beta release, ensure versions are set to `0.1.0-beta.0` (or next beta) in target packages.

## First Beta Publish (Core and React)

Publish in dependency order (`core` first):

```bash
npm publish -w @guardhouse/core --tag beta --access public
npm publish -w @guardhouse/react --tag beta --access public
```

## Full Publish Order (All SDKs)

When publishing all packages, use this order:

1. `@guardhouse/core`
2. `@guardhouse/node`
3. `@guardhouse/react`
4. `@guardhouse/react-native`

## Verify Published Versions

```bash
npm view @guardhouse/core version
npm view @guardhouse/react version
npm view @guardhouse/core dist-tags
npm view @guardhouse/react dist-tags
```

## CI/CD (GitHub Actions) Example

Store `NPM_TOKEN` in GitHub Secrets, then configure npm before publish:

```yaml
- name: Setup Node
  uses: actions/setup-node@v4
  with:
    node-version: 20
    registry-url: https://registry.npmjs.org

- name: Configure npm token
  run: npm config set //registry.npmjs.org/:_authToken "${NPM_TOKEN}"
  env:
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}

- name: Build
  run: npm run build

- name: Publish core beta
  run: npm publish -w @guardhouse/core --tag beta --access public

- name: Publish react beta
  run: npm publish -w @guardhouse/react --tag beta --access public
```

## Common Errors

- `ENEEDAUTH`: npm is not authenticated. Configure token or run `npm login`.
- `E403 ... bypass 2fa enabled is required`: token is missing bypass-2FA permission, or account/org policy requires it.
- `E404` on `npm view`: package may not exist yet, or your account lacks scope visibility.
