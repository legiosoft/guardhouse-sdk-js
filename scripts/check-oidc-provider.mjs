import assert from "node:assert/strict";
import { GuardhouseClient } from "@guardhouse/core";

// Public metadata and an unauthenticated authorization request only. No user
// credentials, token grants, logout requests or changes to the IdP are made.
const [authority, clientId, redirectUri, scope = "openid profile email"] =
  process.argv.slice(2);
if (!authority || !clientId || !redirectUri) {
  throw new Error(
    "Usage: node scripts/check-oidc-provider.mjs <exact-issuer> <client-id> <redirect-uri> [scope]",
  );
}
const client = new GuardhouseClient({
  authority,
  clientId,
  allowedPostLogoutRedirectUris: [redirectUri],
});
const metadata = await client.discoverOpenIdConfiguration();
assert.equal(metadata.issuer, authority);
const jwksResponse = await fetch(metadata.jwks_uri, {
  redirect: "error",
  signal: AbortSignal.timeout(15000),
});
assert.equal(jwksResponse.status, 200, "Public signing keys must be available");
const jwks = await jwksResponse.json();
assert.ok(
  jwks.keys.some(
    (key) => key.kty === "RSA" && (!key.alg || key.alg === "RS256"),
  ),
  "RS256 signing key required",
);
const { authorizationUrl } = await client.createAuthorizationRequest({
  redirectUri,
  scope,
  audiencePolicy: "oidc-optional",
  allowOfflineAccessScope: scope.split(" ").includes("offline_access"),
});
const authorizationResponse = await fetch(authorizationUrl, {
  redirect: "manual",
  signal: AbortSignal.timeout(15000),
});
assert.ok(
  [302, 303].includes(authorizationResponse.status),
  `Expected redirect to sign-in, received HTTP ${authorizationResponse.status}`,
);
const destination = new URL(
  authorizationResponse.headers.get("location"),
  authority,
);
assert.equal(
  destination.origin,
  new URL(authority).origin,
  "Unexpected sign-in origin",
);
assert.match(
  destination.pathname,
  /login|signin|sign-in/i,
  "Authorization must reach a sign-in page, not an error redirect",
);
const logout = new URL(
  await client.buildLogoutUrl({ postLogoutRedirectUri: redirectUri }),
);
assert.equal(
  `${logout.origin}${logout.pathname}`,
  metadata.end_session_endpoint,
);
console.log(
  JSON.stringify(
    {
      issuer: metadata.issuer,
      clientId,
      redirectUri,
      discovery: "passed",
      jwks: "passed",
      authorization: authorizationResponse.status,
      signInPath: destination.pathname,
      logoutUrlConstruction: "passed",
      authenticatedRoundTrip: "NOT TESTED",
    },
    null,
    2,
  ),
);
