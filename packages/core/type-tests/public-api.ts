import {
  GuardhouseClient,
  decodeJWT,
  type AuthorizationTransaction,
  type CreatedAuthorizationRequest,
  type IntrospectionResponse,
  type OidcIdentity,
  type OidcIdentityMetadata,
  type RestoredOidcSession,
  type VerifiedIdToken,
} from "@guardhouse/core";

// @ts-expect-error Claim-only validation was removed because it cannot prove authenticity.
import { validateToken } from "@guardhouse/core";
// @ts-expect-error Detached signature proofs were removed because they were replayable.
import type { VerifiedSignatureProof } from "@guardhouse/core";

const client = new GuardhouseClient({
  authority: "https://auth.example.com",
  clientId: "browser-client",
});

const untrustedIdentityMetadata: OidcIdentityMetadata = {
  issuer: "https://auth.example.com/",
  clientId: "browser-client",
  subject: "user-1",
  audiences: ["browser-client"],
  authorizedParty: null,
  issuedAt: 1_900_000_000,
  expiresAt: 1_900_003_600,
  nonce: null,
  authTime: null,
  acr: null,
  amr: [],
  sessionId: null,
};

// @ts-expect-error Serializable metadata is not verified identity evidence.
const forgedIdentity: OidcIdentity = untrustedIdentityMetadata;

async function exercisePublicFlow(): Promise<void> {
  const created: CreatedAuthorizationRequest =
    await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid profile",
      resource: ["https://api.example.com", "https://files.example.com"],
      audiencePolicy: "oidc-optional",
      maxAgeSeconds: 300,
      requiredAcrValues: ["urn:guardhouse:acr:passkey"],
      requiredAmrValues: ["passkey"],
    });

  const transaction: AuthorizationTransaction =
    client.restoreAuthorizationTransaction(created.transaction);
  const callback = await client.validateOAuthCallback(
    { mode: "query", url: "https://app.example.com/callback" },
    transaction,
  );

  if (callback.type === "authorization_code") {
    const result = await client.exchangeAuthorizationCode(callback);
    if (result.mode === "oidc") {
      const verified: VerifiedIdToken = result.idToken;
      void verified.identity.subject;
      const profile: string | undefined = verified.payload.profile;
      void profile;
      const roles: readonly string[] | undefined = verified.payload.roles;
      const scopes: readonly string[] | undefined = verified.payload.scopes;
      const amr: readonly string[] | undefined = verified.payload.amr;
      const address: Readonly<Record<string, unknown>> | undefined =
        verified.payload.address;
      void roles;
      void scopes;
      void amr;
      void address;
      const extensionClaim: unknown = verified.payload["custom_claim"];
      void extensionClaim;
      if (verified.payload.roles) {
        // @ts-expect-error Verified role claims are immutable.
        verified.payload.roles.push("admin");
      }
      // @ts-expect-error Unknown extension claims require explicit narrowing.
      void verified.payload["custom_claim"].nested;

      const userInfo = await client.getUserInfo(
        result.tokens.access_token,
        result.identity,
      );
      const userInfoExtension: unknown = userInfo["custom_claim"];
      void userInfoExtension;
      if (userInfo.roles) {
        // @ts-expect-error UserInfo role claims are immutable.
        userInfo.roles.push("admin");
      }
      // @ts-expect-error Unknown UserInfo extensions require explicit narrowing.
      void userInfo["custom_claim"].nested;
    }
  } else {
    void callback.error;
  }

  // @ts-expect-error Validated callbacks are opaque and client-produced.
  await client.exchangeAuthorizationCode({
    type: "authorization_code",
    code: "forged",
    state: transaction.state,
    sanitizedUrl: transaction.redirectUri,
  });

  const decoded = decodeJWT("header.payload.signature");
  void decoded.payload;

  const introspection: IntrospectionResponse =
    await client.introspectToken("opaque-token");
  if (introspection.active) {
    void introspection.sub;
  }

  await client.verifyIdToken("signed-id-token", {
    purpose: "authorization_code",
    nonce: transaction.nonce,
  });

  // @ts-expect-error Every verification call must declare its security purpose.
  await client.verifyIdToken("signed-id-token");

  // @ts-expect-error UserInfo requires opaque verifier-produced evidence.
  await client.getUserInfo("access-token", untrustedIdentityMetadata);

  const refreshed = await client.refreshOidcSession("refresh-token", {
    previousIdToken: "signed-id-token",
  });
  await client.refreshOidcSession("refresh-token", {
    previousIdToken: "signed-id-token",
    grantedScope: "openid profile offline_access",
    scope: "openid offline_access",
    audience: "urn:api",
  });
  await client.refreshOAuthToken("refresh-token", {
    grantedScope: "read write",
    scope: "read",
    audience: "urn:api",
    requestParameters: { extension: "value" },
  });
  await client.refreshOAuthToken("refresh-token", {
    // @ts-expect-error A refresh scope must be a string, not a list.
    scope: ["read"],
  });
  const restored: RestoredOidcSession = await client.restoreOidcSession(
    "access-token",
    { idToken: "signed-id-token", requiredAmrValues: ["passkey"] },
  );
  // @ts-expect-error Online restoration does not make an old ID token current.
  const restoredCurrentIdentity: OidcIdentity = restored.identity;
  // @ts-expect-error Historical restoration never exposes a verified ID token.
  const restoredIdToken: VerifiedIdToken = restored.idToken;
  void restored.userInfo.sub;
  void restoredCurrentIdentity;
  void restoredIdToken;
  if (refreshed.identityStatus === "historical") {
    // @ts-expect-error Historical evidence is not a current identity credential.
    const currentIdentity: OidcIdentity = refreshed.identity;
    void currentIdentity;
  }

  await client.createAuthorizationRequest({
    redirectUri: "https://app.example.com/callback",
    scope: "openid",
    // @ts-expect-error Implicit and hybrid response types are not configurable in v2.
    responseType: "token",
  });
}

void validateToken;
declare const removedProof: VerifiedSignatureProof;
void removedProof;
void forgedIdentity;
void exercisePublicFlow;
