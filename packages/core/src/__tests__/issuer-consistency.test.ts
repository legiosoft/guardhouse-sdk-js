import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { GuardhouseClient } from "../client";
import { canonicalizeIssuer, validateFrontChannelLogoutRequest } from "../auth";

const clientId = "issuer-client";
const redirectUri = "https://app.example.com/callback";
const scope = "openid profile";
const issuers = [
  "https://auth.example.com",
  "https://auth.example.com/",
  "https://auth.example.com/tenant",
  "https://auth.example.com/tenant/",
];

describe("exact protocol issuer across the public Core flow", () => {
  let pair: Awaited<ReturnType<typeof generateKeyPair>>;
  let jwk: Awaited<ReturnType<typeof exportJWK>>;
  let metadataIssuer: string;
  let responseToken: string;
  let fetchMock: jest.SpyInstance;

  beforeAll(async () => {
    pair = await generateKeyPair("RS256", { extractable: true });
    jwk = {
      ...(await exportJWK(pair.publicKey)),
      kid: "issuer-key",
      alg: "RS256",
    };
  });
  beforeEach(() => {
    fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const url = String(input);
        let data: unknown;
        if (url.endsWith("/.well-known/openid-configuration")) {
          data = {
            issuer: metadataIssuer,
            authorization_endpoint:
              "https://auth.example.com/connect/authorize",
            jwks_uri: "https://auth.example.com/jwks",
            id_token_signing_alg_values_supported: ["RS256"],
            authorization_response_iss_parameter_supported: true,
          };
        } else if (url.endsWith("/jwks")) data = { keys: [jwk] };
        else if (url.endsWith("/connect/userinfo")) data = { sub: "user-1" };
        else if (url.endsWith("/connect/token"))
          data = {
            access_token: "access",
            refresh_token: "refresh",
            token_type: "Bearer",
            expires_in: 3600,
            scope,
            id_token: responseToken,
          };
        else throw new Error(`Unexpected request: ${url}`);
        return new Response(JSON.stringify(data), {
          headers: { "Content-Type": "application/json" },
        });
      });
  });
  afterEach(() => jest.restoreAllMocks());

  function sign(issuer: string, nonce?: string) {
    return new SignJWT({ ...(nonce ? { nonce } : {}) })
      .setProtectedHeader({ alg: "RS256", kid: "issuer-key" })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setSubject("user-1")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(pair.privateKey);
  }

  it.each(issuers)(
    "supports login, refresh, UserInfo and cold restoration for %s",
    async (authority) => {
      metadataIssuer = authority;
      const values = new Map<string, string>();
      const storage = {
        getItem: async (key: string) => values.get(key) ?? null,
        setItem: async (key: string, value: string) => {
          values.set(key, value);
        },
        removeItem: async (key: string) => {
          values.delete(key);
        },
      };
      const client = new GuardhouseClient({ authority, clientId, storage });
      const { transaction } = await client.createAuthorizationRequest({
        redirectUri,
        scope,
        audiencePolicy: "oidc-optional",
      });
      expect(transaction.issuer).toBe(authority);
      const restoredTransaction = client.restoreAuthorizationTransaction(
        JSON.parse(JSON.stringify(transaction)),
      );
      expect(restoredTransaction.issuer).toBe(authority);
      const callback = await client.validateOAuthCallback(
        {
          mode: "query",
          url: `${redirectUri}?${new URLSearchParams({ code: "code", state: transaction.state, iss: authority })}`,
        },
        restoredTransaction,
      );
      if (callback.type !== "authorization_code")
        throw new Error("Expected code callback");
      responseToken = await sign(authority, transaction.nonce);
      const login = await client.exchangeAuthorizationCode(callback);
      if (login.mode !== "oidc") throw new Error("Expected OIDC exchange");
      expect(login.idToken.identity.issuer).toBe(authority);
      responseToken = await sign(authority);
      const refreshed = await client.refreshOidcSession("refresh", {
        previousIdToken: login.tokens.id_token!,
        grantedScope: scope,
      });
      expect(refreshed.identity.issuer).toBe(authority);
      await expect(
        client.getUserInfo("access", refreshed.identity),
      ).resolves.toMatchObject({ sub: "user-1" });
      const cold = new GuardhouseClient({ authority, clientId, storage });
      await expect(cold.getSessionState()).resolves.toMatchObject({
        kind: "oidc",
        identity: { issuer: authority },
      });
      await expect(
        cold.restoreOidcSession("access", { idToken: responseToken }),
      ).resolves.toMatchObject({ identity: { issuer: authority } });
      expect([...values.keys()]).toEqual([
        `guardhouse:session:v3:${encodeURIComponent(canonicalizeIssuer(authority))}:${clientId}`,
      ]);
    },
  );

  it.each([
    [issuers[0], issuers[1]],
    [issuers[1], issuers[0]],
    [issuers[2], issuers[3]],
    [issuers[3], issuers[2]],
    [issuers[0], "https://AUTH.example.com"],
    [issuers[0], "https://auth.example.com:443"],
  ])(
    "rejects normalized-equivalent discovery and token issuers (%s / %s)",
    async (authority, other) => {
      const client = new GuardhouseClient({ authority, clientId });
      metadataIssuer = other;
      await expect(client.discoverOpenIdConfiguration()).rejects.toMatchObject({
        code: "ISSUER_AUTHORITY_MISMATCH",
      });
      metadataIssuer = authority;
      await expect(
        client.verifyIdToken(await sign(other), { purpose: "session" }),
      ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
    },
  );

  it.each(issuers)(
    "rejects a substituted transaction/callback issuer before exchanging tokens (%s)",
    async (authority) => {
      metadataIssuer = authority;
      const other = authority.endsWith("/")
        ? authority.slice(0, -1)
        : authority + "/";
      const client = new GuardhouseClient({ authority, clientId });
      const { transaction } = await client.createAuthorizationRequest({
        redirectUri,
        scope,
        audiencePolicy: "oidc-optional",
      });
      expect(() =>
        client.restoreAuthorizationTransaction({
          ...transaction,
          issuer: other,
        }),
      ).toThrow("issuer");
      await expect(
        client.validateOAuthCallback(
          {
            mode: "query",
            url: `${redirectUri}?${new URLSearchParams({ code: "code", state: transaction.state, iss: other })}`,
          },
          transaction,
        ),
      ).rejects.toMatchObject({ code: "ISSUER_VALIDATION_FAILED" });
      expect(
        fetchMock.mock.calls.some(([url]) =>
          String(url).endsWith("/connect/token"),
        ),
      ).toBe(false);
      expect(() =>
        validateFrontChannelLogoutRequest(
          `https://app.example.com/logout?${new URLSearchParams({ iss: other })}`,
          { expectedIssuer: authority },
        ),
      ).toThrow("issuer validation failed");
    },
  );
});
