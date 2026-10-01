jest.mock("@guardhouse/core", () => {
  class CoreGuardhouseError extends Error {
    constructor(message, code, options) {
      super(message);
      this.code = code;
      this.statusCode = options?.statusCode;
    }
  }

  return {
    GuardhouseError: CoreGuardhouseError,
    canonicalizeIssuer: (value) => new URL(value.trim()).href,
    setCryptoAdapter: jest.fn(),
  };
});

const {
  AuthManager,
  parseTokenResponsePayload,
} = require("../core/AuthManager");
const { GuardhouseClient } = require("../core/GuardhouseClient");

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }

  async getItem(key) {
    return this.values.get(key) ?? null;
  }

  async setItem(key, value) {
    this.values.set(key, value);
  }

  async removeItem(key) {
    this.values.delete(key);
  }
}

const issuer = "https://auth.example.com/tenant";
const canonicalIssuer = "https://auth.example.com/tenant";
const clientId = "mobile-client";

function createIdentity(subject = "user-1") {
  return {
    issuer: canonicalIssuer,
    clientId,
    subject,
    audiences: [clientId],
    authorizedParty: null,
    issuedAt: 1_700_000_000,
    expiresAt: 1_900_000_000,
    nonce: "nonce-value",
    authTime: 1_700_000_000,
    acr: null,
    amr: ["pwd"],
    sessionId: null,
  };
}

function createVerifiedIdToken(identity) {
  return {
    header: { alg: "RS256", kid: "key-1" },
    payload: {
      iss: canonicalIssuer,
      sub: identity.subject,
      aud: clientId,
      exp: identity.expiresAt,
      iat: identity.issuedAt,
    },
    identity,
  };
}

async function seedOidcSession(manager, coreClient, identity) {
  coreClient.verifyIdToken.mockResolvedValueOnce(
    createVerifiedIdToken(identity),
  );
  coreClient.getUserInfo.mockResolvedValueOnce({
    sub: identity.subject,
    name: "Initial User",
  });

  return manager.persistTokenResponse(
    {
      access_token: "initial-access-token",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "initial-refresh-token",
      id_token: "initial-signed-id-token",
      scope: "openid profile offline_access",
    },
    "openid profile offline_access",
  );
}

function createCoreClient(overrides = {}) {
  return {
    createAuthorizationRequest: jest.fn(),
    validateOAuthCallback: jest.fn(),
    exchangeAuthorizationCode: jest.fn(),
    refreshOidcSession: jest.fn(),
    restoreOidcSession: jest.fn(),
    refreshOAuthToken: jest.fn(),
    verifyIdToken: jest.fn(),
    getUserInfo: jest.fn(),
    revokeToken: jest.fn(),
    clearSessionState: jest.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function createManager({
  coreClient = createCoreClient(),
  browser,
  sessionStorage = new MemoryStorage(),
  refreshTokenStorage = new MemoryStorage(),
  configuredClientId = clientId,
  userInfoOnLogin = true,
} = {}) {
  return {
    manager: new AuthManager({
      authority: issuer,
      clientId: configuredClientId,
      redirectUri: "com.example.app://callback",
      defaultScope: "openid profile offline_access",
      defaultAudience: undefined,
      defaultEphemeralSession: true,
      userInfoOnLogin,
      registrationEndpoint: `${issuer}/account/signup`,
      requiredAcrValues: [],
      requiredAmrValues: [],
      coreClient,
      browser,
      refreshTokenStorage,
      sessionStorage,
      logger: {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
      },
    }),
    coreClient,
    sessionStorage,
    refreshTokenStorage,
  };
}

describe("React Native Core v2 auth integration", () => {
  it("rejects malformed passkey token responses instead of coercing JSON", () => {
    expect(() =>
      parseTokenResponsePayload({
        access_token: "secret-access-token",
        token_type: "Bearer",
        expires_in: "3600",
      }),
    ).toThrow("missing a valid");
  });

  it("uses a bound Core transaction for browser login and binds UserInfo", async () => {
    const identity = createIdentity();
    const transaction = {
      version: 2,
      issuer: canonicalIssuer,
      clientId,
      redirectUri: "com.example.app://callback",
      state: "state-value",
      codeVerifier: "v".repeat(43),
      codeChallenge: "c".repeat(43),
      nonce: "nonce-value",
      requestedScope: "openid profile offline_access",
      requestedResources: [],
      requiredAcrValues: [],
      requiredAmrValues: [],
      responseMode: "query",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      issRequired: false,
      applicationState: { returnTo: "app://home" },
    };
    const callback = {
      type: "authorization_code",
      code: "authorization-code",
      state: transaction.state,
      sanitizedUrl: transaction.redirectUri,
    };
    const idToken = createVerifiedIdToken(identity);
    const tokens = {
      access_token: "access-token",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "refresh-token",
      id_token: "signed-id-token",
      scope: transaction.requestedScope,
    };
    const coreClient = createCoreClient({
      createAuthorizationRequest: jest.fn().mockResolvedValue({
        authorizationUrl: `${issuer}/connect/authorize?state=state-value`,
        transaction,
      }),
      validateOAuthCallback: jest.fn().mockResolvedValue(callback),
      exchangeAuthorizationCode: jest.fn().mockResolvedValue({
        mode: "oidc",
        tokens,
        idToken,
        identity,
      }),
      getUserInfo: jest.fn().mockResolvedValue({
        sub: identity.subject,
        name: "Verified User",
      }),
    });
    const browser = {
      openAuthSession: jest.fn().mockResolvedValue({
        url: `${transaction.redirectUri}?code=authorization-code&state=${transaction.state}`,
      }),
    };
    const { manager } = createManager({ coreClient, browser });

    const result = await manager.loginWithBrowser();

    expect(coreClient.createAuthorizationRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        redirectUri: transaction.redirectUri,
        scope: transaction.requestedScope,
        audiencePolicy: "oidc-optional",
        responseMode: "query",
      }),
    );
    expect(coreClient.validateOAuthCallback).toHaveBeenCalledWith(
      { mode: "query", url: expect.stringContaining("authorization-code") },
      transaction,
    );
    expect(coreClient.exchangeAuthorizationCode).toHaveBeenCalledWith(callback);
    expect(coreClient.getUserInfo).toHaveBeenCalledWith(
      tokens.access_token,
      identity,
    );
    expect(result.session.identity).toEqual(identity);
    expect(result.user.sub).toBe(identity.subject);
    expect(Object.isFrozen(result.user)).toBe(true);
    expect(result.appState).toEqual(transaction.applicationState);
  });

  it("persists a replacement ID token only for current refresh evidence", async () => {
    const initialIdentity = createIdentity();
    const replacementIdentity = {
      ...createIdentity(),
      issuedAt: initialIdentity.issuedAt + 60,
      expiresAt: initialIdentity.expiresAt + 60,
      verificationMarker: "current-evidence",
    };
    const replacementIdToken = createVerifiedIdToken(replacementIdentity);
    const coreClient = createCoreClient();
    const { manager, sessionStorage } = createManager({ coreClient });
    await seedOidcSession(manager, coreClient, initialIdentity);
    coreClient.getUserInfo.mockClear();
    coreClient.getUserInfo.mockResolvedValueOnce({
      sub: replacementIdentity.subject,
      name: "Refreshed User",
    });
    coreClient.refreshOidcSession.mockResolvedValueOnce({
      identityStatus: "current",
      tokens: {
        access_token: "replacement-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        id_token: "replacement-signed-id-token",
        scope: "openid profile offline_access",
      },
      identity: replacementIdentity,
      idToken: replacementIdToken,
    });

    const result = await manager.refreshToken();

    expect(coreClient.getUserInfo).toHaveBeenCalledWith(
      "replacement-access-token",
      replacementIdentity,
    );
    expect(result.session.idToken).toBe("replacement-signed-id-token");
    expect(result.session.identity).toEqual(
      expect.not.objectContaining({ verificationMarker: expect.anything() }),
    );
    const stored = JSON.parse(Array.from(sessionStorage.values.values())[0]);
    expect(stored.idTokenCurrent).toBe(true);
    expect(stored.idToken).toBe("replacement-signed-id-token");
    expect(stored.identity.verificationMarker).toBeUndefined();
  });

  it("uses historical evidence for UserInfo without persisting or exposing it as current", async () => {
    const initialIdentity = createIdentity();
    const historicalIdentity = {
      ...initialIdentity,
      verificationMarker: "historical-evidence",
    };
    const coreClient = createCoreClient();
    const { manager, sessionStorage } = createManager({ coreClient });
    await seedOidcSession(manager, coreClient, initialIdentity);
    coreClient.getUserInfo.mockClear();
    coreClient.getUserInfo.mockResolvedValueOnce({
      sub: historicalIdentity.subject,
      name: "Fresh UserInfo",
    });
    coreClient.refreshOidcSession.mockResolvedValueOnce({
      identityStatus: "historical",
      tokens: {
        access_token: "historical-bound-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile offline_access",
      },
      identity: historicalIdentity,
    });

    const result = await manager.refreshToken();

    expect(coreClient.getUserInfo).toHaveBeenCalledWith(
      "historical-bound-access-token",
      historicalIdentity,
    );
    expect(result.session.idToken).toBeUndefined();
    expect(result.tokenResponse.id_token).toBeUndefined();
    expect(result.session.identity).toEqual(
      expect.not.objectContaining({ verificationMarker: expect.anything() }),
    );
    const stored = JSON.parse(Array.from(sessionStorage.values.values())[0]);
    expect(stored.idTokenCurrent).toBe(false);
    expect(stored.idToken).toBe("initial-signed-id-token");
    expect(stored.identity.verificationMarker).toBeUndefined();
  });

  it("namespaces v3 sessions by issuer and client", async () => {
    const sessionStorage = new MemoryStorage();
    const refreshTokenStorage = new MemoryStorage();
    const first = createManager({ sessionStorage, refreshTokenStorage });
    const second = createManager({
      sessionStorage,
      refreshTokenStorage,
      configuredClientId: "other-mobile-client",
    });

    await first.manager.persistTokenResponse(
      {
        access_token: "first-access",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "first-refresh",
        scope: "api.read",
      },
      "api.read",
    );
    await second.manager.persistTokenResponse(
      {
        access_token: "second-access",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "second-refresh",
        scope: "api.read",
      },
      "api.read",
    );

    await expect(first.manager.getSession()).resolves.toEqual(
      expect.objectContaining({ accessToken: "first-access" }),
    );
    await expect(second.manager.getSession()).resolves.toEqual(
      expect.objectContaining({ accessToken: "second-access" }),
    );
    expect(sessionStorage.values.size).toBe(2);
    expect(refreshTokenStorage.values.size).toBe(2);
  });

  it.each([true, false])(
    "restores historical sessions on cold start (userInfoOnLogin=%s)",
    async (userInfoOnLogin) => {
      const identity = createIdentity();
      const first = createManager();
      await seedOidcSession(first.manager, first.coreClient, identity);
      first.coreClient.refreshOidcSession.mockResolvedValueOnce({
        identityStatus: "historical",
        identity,
        tokens: {
          access_token: "refreshed-access",
          refresh_token: "rotated-refresh",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid profile offline_access",
        },
      });
      first.coreClient.getUserInfo.mockResolvedValueOnce({
        sub: identity.subject,
        roles: ["old-role"],
      });
      await first.manager.refreshToken();

      const cold = createManager({
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
        userInfoOnLogin,
      });
      cold.coreClient.restoreOidcSession.mockResolvedValueOnce({
        identity,
        userInfo: { sub: identity.subject, roles: ["reader"] },
      });
      const result = await cold.manager.restoreSession();
      expect(cold.coreClient.restoreOidcSession).toHaveBeenCalledWith(
        "refreshed-access",
        {
          idToken: "initial-signed-id-token",
          requiredAcrValues: [],
          requiredAmrValues: [],
        },
      );
      expect(cold.coreClient.refreshOidcSession).not.toHaveBeenCalled();
      expect(result.session.idToken).toBeUndefined();
      expect(result.tokenResponse.id_token).toBeUndefined();
      expect(result.user).toEqual(
        userInfoOnLogin
          ? { sub: identity.subject, roles: ["reader"] }
          : { sub: identity.subject },
      );
      expect(await cold.manager.getAccessToken()).toBe("refreshed-access");
      expect(cold.coreClient.restoreOidcSession).toHaveBeenCalledTimes(1);
      expect(first.sessionStorage.values.size).toBe(1);
      expect(first.refreshTokenStorage.values.size).toBe(1);

      cold.coreClient.refreshOidcSession.mockResolvedValueOnce({
        identityStatus: "historical",
        identity,
        tokens: {
          access_token: "next-access",
          refresh_token: "next-refresh",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid profile offline_access",
        },
      });
      cold.coreClient.getUserInfo.mockResolvedValueOnce({
        sub: identity.subject,
      });
      await cold.manager.refreshToken();
      expect(cold.coreClient.refreshOidcSession).toHaveBeenCalledWith(
        "rotated-refresh",
        expect.objectContaining({
          previousIdToken: "initial-signed-id-token",
        }),
      );
      expect(
        Array.from(first.refreshTokenStorage.values.values())[0],
      ).toContain("next-refresh");
    },
  );

  it.each(["restoreSession", "getSession", "getAccessToken"])(
    "uses online historical restoration in %s when a current ID token has since expired",
    async (method) => {
      const identity = {
        ...createIdentity(),
        expiresAt: Math.floor(Date.now() / 1000) - 120,
      };
      const first = createManager();
      await seedOidcSession(first.manager, first.coreClient, identity);
      const cold = createManager({
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      cold.coreClient.restoreOidcSession.mockResolvedValueOnce({
        identity,
        userInfo: { sub: identity.subject },
      });
      const result = await cold.manager[method]();
      expect(result).not.toBeNull();
      expect(cold.coreClient.verifyIdToken).not.toHaveBeenCalled();
      expect(cold.coreClient.restoreOidcSession).toHaveBeenCalledTimes(1);
      expect((await cold.manager.getSession()).idToken).toBeUndefined();
    },
  );

  it.each(["identity mismatch", "verification failure"])(
    "rejects historical restoration on %s",
    async (failure) => {
      const identity = {
        ...createIdentity(),
        expiresAt: Math.floor(Date.now() / 1000) - 120,
      };
      const first = createManager();
      await seedOidcSession(first.manager, first.coreClient, identity);
      const cold = createManager({
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      if (failure === "identity mismatch") {
        cold.coreClient.restoreOidcSession.mockResolvedValueOnce({
          identity: { ...identity, nonce: "modified" },
          userInfo: { sub: identity.subject },
        });
      } else {
        cold.coreClient.restoreOidcSession.mockRejectedValueOnce(
          new Error("Signature or UserInfo rejected"),
        );
      }
      await expect(cold.manager.restoreSession()).rejects.toThrow();
      expect(first.sessionStorage.values.size).toBe(0);
      expect(first.refreshTokenStorage.values.size).toBe(0);
    },
  );

  it("rejects competing browser transactions", async () => {
    const transaction = {
      version: 2,
      issuer: canonicalIssuer,
      clientId,
      redirectUri: "com.example.app://callback",
      state: "state-value",
      codeVerifier: "v".repeat(43),
      codeChallenge: "c".repeat(43),
      nonce: "nonce-value",
      requestedScope: "api.read",
      requestedResources: [],
      requiredAcrValues: [],
      requiredAmrValues: [],
      responseMode: "query",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      issRequired: false,
    };
    let releaseAuthorizationRequest;
    const coreClient = createCoreClient({
      createAuthorizationRequest: jest.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            releaseAuthorizationRequest = resolve;
          }),
      ),
      validateOAuthCallback: jest.fn().mockResolvedValue({
        type: "authorization_code",
        code: "authorization-code",
        state: transaction.state,
        sanitizedUrl: transaction.redirectUri,
      }),
      exchangeAuthorizationCode: jest.fn().mockResolvedValue({
        mode: "oauth2",
        tokens: {
          access_token: "access-token",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "api.read",
        },
      }),
    });
    const browser = {
      openAuthSession: jest.fn().mockResolvedValue({
        url: `${transaction.redirectUri}?code=authorization-code&state=${transaction.state}`,
      }),
    };
    const { manager } = createManager({ coreClient, browser });

    const first = manager.loginWithBrowser({ scope: "api.read" });
    await expect(
      manager.loginWithBrowser({ scope: "api.read" }),
    ).rejects.toThrow("already in progress");

    releaseAuthorizationRequest({
      authorizationUrl: `${issuer}/connect/authorize?state=state-value`,
      transaction,
    });
    await expect(first).resolves.toEqual(
      expect.objectContaining({
        session: expect.objectContaining({ accessToken: "access-token" }),
      }),
    );
  });

  it("discards a mismatched stored v3 session instead of restoring it", async () => {
    const sessionStorage = new MemoryStorage();
    const refreshTokenStorage = new MemoryStorage();
    const first = createManager({ sessionStorage, refreshTokenStorage });
    await first.manager.persistTokenResponse(
      {
        access_token: "access-token",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "refresh-token",
        scope: "api.read",
      },
      "api.read",
    );

    const sessionKey = Array.from(sessionStorage.values.keys())[0];
    const stored = JSON.parse(sessionStorage.values.get(sessionKey));
    stored.clientId = "attacker-client";
    sessionStorage.values.set(sessionKey, JSON.stringify(stored));

    const restored = createManager({ sessionStorage, refreshTokenStorage });
    await expect(restored.manager.restoreSession()).resolves.toBeNull();
    expect(sessionStorage.values.size).toBe(0);
    expect(refreshTokenStorage.values.size).toBe(0);
    expect(restored.coreClient.clearSessionState).toHaveBeenCalled();
  });

  it("does not expose manual code or front-channel token ingestion methods", () => {
    expect(GuardhouseClient.prototype.exchangeCodeForTokens).toBeUndefined();
    expect(GuardhouseClient.prototype.applyRedirectTokens).toBeUndefined();
  });
});
