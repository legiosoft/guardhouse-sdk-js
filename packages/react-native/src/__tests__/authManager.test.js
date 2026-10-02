jest.mock("@guardhouse/core", () => {
  class CoreGuardhouseError extends Error {
    constructor(message, code, options) {
      super(message);
      this.code = code;
      this.statusCode = options?.statusCode;
      this.retryable = options?.retryable;
    }
  }

  return {
    GuardhouseError: CoreGuardhouseError,
    canonicalizeIssuer: (value) => new URL(value.trim()).href,
    setCryptoAdapter: jest.fn(),
    isTransientAuthError: jest.requireActual("../../../core/src/config")
      .isTransientAuthError,
  };
});

const {
  AuthManager,
  parseTokenResponsePayload,
} = require("../core/AuthManager");
const { GuardhouseClient } = require("../core/GuardhouseClient");
const { GuardhouseError: CoreError } = require("@guardhouse/core");
const { sanitizeAuthority, resolveEndpoint } = require("../utils/url");
const { webcrypto } = require("node:crypto");
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
beforeEach(() => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: webcrypto,
  });
});
afterEach(() => {
  if (originalCrypto)
    Object.defineProperty(globalThis, "crypto", originalCrypto);
  else delete globalThis.crypto;
});

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
  authority = issuer,
  userInfoOnLogin = true,
} = {}) {
  return {
    manager: new AuthManager({
      authority,
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
  it.each([false, true])(
    "clears partial rotated credentials when session storage fails (silent=%s)",
    async (silent) => {
      const { manager, coreClient, sessionStorage, refreshTokenStorage } =
        createManager();
      const identity = createIdentity();
      await seedOidcSession(manager, coreClient, identity);
      coreClient.getUserInfo.mockClear();
      coreClient.refreshOidcSession.mockResolvedValue({
        identityStatus: "historical",
        identity,
        tokens: {
          access_token: "rotated-access",
          refresh_token: "rotated-refresh",
          token_type: "Bearer",
          expires_in: 3600,
        },
      });
      sessionStorage.setItem = async () => {
        if (!silent) throw new Error("Storage failed");
      };
      await expect(manager.refreshToken()).rejects.toThrow();
      expect(sessionStorage.values.size).toBe(0);
      expect(refreshTokenStorage.values.size).toBe(0);
      expect(coreClient.getUserInfo).not.toHaveBeenCalled();
      await expect(manager.getSession()).resolves.toBeNull();
    },
  );

  it("still requires UserInfo before persisting an initial OIDC login", async () => {
    const { manager, coreClient, sessionStorage, refreshTokenStorage } =
      createManager();
    coreClient.verifyIdToken.mockResolvedValue(
      createVerifiedIdToken(createIdentity()),
    );
    coreClient.getUserInfo.mockRejectedValue(
      new CoreError("Unavailable", "SERVER_ERROR", { statusCode: 503 }),
    );
    await expect(
      manager.persistTokenResponse({
        access_token: "initial-access",
        refresh_token: "initial-refresh",
        id_token: "initial-id-token",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile offline_access",
      }),
    ).rejects.toThrow();
    expect(sessionStorage.values.size).toBe(0);
    expect(refreshTokenStorage.values.size).toBe(0);
  });

  it.each(["oauth", "oidc"])(
    "retains a valid %s session without refresh when the requested validity is longer",
    async (kind) => {
      const now = 1_800_000_000;
      const clock = jest.spyOn(Date, "now").mockReturnValue(now * 1000);
      try {
        const first = createManager();
        const identity = createIdentity();
        first.coreClient.verifyIdToken.mockResolvedValue(
          createVerifiedIdToken(identity),
        );
        first.coreClient.getUserInfo.mockResolvedValue({
          sub: identity.subject,
        });
        await first.manager.persistTokenResponse(
          {
            access_token: "short-access",
            token_type: "Bearer",
            expires_in: 30,
            ...(kind === "oidc" ? { id_token: "signed-id-token" } : {}),
          },
          kind === "oidc" ? "openid profile" : "api",
        );
        const snapshot = [...first.sessionStorage.values.entries()];
        const cold = createManager({
          coreClient: first.coreClient,
          sessionStorage: first.sessionStorage,
          refreshTokenStorage: first.refreshTokenStorage,
        });
        await expect(cold.manager.restoreSession()).resolves.toBeNull();
        await expect(cold.manager.getAccessToken()).resolves.toBeNull();
        await expect(
          cold.manager.restoreSession({ minValiditySeconds: 30 }),
        ).resolves.toBeNull();
        expect([...first.sessionStorage.values.entries()]).toEqual(snapshot);
        await expect(
          cold.manager.restoreSession({ minValiditySeconds: 0 }),
        ).resolves.toMatchObject({
          session: { accessToken: "short-access" },
        });
        await expect(
          cold.manager.getAccessToken({ minValiditySeconds: 0 }),
        ).resolves.toBe("short-access");
        expect(first.coreClient.refreshOidcSession).not.toHaveBeenCalled();
        expect(first.coreClient.refreshOAuthToken).not.toHaveBeenCalled();
        clock.mockReturnValue((now + 30) * 1000);
        await expect(
          cold.manager.restoreSession({ minValiditySeconds: 0 }),
        ).resolves.toBeNull();
        await expect(
          cold.manager.getAccessToken({ minValiditySeconds: 0 }),
        ).resolves.toBeNull();
        expect(first.sessionStorage.values.size).toBe(0);
      } finally {
        clock.mockRestore();
      }
    },
  );

  it.each([true, false])(
    "retains rotated tokens through a transient UserInfo failure and cold restore (new ID token=%s)",
    async (current) => {
      const first = createManager();
      const identity = createIdentity();
      await seedOidcSession(first.manager, first.coreClient, identity);
      const tokens = {
        access_token: "rotated-access",
        refresh_token: "rotated-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile offline_access",
        ...(current ? { id_token: "rotated-id-token" } : {}),
      };
      first.coreClient.refreshOidcSession.mockResolvedValue({
        identityStatus: current ? "current" : "historical",
        identity,
        tokens,
        ...(current ? { idToken: createVerifiedIdToken(identity) } : {}),
      });
      first.coreClient.getUserInfo.mockRejectedValueOnce(
        new CoreError("UserInfo unavailable", "SERVER_ERROR", {
          statusCode: 503,
        }),
      );
      await expect(first.manager.refreshToken()).rejects.toThrow();
      expect([...first.refreshTokenStorage.values.values()]).toEqual([
        "rotated-refresh",
      ]);
      expect(
        JSON.parse([...first.sessionStorage.values.values()][0]),
      ).toMatchObject({
        accessToken: "rotated-access",
        idTokenCurrent: current,
      });
      expect(first.coreClient.clearSessionState).not.toHaveBeenCalled();
      const cold = createManager({
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      const verify = current
        ? cold.coreClient.verifyIdToken
        : cold.coreClient.restoreOidcSession;
      verify.mockRejectedValueOnce(
        new CoreError("Still unavailable", "NETWORK_ERROR"),
      );
      await expect(cold.manager.getAccessToken()).rejects.toThrow();
      expect([...first.refreshTokenStorage.values.values()]).toEqual([
        "rotated-refresh",
      ]);
      if (current) {
        verify.mockResolvedValue(createVerifiedIdToken(identity));
        cold.coreClient.getUserInfo.mockResolvedValue({
          sub: identity.subject,
        });
      } else {
        verify.mockResolvedValue({
          identity,
          userInfo: { sub: identity.subject },
        });
      }
      await expect(cold.manager.restoreSession()).resolves.toMatchObject({
        session: {
          accessToken: "rotated-access",
          refreshToken: "rotated-refresh",
        },
        user: { sub: identity.subject },
      });
      expect(cold.coreClient.refreshOidcSession).not.toHaveBeenCalled();
      cold.coreClient.refreshOidcSession.mockResolvedValue({
        identityStatus: current ? "current" : "historical",
        identity,
        tokens,
        ...(current ? { idToken: createVerifiedIdToken(identity) } : {}),
      });
      cold.coreClient.getUserInfo.mockResolvedValue({ sub: identity.subject });
      await cold.manager.refreshToken();
      expect(cold.coreClient.refreshOidcSession).toHaveBeenCalledWith(
        "rotated-refresh",
        expect.any(Object),
      );
      await cold.manager.logout();
      expect(first.sessionStorage.values.size).toBe(0);
      expect(first.refreshTokenStorage.values.size).toBe(0);
    },
  );

  it.each(["USERINFO_SUBJECT_MISMATCH", "invalid_token"])(
    "discards rotated credentials after permanent UserInfo failure %s",
    async (code) => {
      const { manager, coreClient, sessionStorage, refreshTokenStorage } =
        createManager();
      const identity = createIdentity();
      await seedOidcSession(manager, coreClient, identity);
      coreClient.refreshOidcSession.mockResolvedValue({
        identityStatus: "historical",
        identity,
        tokens: {
          access_token: "rotated-access",
          refresh_token: "rotated-refresh",
          token_type: "Bearer",
          expires_in: 3600,
        },
      });
      coreClient.getUserInfo.mockRejectedValue(new CoreError("Rejected", code));
      await expect(manager.refreshToken()).rejects.toThrow();
      expect(sessionStorage.values.size).toBe(0);
      expect(refreshTokenStorage.values.size).toBe(0);
    },
  );

  it.each([false, true])(
    "logout wins while refreshed UserInfo is pending (failure=%s)",
    async (failure) => {
      const { manager, coreClient, sessionStorage, refreshTokenStorage } =
        createManager();
      const identity = createIdentity();
      await seedOidcSession(manager, coreClient, identity);
      coreClient.refreshOidcSession.mockResolvedValue({
        identityStatus: "historical",
        identity,
        tokens: {
          access_token: "rotated-access",
          refresh_token: "rotated-refresh",
          token_type: "Bearer",
          expires_in: 3600,
        },
      });
      let release;
      let started;
      const pending = new Promise((resolve) => {
        started = resolve;
      });
      coreClient.getUserInfo.mockImplementationOnce(() => {
        started();
        return new Promise((resolve, reject) => {
          release = () =>
            failure
              ? reject(new CoreError("Unavailable", "NETWORK_ERROR"))
              : resolve({ sub: identity.subject });
        });
      });
      const outcome = manager.refreshToken().catch((error) => error);
      await pending;
      await manager.logout();
      release();
      expect(await outcome).toBeInstanceOf(Error);
      expect(sessionStorage.values.size).toBe(0);
      expect(refreshTokenStorage.values.size).toBe(0);
      await expect(manager.getSession()).resolves.toBeNull();
    },
  );

  it("rejects a passkey result from an operation started before logout", async () => {
    const { manager, coreClient } = createManager();
    const persist = manager.createTokenPersistenceOperation();
    await manager.logout();
    await expect(
      persist(
        { access_token: "late-token", token_type: "Bearer", expires_in: 3600 },
        "api",
      ),
    ).rejects.toMatchObject({ code: "AUTH_OPERATION_SUPERSEDED" });
    expect(coreClient.verifyIdToken).not.toHaveBeenCalled();
    await expect(manager.getSession()).resolves.toBeNull();
  });

  it("orders logout cleanup after a pending secure-storage write", async () => {
    const sessionStorage = new MemoryStorage();
    const refreshTokenStorage = new MemoryStorage();
    const { manager } = createManager({ sessionStorage, refreshTokenStorage });
    let finishWrite;
    let writeStarted;
    const started = new Promise((resolve) => {
      writeStarted = resolve;
    });
    refreshTokenStorage.setItem = async (key, value) => {
      writeStarted();
      await new Promise((resolve) => {
        finishWrite = resolve;
      });
      refreshTokenStorage.values.set(key, value);
    };
    const pending = manager.persistTokenResponse(
      {
        access_token: "old-access",
        refresh_token: "old-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "api",
      },
      "api",
    );
    const outcome = pending.then(
      () => null,
      (error) => error,
    );
    await started;
    const logout = manager.logout();
    finishWrite();
    await logout;
    expect(await outcome).toMatchObject({ code: "AUTH_OPERATION_SUPERSEDED" });
    expect(sessionStorage.values.size).toBe(0);
    expect(refreshTokenStorage.values.size).toBe(0);
    await expect(manager.getSession()).resolves.toBeNull();
  });

  it("an old restoration cannot repopulate the cache after logout", async () => {
    const { manager, coreClient } = createManager();
    const identity = createIdentity();
    await seedOidcSession(manager, coreClient, identity);
    let finishUserInfo;
    let userInfoStarted;
    const started = new Promise((resolve) => {
      userInfoStarted = resolve;
    });
    coreClient.verifyIdToken.mockResolvedValue(createVerifiedIdToken(identity));
    coreClient.getUserInfo.mockImplementation(() => {
      userInfoStarted();
      return new Promise((resolve) => {
        finishUserInfo = resolve;
      });
    });
    const outcome = manager.getSession().then(
      () => null,
      (error) => error,
    );
    await started;
    await manager.logout();
    finishUserInfo({ sub: identity.subject });
    expect(await outcome).toMatchObject({ code: "AUTH_OPERATION_SUPERSEDED" });
    await expect(manager.getSession()).resolves.toBeNull();
  });
  it("does not restore a session when UserInfo completes after logout", async () => {
    const { manager, coreClient, sessionStorage, refreshTokenStorage } =
      createManager();
    const identity = createIdentity();
    let finishUserInfo;
    let userInfoStarted;
    const started = new Promise((resolve) => {
      userInfoStarted = resolve;
    });
    coreClient.verifyIdToken.mockResolvedValue(createVerifiedIdToken(identity));
    coreClient.getUserInfo.mockImplementation(() => {
      userInfoStarted();
      return new Promise((resolve) => {
        finishUserInfo = resolve;
      });
    });
    const pending = manager.persistTokenResponse({
      access_token: "late-access",
      refresh_token: "late-refresh",
      id_token: "signed-id-token",
      token_type: "Bearer",
      expires_in: 3600,
      scope: "openid profile offline_access",
    });
    const outcome = pending.then(
      () => null,
      (error) => error,
    );
    await started;
    await manager.logout();
    finishUserInfo({ sub: identity.subject });
    expect(await outcome).toMatchObject({ code: "AUTH_OPERATION_SUPERSEDED" });
    expect(sessionStorage.values.size).toBe(0);
    expect(refreshTokenStorage.values.size).toBe(0);
    await expect(manager.getSession()).resolves.toBeNull();
  });
  it.each([
    "https://auth.example.com",
    "https://auth.example.com/",
    "https://auth.example.com/tenant",
    "https://auth.example.com/tenant/",
  ])(
    "retains exact issuer and restores a Native session (%s)",
    async (authority) => {
      expect(sanitizeAuthority(authority)).toBe(authority);
      const identity = { ...createIdentity(), issuer: authority };
      const first = createManager({ authority });
      await seedOidcSession(first.manager, first.coreClient, identity);
      const cold = createManager({
        authority,
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      cold.coreClient.verifyIdToken.mockResolvedValue(
        createVerifiedIdToken(identity),
      );
      cold.coreClient.getUserInfo.mockResolvedValue({ sub: identity.subject });
      await expect(cold.manager.restoreSession()).resolves.toMatchObject({
        session: { identity: { issuer: authority } },
      });
      expect([...first.sessionStorage.values.keys()]).toEqual([
        `gh:v3:${encodeURIComponent(new URL(authority).href)}:${clientId}:session`,
      ]);
    },
  );

  it.each(["https://auth.example.com", "https://auth.example.com/"])(
    "rejects another exact issuer in the same Native storage namespace (%s)",
    async (authority) => {
      const first = createManager({ authority });
      await seedOidcSession(first.manager, first.coreClient, {
        ...createIdentity(),
        issuer: authority,
      });
      const cold = createManager({
        authority: authority.endsWith("/")
          ? authority.slice(0, -1)
          : authority + "/",
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      await expect(cold.manager.restoreSession()).resolves.toBeNull();
      expect(cold.coreClient.verifyIdToken).not.toHaveBeenCalled();
    },
  );

  it.each([
    "https://auth.example.com?tenant=one",
    "https://auth.example.com#fragment",
    "https://user:pass@auth.example.com",
  ])(
    "rejects invalid Native authority rather than rewriting it (%s)",
    (authority) => {
      expect(() => sanitizeAuthority(authority)).toThrow(
        "Authority must not contain",
      );
    },
  );

  it("preserves existing relative Native endpoint resolution", () => {
    expect(
      resolveEndpoint("https://auth.example.com/tenant/", "connect/token"),
    ).toBe("https://auth.example.com/connect/token");
  });

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

  it.each(
    ["restoreSession", "getSession", "getAccessToken"].flatMap((method) =>
      [false, true].flatMap((historical) =>
        ["NETWORK_ERROR", "OIDC_METADATA_REQUEST_FAILED"].map((code) => [
          method,
          historical,
          code,
        ]),
      ),
    ),
  )(
    "retains credentials after %s fails temporarily (historical=%s, %s)",
    async (method, historical, code) => {
      const identity = {
        ...createIdentity(),
        ...(historical
          ? { expiresAt: Math.floor(Date.now() / 1000) - 120 }
          : {}),
      };
      const first = createManager();
      await seedOidcSession(first.manager, first.coreClient, identity);
      const snapshots = [...first.sessionStorage.values.entries()];
      const refreshSnapshots = [...first.refreshTokenStorage.values.entries()];
      const cold = createManager({
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      const verification = historical
        ? cold.coreClient.restoreOidcSession
        : cold.coreClient.verifyIdToken;
      verification.mockRejectedValueOnce(
        new CoreError("Temporarily unavailable", code, { retryable: true }),
      );
      await expect(cold.manager[method]()).rejects.toMatchObject({
        code: "NETWORK_ERROR",
      });
      expect([...first.sessionStorage.values.entries()]).toEqual(snapshots);
      expect([...first.refreshTokenStorage.values.entries()]).toEqual(
        refreshSnapshots,
      );
      expect(cold.coreClient.clearSessionState).not.toHaveBeenCalled();
      if (historical)
        verification.mockResolvedValueOnce({
          identity,
          userInfo: { sub: identity.subject },
        });
      else {
        verification.mockResolvedValueOnce(createVerifiedIdToken(identity));
        cold.coreClient.getUserInfo.mockResolvedValueOnce({
          sub: identity.subject,
        });
      }
      expect(await cold.manager[method]()).not.toBeNull();
      expect([...first.refreshTokenStorage.values.entries()]).toEqual(
        refreshSnapshots,
      );
    },
  );

  it.each([
    "invalid_token",
    "USERINFO_SUBJECT_MISMATCH",
    "ID_TOKEN_VALIDATION_FAILED",
  ])(
    "still deletes credentials after permanent restore failure %s",
    async (code) => {
      const first = createManager();
      await seedOidcSession(first.manager, first.coreClient, createIdentity());
      const cold = createManager({
        sessionStorage: first.sessionStorage,
        refreshTokenStorage: first.refreshTokenStorage,
      });
      cold.coreClient.verifyIdToken.mockRejectedValueOnce(
        new CoreError("Rejected", code),
      );
      await expect(cold.manager.restoreSession()).rejects.toThrow();
      expect(first.sessionStorage.values.size).toBe(0);
      expect(first.refreshTokenStorage.values.size).toBe(0);
    },
  );

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
