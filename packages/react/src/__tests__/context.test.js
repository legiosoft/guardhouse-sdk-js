const React = require("react");
const TestRenderer = require("react-test-renderer");

const mockClients = [];
const mockGenerateState = jest.fn(async () => "generated-state-value");
const mockRefreshOidcSession = jest.fn();
const mockVerifyIdToken = jest.fn();
const mockValidateOAuthCallback = jest.fn();
const mockExchangeAuthorizationCode = jest.fn();
const mockCreateAuthorizationRequest = jest.fn();
const mockGetUserInfo = jest.fn();

jest.mock("@guardhouse/core", () => {
  const actual = jest.requireActual("@guardhouse/core");
  return {
    ...actual,
    GuardhouseClient: jest.fn().mockImplementation((config) => {
      const client = {
        config,
        buildLogoutUrl: jest.fn(() => "https://auth.test/connect/logout"),
        clearSessionState: jest.fn(async () => undefined),
        verifyIdToken: mockVerifyIdToken,
        refreshOidcSession: (...args) => mockRefreshOidcSession(...args),
        validateOAuthCallback: mockValidateOAuthCallback,
        exchangeAuthorizationCode: mockExchangeAuthorizationCode,
        createAuthorizationRequest: mockCreateAuthorizationRequest,
        getUserInfo: mockGetUserInfo,
      };
      mockClients.push(client);
      return client;
    }),
    generateState: (...args) => mockGenerateState(...args),
    setGuardhouseDebug: jest.fn(),
  };
});

const { GuardhouseProvider, useAuth } = require("../context");
const { ProtectedRoute } = require("../ProtectedRoute");
const { SessionStorageAdapter } = require("../utils");
const {
  getOidcSessionStorageKey,
  getLogoutStateStorageKey,
} = require("../security-state");

const baseConfig = {
  authority: "https://auth.test/",
  clientId: "client-a",
  redirectUri: "https://app.test/callback",
  audiencePolicy: "oidc-optional",
};

let latestAuth = null;

function Probe() {
  latestAuth = useAuth();
  return null;
}

function provider(config) {
  return React.createElement(
    GuardhouseProvider,
    { config },
    React.createElement(Probe),
  );
}

function installBrowserStorage(
  overrides = {},
  initialUrl = "https://app.test/",
) {
  const values = new Map();
  let currentUrl = new URL(initialUrl);
  const replace = jest.fn((value) => {
    currentUrl = new URL(value, currentUrl);
  });
  const replaceState = jest.fn((_state, _title, value) => {
    currentUrl = new URL(value, currentUrl);
  });
  global.sessionStorage = {
    getItem: jest.fn((key) => values.get(key) ?? null),
    setItem: jest.fn((key, value) => values.set(key, value)),
    removeItem: jest.fn((key) => values.delete(key)),
    ...overrides,
  };
  global.window = {
    location: {
      get href() {
        return currentUrl.toString();
      },
      set href(value) {
        currentUrl = new URL(value, currentUrl);
      },
      get origin() {
        return currentUrl.origin;
      },
      get pathname() {
        return currentUrl.pathname;
      },
      get search() {
        return currentUrl.search;
      },
      get hash() {
        return currentUrl.hash;
      },
      replace,
    },
    history: { state: null, replaceState },
  };

  return { values, replace, replaceState };
}

async function flushEffects() {
  await TestRenderer.act(async () => {
    for (let attempt = 0; attempt < 12; attempt += 1) {
      await Promise.resolve();
    }
  });
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function identity(overrides = {}) {
  return {
    issuer: "https://auth.test/",
    clientId: "client-a",
    subject: "user-1",
    audiences: ["client-a"],
    authorizedParty: null,
    issuedAt: 1_700_000_000,
    expiresAt: 2_000_000_000,
    nonce: "nonce-value-1234",
    authTime: 1_700_000_000,
    acr: null,
    amr: [],
    sessionId: null,
    ...overrides,
  };
}

function storedSession(overrides = {}) {
  return {
    version: 3,
    clientId: "client-a",
    accessToken: "expired-access-token",
    refreshToken: "recoverable-refresh-token",
    idToken: "previously-verified-id-token",
    tokenType: "Bearer",
    expiresAt: 1,
    scope: "openid profile",
    identity: identity(),
    oidc: { issuer: "https://auth.test/" },
    ...overrides,
  };
}

function authorizationTransaction(state, applicationState) {
  const now = Date.now();
  return {
    version: 2,
    issuer: "https://auth.test/",
    clientId: "client-a",
    redirectUri: "https://app.test/callback",
    state,
    codeVerifier: "v".repeat(43),
    codeChallenge: "c".repeat(43),
    nonce: "nonce-value-1234",
    requestedScope: "openid profile",
    requestedResources: [],
    requiredAcrValues: [],
    requiredAmrValues: [],
    responseMode: "query",
    applicationState,
    createdAt: now,
    expiresAt: now + 10 * 60 * 1000,
    issRequired: true,
  };
}

function transactionStorageKey(state) {
  return `gh:v3:transaction:https%3A%2F%2Fauth.test%2F:client-a:${state}`;
}

describe("GuardhouseProvider operation safety", () => {
  beforeAll(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
  });

  beforeEach(() => {
    latestAuth = null;
    mockClients.length = 0;
    mockGenerateState.mockReset();
    mockGenerateState.mockResolvedValue("generated-state-value");
    mockRefreshOidcSession.mockReset();
    mockVerifyIdToken.mockReset();
    mockValidateOAuthCallback.mockReset();
    mockExchangeAuthorizationCode.mockReset();
    mockCreateAuthorizationRequest.mockReset();
    mockGetUserInfo.mockReset();
    installBrowserStorage();
  });

  afterEach(() => {
    delete global.window;
    delete global.sessionStorage;
  });

  it("surfaces storage initialization failures instead of remaining loading", async () => {
    installBrowserStorage({
      removeItem: jest.fn(() => {
        throw new Error("Session storage is blocked");
      }),
    });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(latestAuth).toMatchObject({
      isAuthenticated: false,
      isLoading: false,
      error: expect.objectContaining({ message: "Session storage is blocked" }),
    });

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("does not finish logout for a client replaced while state is generated", async () => {
    let resolveLogoutState;
    mockGenerateState.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveLogoutState = resolve;
        }),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    let logoutPromise;
    await TestRenderer.act(async () => {
      logoutPromise = latestAuth.logout();
      await Promise.resolve();
      await Promise.resolve();
    });

    await TestRenderer.act(async () => {
      renderer.update(
        provider({
          ...baseConfig,
          clientId: "client-b",
        }),
      );
    });

    await TestRenderer.act(async () => {
      resolveLogoutState("logout-state");
      await logoutPromise;
    });

    expect(mockClients[0].buildLogoutUrl).not.toHaveBeenCalled();
    expect(global.window.location.href).toBe("https://app.test/");

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("does not restart login while the browser is navigating to logout", async () => {
    const session = storedSession({ expiresAt: 2_000_000_000 });
    global.sessionStorage.setItem(
      getOidcSessionStorageKey(baseConfig.authority, baseConfig.clientId),
      JSON.stringify(session),
    );
    mockVerifyIdToken.mockResolvedValue({
      payload: { sub: "user-1" },
      identity: session.identity,
    });
    mockGetUserInfo.mockResolvedValue({ sub: "user-1" });
    mockCreateAuthorizationRequest.mockResolvedValue({
      authorizationUrl: "https://auth.test/connect/authorize",
      transaction: authorizationTransaction("new-login-state"),
    });
    // A location assignment starts navigation; the current React tree can still
    // run effects until the destination response replaces the document.
    const navigate = jest.fn();
    Object.defineProperty(global.window.location, "href", {
      get: () => "https://app.test/",
      set: navigate,
    });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(
        React.createElement(
          GuardhouseProvider,
          { config: baseConfig },
          React.createElement(Probe),
          React.createElement(ProtectedRoute, null, "Private page"),
        ),
      );
    });
    await flushEffects();
    expect(latestAuth.isAuthenticated).toBe(true);
    expect(mockCreateAuthorizationRequest).not.toHaveBeenCalled();

    await TestRenderer.act(async () => latestAuth.logout());
    await flushEffects();

    // Background token requests and repeated clicks must not release the
    // pending navigation or start a second authentication operation.
    await TestRenderer.act(async () => {
      expect(await latestAuth.getAccessTokenSilently()).toBeNull();
      await latestAuth.logout();
    });
    await flushEffects();
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith("https://auth.test/connect/logout");
    expect(mockCreateAuthorizationRequest).not.toHaveBeenCalled();
    expect(latestAuth).toMatchObject({
      isLoading: true,
      isAuthenticated: false,
      user: null,
    });
    await TestRenderer.act(async () => renderer.unmount());
  });

  it("releases the pending logout state when browser navigation throws", async () => {
    const navigate = jest.fn(() => {
      throw new Error("Navigation blocked");
    });
    Object.defineProperty(global.window.location, "href", {
      get: () => "https://app.test/",
      set: navigate,
    });
    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    await TestRenderer.act(async () => {
      await expect(latestAuth.logout()).rejects.toThrow("Navigation blocked");
    });
    expect(latestAuth).toMatchObject({
      isLoading: false,
      isAuthenticated: false,
      error: expect.objectContaining({ message: "Navigation blocked" }),
    });
    navigate.mockImplementation(() => undefined);
    await TestRenderer.act(async () => latestAuth.logout());
    expect(navigate).toHaveBeenCalledTimes(2);
    expect(latestAuth.isLoading).toBe(true);
    await TestRenderer.act(async () => renderer.unmount());
  });

  it.each([
    ["client-a", "client-b", false],
    ["client-b", "client-a", false],
    ["client-a", "client-b", true],
    ["client-b", "client-a", true],
  ])(
    "isolates logout after navigating /%s to /%s (destination session: %s)",
    async (source, destination, hasDestinationSession) => {
      installBrowserStorage({}, `https://app.test/${source}/`);
      const makeSession = (clientId) =>
        storedSession({
          clientId,
          accessToken: `${clientId}-access-token`,
          idToken: `${clientId}-id-token`,
          expiresAt: 2_000_000_000,
          identity: identity({ clientId, audiences: [clientId] }),
        });
      const sourceSession = makeSession(source);
      const destinationSession = makeSession(destination);
      const sourceKey = getOidcSessionStorageKey(baseConfig.authority, source);
      const destinationKey = getOidcSessionStorageKey(
        baseConfig.authority,
        destination,
      );
      const sourceSerialized = JSON.stringify(sourceSession);
      global.sessionStorage.setItem(sourceKey, sourceSerialized);
      if (hasDestinationSession) {
        global.sessionStorage.setItem(
          destinationKey,
          JSON.stringify(destinationSession),
        );
      }
      mockVerifyIdToken.mockImplementation(async (token) => ({
        payload: { sub: "user-1" },
        identity:
          token === sourceSession.idToken
            ? sourceSession.identity
            : destinationSession.identity,
      }));
      mockGetUserInfo.mockResolvedValue({ sub: "user-1" });

      let renderer;
      await TestRenderer.act(async () => {
        renderer = TestRenderer.create(
          provider({ ...baseConfig, clientId: source }),
        );
      });
      await flushEffects();
      expect(latestAuth.isAuthenticated).toBe(true);
      await TestRenderer.act(async () => renderer.unmount());

      // Address-bar navigation creates a new app but retains this tab's storage.
      global.window.location.href = `https://app.test/${destination}/`;
      mockVerifyIdToken.mockClear();
      await TestRenderer.act(async () => {
        renderer = TestRenderer.create(
          provider({
            ...baseConfig,
            clientId: destination,
            logoutRedirectUri: `https://app.test/${destination}/`,
          }),
        );
      });
      await flushEffects();
      expect(latestAuth).toMatchObject({
        isAuthenticated: hasDestinationSession,
        isLoading: false,
      });
      expect(mockVerifyIdToken).not.toHaveBeenCalledWith(
        sourceSession.idToken,
        expect.anything(),
      );
      await TestRenderer.act(async () => {
        expect(await latestAuth.getAccessToken()).toBe(
          hasDestinationSession ? destinationSession.accessToken : null,
        );
      });

      await TestRenderer.act(async () => latestAuth.logout());
      expect(mockClients[1].buildLogoutUrl).toHaveBeenCalledWith({
        postLogoutRedirectUri: `https://app.test/${destination}/`,
        idTokenHint: hasDestinationSession
          ? destinationSession.idToken
          : undefined,
        state: "generated-state-value",
        federated: undefined,
      });
      expect(global.sessionStorage.getItem(sourceKey)).toBe(sourceSerialized);
      expect(global.sessionStorage.getItem(destinationKey)).toBeNull();
      expect(
        global.sessionStorage.getItem(
          getLogoutStateStorageKey(baseConfig.authority, destination),
        ),
      ).toBe("generated-state-value");
      expect(mockRefreshOidcSession).not.toHaveBeenCalled();
      expect(global.window.location.href).toBe(
        "https://auth.test/connect/logout",
      );
      await TestRenderer.act(async () => renderer.unmount());
    },
  );

  it("never uses a legacy shared session as a logout hint", async () => {
    const legacySession = JSON.stringify({
      accessToken: "client-b-access-token",
      idToken: "client-b-id-token",
      tokenType: "Bearer",
      expiresAt: 2_000_000_000,
      user: { sub: "user-1" },
      oidc: { issuer: "https://auth.test/" },
    });
    global.sessionStorage.setItem("gh_oidc_session", legacySession);

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();
    expect(latestAuth.isAuthenticated).toBe(false);
    expect(global.sessionStorage.getItem("gh_oidc_session")).toBeNull();

    // A v1 app may write the shared key again after this provider initializes.
    global.sessionStorage.setItem("gh_oidc_session", legacySession);
    await TestRenderer.act(async () => latestAuth.logout());
    expect(mockClients[0].buildLogoutUrl).toHaveBeenCalledWith(
      expect.objectContaining({ idTokenHint: undefined }),
    );
    expect(global.sessionStorage.getItem("gh_oidc_session")).toBeNull();
    expect(mockVerifyIdToken).not.toHaveBeenCalled();
    await TestRenderer.act(async () => renderer.unmount());
  });

  it("preserves the stored session after a transient refresh failure", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    const identity = {
      issuer: "https://auth.test/",
      clientId: "client-a",
      subject: "user-1",
      audiences: ["client-a"],
      authorizedParty: null,
      issuedAt: 1,
      expiresAt: 2,
      nonce: "nonce-value-1234",
      authTime: 1,
      acr: null,
      amr: [],
      sessionId: null,
    };
    const serializedSession = JSON.stringify({
      version: 3,
      clientId: "client-a",
      accessToken: "expired-access-token",
      refreshToken: "recoverable-refresh-token",
      idToken: "previously-verified-id-token",
      tokenType: "Bearer",
      expiresAt: 1,
      scope: "openid profile",
      identity,
      oidc: { issuer: "https://auth.test/" },
    });
    global.sessionStorage.setItem(sessionKey, serializedSession);
    mockRefreshOidcSession.mockRejectedValueOnce(
      Object.assign(new Error("Network unavailable"), {
        code: "NETWORK_ERROR",
      }),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBe(serializedSession);
    expect(mockClients[0].clearSessionState).not.toHaveBeenCalled();

    await TestRenderer.act(async () => renderer.unmount());
  });

  it.each([
    ["historical ID-token signature", "signature verification failed"],
    ["historical ACR/AMR assurance", "required assurance was not satisfied"],
  ])("clears the stored session after %s failure", async (_name, message) => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(sessionKey, JSON.stringify(storedSession()));
    mockRefreshOidcSession.mockRejectedValueOnce(
      Object.assign(new Error(message), {
        code: "ID_TOKEN_VALIDATION_FAILED",
      }),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(mockClients[0].clearSessionState).toHaveBeenCalledTimes(1);
    expect(latestAuth.isAuthenticated).toBe(false);

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("clears the stored session after a terminal refresh failure", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(
      sessionKey,
      JSON.stringify(
        {
          version: 3,
          clientId: "client-a",
          accessToken: "expired-access-token",
          refreshToken: "revoked-refresh-token",
          idToken: "previously-verified-id-token",
          tokenType: "Bearer",
          expiresAt: 1,
          scope: "openid profile",
          identity: {
            issuer: "https://auth.test/",
            clientId: "client-a",
            subject: "user-1",
            audiences: ["client-a"],
            authorizedParty: null,
            issuedAt: 1,
            expiresAt: 2,
            nonce: "nonce-value-1234",
            authTime: 1,
            acr: null,
            amr: [],
            sessionId: null,
          },
          oidc: { issuer: "https://auth.test/" },
        },
        null,
        2,
      ),
    );
    mockRefreshOidcSession.mockRejectedValueOnce(
      Object.assign(new Error("Refresh token revoked"), {
        code: "invalid_grant",
      }),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(mockClients[0].clearSessionState).toHaveBeenCalledTimes(1);

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("preserves and restores a newer session when stale refresh cleanup loses the race", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    const staleSerialized = JSON.stringify(storedSession(), null, 2);
    global.sessionStorage.setItem(sessionKey, staleSerialized);
    const refresh = createDeferred();
    mockRefreshOidcSession.mockReturnValueOnce(refresh.promise);

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();
    expect(mockRefreshOidcSession).toHaveBeenCalledTimes(1);

    const newerIdentity = identity({ subject: "user-2" });
    const newerSession = storedSession({
      accessToken: "newer-access-token",
      refreshToken: "newer-refresh-token",
      idToken: "newer-signed-id-token",
      expiresAt: 2_000_000_000,
      identity: newerIdentity,
    });
    const newerSerialized = JSON.stringify(newerSession);
    global.sessionStorage.setItem(sessionKey, newerSerialized);
    mockVerifyIdToken.mockResolvedValueOnce({
      payload: { sub: "user-2", roles: ["signed-reader"] },
      identity: newerIdentity,
    });
    mockGetUserInfo.mockResolvedValueOnce({
      sub: "user-2",
      roles: ["current-reader"],
    });

    await TestRenderer.act(async () => {
      refresh.reject(
        Object.assign(new Error("Old refresh token revoked"), {
          code: "invalid_grant",
        }),
      );
      await refresh.promise.catch(() => undefined);
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBe(newerSerialized);
    expect(mockVerifyIdToken).toHaveBeenCalledWith(
      "newer-signed-id-token",
      expect.objectContaining({ purpose: "session" }),
    );
    expect(mockClients[0].clearSessionState).not.toHaveBeenCalled();
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-2", roles: ["current-reader"] },
    });

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("never publishes a successfully verified stale session after another adapter commits a winner", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    const staleSession = storedSession({
      accessToken: "stale-access-token",
      expiresAt: 2_000_000_000,
    });
    global.sessionStorage.setItem(sessionKey, JSON.stringify(staleSession));
    const staleVerification = createDeferred();
    mockVerifyIdToken.mockReturnValueOnce(staleVerification.promise);

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();
    expect(mockVerifyIdToken).toHaveBeenCalledTimes(1);

    const winnerIdentity = identity({ subject: "user-2" });
    const winnerSession = storedSession({
      accessToken: "winner-access-token",
      refreshToken: "winner-refresh-token",
      idToken: "winner-id-token",
      expiresAt: 2_000_000_000,
      identity: winnerIdentity,
    });
    const winnerSerialized = JSON.stringify(winnerSession);
    const winnerAdapter = new SessionStorageAdapter();
    await winnerAdapter.setItem(sessionKey, winnerSerialized);

    mockVerifyIdToken.mockResolvedValueOnce({
      payload: { sub: "user-2", roles: ["winner-signed"] },
      identity: winnerIdentity,
    });
    mockGetUserInfo
      .mockResolvedValueOnce({ sub: "user-1", roles: ["stale-role"] })
      .mockResolvedValueOnce({ sub: "user-2", roles: ["winner-role"] });

    await TestRenderer.act(async () => {
      staleVerification.resolve({
        payload: { sub: "user-1", roles: ["stale-signed"] },
        identity: staleSession.identity,
      });
      await staleVerification.promise;
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBe(winnerSerialized);
    expect(mockVerifyIdToken).toHaveBeenNthCalledWith(
      2,
      "winner-id-token",
      expect.objectContaining({ purpose: "session" }),
    );
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-2", roles: ["winner-role"] },
    });

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("never overwrites a newer session with a successful stale refresh", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    const staleSession = storedSession();
    global.sessionStorage.setItem(sessionKey, JSON.stringify(staleSession));
    const staleRefresh = createDeferred();
    mockRefreshOidcSession.mockReturnValueOnce(staleRefresh.promise);

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();
    expect(mockRefreshOidcSession).toHaveBeenCalledTimes(1);

    const winnerIdentity = identity({ subject: "user-2" });
    const winnerSession = storedSession({
      accessToken: "winner-access-token",
      refreshToken: "winner-refresh-token",
      idToken: "winner-id-token",
      expiresAt: 2_000_000_000,
      identity: winnerIdentity,
    });
    const winnerSerialized = JSON.stringify(winnerSession);
    const winnerAdapter = new SessionStorageAdapter();
    await winnerAdapter.setItem(sessionKey, winnerSerialized);

    mockVerifyIdToken.mockResolvedValueOnce({
      payload: { sub: "user-2" },
      identity: winnerIdentity,
    });
    mockGetUserInfo
      .mockResolvedValueOnce({ sub: "user-1", roles: ["stale-refreshed"] })
      .mockResolvedValueOnce({ sub: "user-2", roles: ["winner-role"] });

    await TestRenderer.act(async () => {
      staleRefresh.resolve({
        identityStatus: "historical",
        tokens: {
          access_token: "stale-refreshed-access-token",
          token_type: "Bearer",
          expires_in: 3600,
        },
        identity: staleSession.identity,
        idToken: undefined,
      });
      await staleRefresh.promise;
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBe(winnerSerialized);
    expect(global.sessionStorage.setItem).not.toHaveBeenCalledWith(
      sessionKey,
      expect.stringContaining("stale-refreshed-access-token"),
    );
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-2", roles: ["winner-role"] },
    });

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("restores a newer winner after a retryable stale refresh failure", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(sessionKey, JSON.stringify(storedSession()));
    const staleRefresh = createDeferred();
    mockRefreshOidcSession.mockReturnValueOnce(staleRefresh.promise);

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();
    expect(mockRefreshOidcSession).toHaveBeenCalledTimes(1);

    const winnerIdentity = identity({ subject: "user-2" });
    const winnerSession = storedSession({
      accessToken: "winner-access-token",
      refreshToken: "winner-refresh-token",
      idToken: "winner-id-token",
      expiresAt: 2_000_000_000,
      identity: winnerIdentity,
    });
    const winnerSerialized = JSON.stringify(winnerSession);
    const winnerAdapter = new SessionStorageAdapter();
    await winnerAdapter.setItem(sessionKey, winnerSerialized);
    mockVerifyIdToken.mockResolvedValueOnce({
      payload: { sub: "user-2" },
      identity: winnerIdentity,
    });
    mockGetUserInfo.mockResolvedValueOnce({
      sub: "user-2",
      roles: ["winner-role"],
    });

    await TestRenderer.act(async () => {
      staleRefresh.reject(
        Object.assign(new Error("Network unavailable"), {
          code: "NETWORK_ERROR",
        }),
      );
      await staleRefresh.promise.catch(() => undefined);
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBe(winnerSerialized);
    expect(mockClients[0].clearSessionState).not.toHaveBeenCalled();
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-2", roles: ["winner-role"] },
    });

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("does not restore a session copied into another client namespace", async () => {
    const clientBSessionKey =
      "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-b";
    global.sessionStorage.setItem(
      clientBSessionKey,
      JSON.stringify(storedSession()),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(
        provider({ ...baseConfig, clientId: "client-b" }),
      );
    });
    await flushEffects();

    expect(latestAuth).toMatchObject({
      isAuthenticated: false,
      isLoading: false,
      user: null,
    });
    expect(global.sessionStorage.getItem(clientBSessionKey)).toBeNull();
    expect(mockVerifyIdToken).not.toHaveBeenCalled();

    // Logout must also reject a foreign record written after initialization.
    global.sessionStorage.setItem(
      clientBSessionKey,
      JSON.stringify(storedSession()),
    );
    await TestRenderer.act(async () => latestAuth.logout());
    expect(mockClients[0].buildLogoutUrl).toHaveBeenCalledWith(
      expect.objectContaining({ idTokenHint: undefined }),
    );
    expect(global.sessionStorage.getItem(clientBSessionKey)).toBeNull();

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("uses signed refresh continuity and fresh UserInfo instead of stored roles", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(
      sessionKey,
      JSON.stringify({
        ...storedSession(),
        user: { sub: "user-1", roles: ["stale-admin"] },
      }),
    );
    mockRefreshOidcSession.mockResolvedValueOnce({
      identityStatus: "historical",
      tokens: {
        access_token: "refreshed-access-token",
        token_type: "Bearer",
        expires_in: 3600,
      },
      identity: identity(),
      idToken: undefined,
    });
    const currentRoles = ["current-reader"];
    const currentClaims = { preferences: { theme: "dark" } };
    mockGetUserInfo.mockResolvedValueOnce({
      sub: "user-1",
      roles: currentRoles,
      currentClaims,
    });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(mockRefreshOidcSession).toHaveBeenCalledWith(
      "recoverable-refresh-token",
      expect.objectContaining({
        previousIdToken: "previously-verified-id-token",
        grantedScope: "openid profile",
      }),
    );
    expect(mockGetUserInfo).toHaveBeenCalledWith(
      "refreshed-access-token",
      identity(),
    );
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-1", roles: ["current-reader"] },
    });
    const persisted = JSON.parse(global.sessionStorage.getItem(sessionKey));
    expect(persisted).toMatchObject({
      accessToken: "refreshed-access-token",
      idToken: "previously-verified-id-token",
      scope: "openid profile",
    });
    expect(persisted).not.toHaveProperty("user");

    currentRoles.push("admin");
    currentClaims.preferences.theme = "attacker-theme";
    expect(latestAuth.user).toMatchObject({
      roles: ["current-reader"],
      currentClaims: { preferences: { theme: "dark" } },
    });
    expect(Object.isFrozen(latestAuth.user)).toBe(true);
    expect(Object.isFrozen(latestAuth.user.roles)).toBe(true);
    expect(Object.isFrozen(latestAuth.user.currentClaims.preferences)).toBe(
      true,
    );

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("clears durable state when Core rejects refresh scope escalation", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(sessionKey, JSON.stringify(storedSession()));
    mockRefreshOidcSession.mockRejectedValueOnce(
      Object.assign(new Error("Refresh scope escalated"), {
        code: "SCOPE_ESCALATION_DETECTED",
      }),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(mockRefreshOidcSession).toHaveBeenCalledWith(
      "recoverable-refresh-token",
      expect.objectContaining({ grantedScope: "openid profile" }),
    );
    expect(global.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(latestAuth.isAuthenticated).toBe(false);

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("clears a rotated refresh session when fresh UserInfo fails", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(sessionKey, JSON.stringify(storedSession()));
    mockRefreshOidcSession.mockResolvedValueOnce({
      identityStatus: "historical",
      tokens: {
        access_token: "rotated-access-token",
        refresh_token: "rotated-refresh-token",
        token_type: "Bearer",
        expires_in: 3600,
      },
      identity: identity(),
      idToken: undefined,
    });
    mockGetUserInfo.mockRejectedValueOnce(new Error("UserInfo unavailable"));

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(mockClients[0].clearSessionState).toHaveBeenCalledTimes(1);
    expect(latestAuth.isAuthenticated).toBe(false);

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("clears a rotated session if refreshed identity metadata is inconsistent", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    global.sessionStorage.setItem(sessionKey, JSON.stringify(storedSession()));
    const inconsistentIdentity = identity({ clientId: "another-client" });
    mockRefreshOidcSession.mockResolvedValueOnce({
      identityStatus: "current",
      tokens: {
        access_token: "rotated-access-token",
        refresh_token: "rotated-refresh-token",
        id_token: "replacement-id-token",
        token_type: "Bearer",
        expires_in: 3600,
      },
      identity: inconsistentIdentity,
      idToken: {
        payload: { sub: "user-1" },
        identity: inconsistentIdentity,
      },
    });
    mockGetUserInfo.mockResolvedValueOnce({ sub: "user-1" });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(mockClients[0].clearSessionState).toHaveBeenCalledTimes(1);
    expect(latestAuth.isAuthenticated).toBe(false);

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("clears the old refresh session when persisting the rotated session fails", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    const { values } = installBrowserStorage();
    values.set(sessionKey, JSON.stringify(storedSession()));
    global.sessionStorage.setItem = jest.fn((key, value) => {
      if (key === sessionKey) {
        throw new Error("Session storage write failed");
      }
      values.set(key, value);
    });
    mockRefreshOidcSession.mockResolvedValueOnce({
      identityStatus: "historical",
      tokens: {
        access_token: "rotated-access-token",
        refresh_token: "rotated-refresh-token",
        token_type: "Bearer",
        expires_in: 3600,
      },
      identity: identity(),
      idToken: undefined,
    });
    mockGetUserInfo.mockResolvedValueOnce({ sub: "user-1" });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(mockClients[0].clearSessionState).toHaveBeenCalledTimes(1);
    expect(latestAuth.isAuthenticated).toBe(false);

    await TestRenderer.act(async () => renderer.unmount());
  });
});

describe("GuardhouseProvider callbacks and protected routes", () => {
  const activeState = "active-state-value-123456";

  beforeAll(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
  });

  beforeEach(() => {
    latestAuth = null;
    mockClients.length = 0;
    mockGenerateState.mockReset();
    mockGenerateState.mockResolvedValue("generated-state-value");
    mockRefreshOidcSession.mockReset();
    mockVerifyIdToken.mockReset();
    mockValidateOAuthCallback.mockReset();
    mockExchangeAuthorizationCode.mockReset();
    mockCreateAuthorizationRequest.mockReset();
    mockGetUserInfo.mockReset();
    installBrowserStorage();
  });

  afterEach(() => {
    delete global.window;
    delete global.sessionStorage;
  });

  it.each([
    {
      name: "duplicate query state",
      callbackUrl: `https://app.test/callback?code=abc&state=${activeState}&state=other-valid-state-1234&tab=profile#section=details`,
      sanitizedUrl: "https://app.test/callback?tab=profile#section=details",
    },
    {
      name: "query code with fragment state",
      callbackUrl: `https://app.test/callback?code=abc&tab=profile#state=${activeState}&section=details`,
      sanitizedUrl: "https://app.test/callback?tab=profile#section=details",
    },
  ])(
    "locates the active transaction for $name so Core rejects and React sanitizes it",
    async ({ callbackUrl, sanitizedUrl }) => {
      installBrowserStorage({}, callbackUrl);
      const transaction = authorizationTransaction(activeState);
      const storageKey = transactionStorageKey(activeState);
      global.sessionStorage.setItem(storageKey, JSON.stringify(transaction));
      const callbackError = new Error("Invalid OAuth callback");
      mockValidateOAuthCallback.mockRejectedValueOnce(callbackError);

      let renderer;
      await TestRenderer.act(async () => {
        renderer = TestRenderer.create(provider(baseConfig));
      });
      await flushEffects();

      expect(mockValidateOAuthCallback).toHaveBeenCalledWith(
        { mode: "query", url: callbackUrl },
        expect.objectContaining({ state: activeState }),
      );
      expect(global.window.location.href).toBe(sanitizedUrl);
      expect(global.sessionStorage.getItem(storageKey)).toBeNull();
      expect(latestAuth).toMatchObject({
        isAuthenticated: false,
        error: callbackError,
      });

      await TestRenderer.act(async () => renderer.unmount());
    },
  );

  it("does not clear an authenticated session for an unsolicited callback", async () => {
    const sessionKey = "gh:v3:session:https%3A%2F%2Fauth.test%2F:client-a";
    const activeSession = storedSession({
      accessToken: "active-access-token",
      expiresAt: 2_000_000_000,
    });
    const callbackUrl =
      "https://app.test/callback?code=unsolicited&state=unknown-state-value-1234";
    installBrowserStorage({}, callbackUrl);
    global.sessionStorage.setItem(sessionKey, JSON.stringify(activeSession));
    mockVerifyIdToken.mockResolvedValueOnce({
      payload: { sub: "user-1", roles: ["signed-role"] },
      identity: activeSession.identity,
    });
    mockGetUserInfo.mockResolvedValueOnce({
      sub: "user-1",
      roles: ["current-role"],
    });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(mockValidateOAuthCallback).not.toHaveBeenCalled();
    expect(global.sessionStorage.getItem(sessionKey)).toBe(
      JSON.stringify(activeSession),
    );
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-1", roles: ["current-role"] },
    });
    expect(global.window.location.href).toBe(callbackUrl);

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("sanitizes a valid callback and restores its validated return path", async () => {
    const callbackUrl = `https://app.test/callback?code=valid-code&state=${activeState}&tab=profile`;
    const { replace } = installBrowserStorage({}, callbackUrl);
    const transaction = authorizationTransaction(activeState, {
      returnTo: "/orders?status=open#current",
    });
    global.sessionStorage.setItem(
      transactionStorageKey(activeState),
      JSON.stringify(transaction),
    );
    const verifiedIdentity = identity();
    mockValidateOAuthCallback.mockResolvedValueOnce({
      type: "authorization_code",
      code: "valid-code",
      state: activeState,
      sessionState: "server-session",
      sanitizedUrl: "https://app.test/callback?tab=profile",
    });
    mockExchangeAuthorizationCode.mockResolvedValueOnce({
      mode: "oidc",
      tokens: {
        access_token: "access-token",
        refresh_token: "refresh-token",
        id_token: "signed-id-token",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile",
      },
      idToken: {
        payload: { sub: "user-1", roles: ["signed-role"] },
        identity: verifiedIdentity,
      },
    });
    mockGetUserInfo.mockResolvedValueOnce({
      sub: "user-1",
      roles: ["current-role"],
    });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(provider(baseConfig));
    });
    await flushEffects();

    expect(global.window.history.replaceState).toHaveBeenCalledWith(
      null,
      "",
      "https://app.test/callback?tab=profile",
    );
    expect(replace).toHaveBeenCalledWith(
      "https://app.test/orders?status=open#current",
    );
    expect(latestAuth).toMatchObject({
      isAuthenticated: true,
      user: { sub: "user-1", roles: ["current-role"] },
    });

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("deduplicates competing protected-route logins and preserves the full return path", async () => {
    installBrowserStorage(
      {},
      "https://app.test/orders?status=open#current-section",
    );
    const authorization = createDeferred();
    mockCreateAuthorizationRequest.mockReturnValueOnce(authorization.promise);

    const guardedApp = React.createElement(
      React.StrictMode,
      null,
      React.createElement(
        GuardhouseProvider,
        { config: baseConfig },
        React.createElement(
          React.Fragment,
          null,
          React.createElement(Probe, { key: "probe" }),
          React.createElement(
            ProtectedRoute,
            { key: "first" },
            React.createElement("p", null, "First protected view"),
          ),
          React.createElement(
            ProtectedRoute,
            { key: "second" },
            React.createElement("p", null, "Second protected view"),
          ),
        ),
      ),
    );

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(guardedApp);
    });
    await flushEffects();

    expect(mockCreateAuthorizationRequest).toHaveBeenCalledTimes(1);
    expect(mockCreateAuthorizationRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        applicationState: {
          returnTo: "/orders?status=open#current-section",
        },
      }),
    );

    const transaction = authorizationTransaction(activeState, {
      returnTo: "/orders?status=open#current-section",
    });
    await TestRenderer.act(async () => {
      authorization.resolve({
        authorizationUrl: "https://auth.test/connect/authorize?request=one",
        transaction,
      });
      await authorization.promise;
    });
    await flushEffects();

    expect(mockCreateAuthorizationRequest).toHaveBeenCalledTimes(1);
    expect(global.window.location.href).toBe(
      "https://auth.test/connect/authorize?request=one",
    );
    expect(
      global.sessionStorage.getItem(transactionStorageKey(activeState)),
    ).toBe(JSON.stringify(transaction));

    await TestRenderer.act(async () => renderer.unmount());
  });

  it("surfaces redirect failure and retries after the provider latch is released", async () => {
    installBrowserStorage({}, "https://app.test/protected");
    const redirectError = new Error("Browser navigation blocked");
    const transaction = authorizationTransaction(activeState, {
      returnTo: "/protected",
    });
    mockCreateAuthorizationRequest
      .mockRejectedValueOnce(redirectError)
      .mockResolvedValueOnce({
        authorizationUrl: "https://auth.test/connect/authorize?retry=one",
        transaction,
      });

    let renderer;
    await TestRenderer.act(async () => {
      renderer = TestRenderer.create(
        React.createElement(
          GuardhouseProvider,
          { config: baseConfig },
          React.createElement(
            React.Fragment,
            null,
            React.createElement(Probe),
            React.createElement(
              ProtectedRoute,
              null,
              React.createElement("p", null, "Protected view"),
            ),
          ),
        ),
      );
    });
    await flushEffects();

    expect(renderer.root.findByProps({ role: "alert" })).toBeDefined();
    expect(latestAuth.error).toBe(redirectError);
    expect(mockCreateAuthorizationRequest).toHaveBeenCalledTimes(1);

    const retryButton = renderer.root.findByType("button");
    await TestRenderer.act(async () => {
      retryButton.props.onClick();
    });
    await flushEffects();

    expect(mockCreateAuthorizationRequest).toHaveBeenCalledTimes(2);
    expect(global.window.location.href).toBe(
      "https://auth.test/connect/authorize?retry=one",
    );

    await TestRenderer.act(async () => renderer.unmount());
  });
});
