const React = require("react");
const Renderer = require("react-test-renderer");
const { generateKeyPairSync, sign, webcrypto } = require("node:crypto");
const { GuardhouseClient } = require("@guardhouse/core");
const { GuardhouseProvider, useAuth } = require("../context");
const { ProtectedRoute } = require("../ProtectedRoute");
const {
  buildRefreshedOidcSession,
  getOidcSessionStorageKey,
} = require("../security-state");

// Use the real Core verifier, signed JWTs and provider restoration, with only
// the transport and browser storage replaced. No verified identities are forged.
const issuer = "https://historical.test/";
const clientId = "web-client";
const scope = "openid profile offline_access";
const key = getOidcSessionStorageKey(issuer, clientId);
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const jwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: "key",
  alg: "RS256",
};
const now = () => Math.floor(Date.now() / 1000);
const originalCrypto = global.crypto;
let values,
  calls,
  userInfo,
  responseTokens,
  userInfoStatus,
  renderer,
  auth,
  failure;

function token(overrides = {}) {
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", kid: "key" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iss: issuer,
      aud: clientId,
      sub: "user-1",
      iat: now() - 600,
      exp: now() - 120,
      nonce: "original-nonce",
      acr: "mfa",
      amr: ["pwd", "otp"],
      oldRole: "admin",
      ...overrides,
    }),
  ).toString("base64url");
  const input = `${header}.${payload}`;
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url")}`;
}

function client() {
  return new GuardhouseClient({ authority: issuer, clientId });
}

async function refreshedSnapshot(raw = token()) {
  const result = await client().refreshOidcSession("original-refresh", {
    previousIdToken: raw,
    grantedScope: scope,
  });
  return buildRefreshedOidcSession(
    {
      version: 3,
      clientId,
      accessToken: "initial-access",
      refreshToken: "original-refresh",
      idToken: raw,
      tokenType: "Bearer",
      expiresAt: 1,
      scope,
      identity: result.identity,
      oidc: { issuer },
    },
    result.tokens,
    result.identity,
  );
}

async function mount(record, protectedRoute = false) {
  values.set(key, JSON.stringify(record));
  function Probe() {
    auth = useAuth();
    return null;
  }
  await Renderer.act(async () => {
    renderer = Renderer.create(
      React.createElement(
        GuardhouseProvider,
        {
          config: {
            authority: issuer,
            clientId,
            redirectUri: "https://app.test/callback",
            audiencePolicy: "oidc-optional",
            requiredAcrValues: ["mfa"],
            requiredAmrValues: ["otp"],
          },
        },
        React.createElement(
          React.Fragment,
          null,
          React.createElement(Probe),
          protectedRoute
            ? React.createElement(
                ProtectedRoute,
                null,
                React.createElement("span", null, "Private content"),
              )
            : null,
        ),
      ),
    );
  });
  for (let attempt = 0; attempt < 200 && auth.isLoading; attempt++) {
    await Renderer.act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
    });
  }
  expect(auth.isLoading).toBe(false);
}

beforeEach(() => {
  global.crypto = webcrypto;
  values = new Map();
  calls = [];
  auth = null;
  renderer = null;
  failure = null;
  userInfo = { sub: "user-1", roles: ["reader"] };
  userInfoStatus = 200;
  responseTokens = {
    access_token: "refreshed-access",
    refresh_token: "rotated-refresh",
    token_type: "Bearer",
    expires_in: 3600,
    scope,
  };
  global.sessionStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  global.window = {
    location: new URL("https://app.test/"),
    history: { replaceState() {} },
  };
  jest.spyOn(global, "fetch").mockImplementation(async (url, options = {}) => {
    calls.push({ url: String(url), ...options });
    if (failure && String(url).endsWith(failure.endpoint)) {
      if (failure.mode === "offline")
        throw new TypeError("Synthetic network outage");
      if (failure.mode === "pending") return failure.promise;
      if (failure.mode === "body") {
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.error(new TypeError("Stream interrupted"));
            },
          }),
        );
      }
      return new Response(JSON.stringify({ error: "server_error" }), {
        status: failure.mode,
      });
    }
    let body;
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      body = {
        issuer,
        jwks_uri: `${issuer}jwks`,
        id_token_signing_alg_values_supported: ["RS256"],
      };
    } else if (String(url).endsWith("/jwks")) {
      body = { keys: [jwk] };
    } else if (String(url).endsWith("/connect/token")) {
      body = responseTokens;
    } else if (String(url).endsWith("/connect/userinfo")) {
      return new Response(JSON.stringify(userInfo), { status: userInfoStatus });
    } else {
      throw new Error(`Unexpected request: ${url}`);
    }
    return new Response(JSON.stringify(body), { status: 200 });
  });
});

afterEach(async () => {
  if (renderer) await Renderer.act(async () => renderer.unmount());
  jest.restoreAllMocks();
  global.crypto = originalCrypto;
  delete global.window;
  delete global.sessionStorage;
});

it.each([
  ["expired ID token", -120, false],
  ["still-valid historical ID token", 3600, false],
  ["older v3 record without a status flag", -120, undefined],
  ["current flag whose ID token has since expired", -120, true],
])(
  "restores %s with fresh UserInfo and without another refresh",
  async (_name, expiresIn, flag) => {
    const record = await refreshedSnapshot(token({ exp: now() + expiresIn }));
    record.idTokenCurrent = flag;
    record.user = { sub: "attacker", roles: ["owner"] };
    const before = calls.filter((call) =>
      call.url.endsWith("/connect/token"),
    ).length;
    await mount(record);
    expect(auth.isAuthenticated).toBe(true);
    expect(auth.user).toEqual(userInfo);
    expect(auth.user.oldRole).toBeUndefined();
    expect(Object.isFrozen(auth.user.roles)).toBe(true);
    expect(JSON.parse(values.get(key)).refreshToken).toBe("rotated-refresh");
    expect(
      calls.filter((call) => call.url.endsWith("/connect/token")),
    ).toHaveLength(before);

    // A later refresh uses the rotated credential retained across restoration.
    values.set(key, JSON.stringify({ ...record, expiresAt: 1 }));
    responseTokens = {
      ...responseTokens,
      access_token: "next-access",
      refresh_token: "next-refresh",
    };
    await Renderer.act(async () => {
      expect(await auth.getAccessTokenSilently()).toBe("next-access");
    });
    const requests = calls.filter((call) =>
      call.url.endsWith("/connect/token"),
    );
    expect(new URLSearchParams(requests.at(-1).body).get("refresh_token")).toBe(
      "rotated-refresh",
    );
    expect(JSON.parse(values.get(key)).refreshToken).toBe("next-refresh");
  },
);

it("restores with a live access token even without a refresh token", async () => {
  const record = await refreshedSnapshot();
  delete record.refreshToken;
  await mount(record);
  expect(auth.isAuthenticated).toBe(true);
});

it("preserves ordinary current-ID-token claims for earlier v3 records", async () => {
  const raw = token({ exp: now() + 3600 });
  const verified = await client().verifyIdToken(raw, { purpose: "session" });
  const record = await refreshedSnapshot(raw);
  delete record.idTokenCurrent;
  record.identity = verified.identity;
  await mount(record);
  expect(auth.isAuthenticated).toBe(true);
  expect(auth.user.oldRole).toBe("admin");
});

it.each([
  "signature",
  "identity",
  "issuer",
  "audience",
  "assurance",
  "not-before",
  "subject",
  "revoked-access",
  "status-type",
])("rejects invalid %s during historical restoration", async (failure) => {
  const record = await refreshedSnapshot();
  if (failure === "signature") {
    const parts = record.idToken.split(".");
    parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
    record.idToken = parts.join(".");
  }
  if (failure === "identity")
    record.identity = { ...record.identity, nonce: "modified" };
  if (failure === "issuer")
    record.idToken = token({ iss: "https://another.test/" });
  if (failure === "audience") record.idToken = token({ aud: "other-client" });
  if (failure === "assurance") record.idToken = token({ amr: ["pwd"] });
  if (failure === "not-before") record.idToken = token({ nbf: now() + 3600 });
  if (failure === "subject") userInfo = { sub: "other-user", roles: ["admin"] };
  if (failure === "revoked-access") {
    userInfoStatus = 401;
    userInfo = { error: "invalid_token" };
  }
  if (failure === "status-type") record.idTokenCurrent = "false";
  await mount(record);
  expect(auth.isAuthenticated).toBe(false);
  expect(auth.user).toBeNull();
  expect(values.has(key)).toBe(false);
});

it("does not promote historical restoration into a current ID token", async () => {
  const raw = token();
  const sdk = client();
  const restored = await sdk.restoreOidcSession("refreshed-access", {
    idToken: raw,
  });
  expect(restored.userInfo).toEqual(userInfo);
  expect(restored.identity.expiresAt).toBeLessThan(now());
  expect(restored.idToken).toBeUndefined();
  expect(restored.payload).toBeUndefined();
  await expect(
    sdk.verifyIdToken(raw, { purpose: "session" }),
  ).rejects.toMatchObject({
    code: "ID_TOKEN_VALIDATION_FAILED",
  });
});

it.each(
  [false, true].flatMap((historical) =>
    ["/.well-known/openid-configuration", "/jwks", "/connect/userinfo"].flatMap(
      (endpoint) =>
        ["offline", 503, 429, "body"].map((mode) => [
          historical,
          endpoint,
          mode,
        ]),
    ),
  ),
)(
  "preserves credentials and denies tokens until retry (historical=%s, %s, %s)",
  async (historical, endpoint, mode) => {
    const record = await refreshedSnapshot(
      token({ exp: historical ? now() - 120 : now() + 3600 }),
    );
    record.idTokenCurrent = !historical;
    failure = { endpoint, mode };
    await mount(record);
    expect(auth).toMatchObject({
      isAuthenticated: false,
      user: null,
      error: expect.any(Error),
    });
    expect(values.get(key)).toBe(JSON.stringify(record));
    await Renderer.act(async () => {
      expect(await auth.getAccessToken()).toBeNull();
      expect(await auth.getAccessTokenSilently()).toBeNull();
    });
    expect(values.get(key)).toBe(JSON.stringify(record));
    failure = null;
    await Renderer.act(async () => {
      expect(await auth.getAccessTokenSilently()).toBe(record.accessToken);
    });
    expect(auth).toMatchObject({
      isAuthenticated: true,
      user: expect.objectContaining({ sub: "user-1" }),
      error: null,
    });
    expect(values.get(key)).toBe(JSON.stringify(record));
    const requestCount = calls.length;
    expect(await auth.getAccessToken()).toBe(record.accessToken);
    expect(calls).toHaveLength(requestCount);
  },
);

it("ProtectedRoute retries restoration without redirecting to login during an outage", async () => {
  const record = await refreshedSnapshot();
  const login = jest.spyOn(
    GuardhouseClient.prototype,
    "createAuthorizationRequest",
  );
  failure = { endpoint: "/connect/userinfo", mode: 503 };
  await mount(record, true);
  expect(login).not.toHaveBeenCalled();
  expect(JSON.stringify(renderer.toJSON())).not.toContain("Private content");
  expect(JSON.stringify(renderer.toJSON())).toContain(
    "Unable to restore your session",
  );
  failure = null;
  await Renderer.act(async () => {
    renderer.root.findByType("button").props.onClick();
  });
  for (let attempt = 0; attempt < 200 && !auth.isAuthenticated; attempt++) {
    await Renderer.act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
    });
  }
  expect(auth.isAuthenticated).toBe(true);
  expect(login).not.toHaveBeenCalled();
  expect(JSON.stringify(renderer.toJSON())).toContain("Private content");
});

it("does not resurrect a session when logout wins over pending retry", async () => {
  const record = await refreshedSnapshot();
  failure = { endpoint: "/connect/userinfo", mode: "offline" };
  await mount(record);
  let release;
  failure = {
    endpoint: "/connect/userinfo",
    mode: "pending",
    promise: new Promise((resolve) => {
      release = resolve;
    }),
  };
  let retry;
  await Renderer.act(async () => {
    retry = auth.getAccessTokenSilently();
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  jest
    .spyOn(GuardhouseClient.prototype, "buildLogoutUrl")
    .mockResolvedValue("https://historical.test/logout");
  await Renderer.act(async () => {
    await auth.logout();
  });
  await Renderer.act(async () => {
    release(new Response(JSON.stringify(userInfo)));
    expect(await retry).toBeNull();
  });
  expect(values.has(key)).toBe(false);
  expect(auth.isAuthenticated).toBe(false);
});

it("retains a newer record when an older restoration fails temporarily", async () => {
  const record = await refreshedSnapshot();
  failure = { endpoint: "/connect/userinfo", mode: "offline" };
  await mount(record);
  let reject;
  failure = {
    endpoint: "/connect/userinfo",
    mode: "pending",
    promise: new Promise((_resolve, rejectPromise) => {
      reject = rejectPromise;
    }),
  };
  let retry;
  await Renderer.act(async () => {
    retry = auth.getAccessTokenSilently();
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
  const newer = {
    ...record,
    accessToken: "newer-access",
    refreshToken: "newer-refresh",
  };
  values.set(key, JSON.stringify(newer));
  await Renderer.act(async () => {
    reject(new TypeError("Synthetic outage"));
    expect(await retry).toBeNull();
  });
  expect(values.get(key)).toBe(JSON.stringify(newer));
  failure = null;
  await Renderer.act(async () => {
    expect(await auth.getAccessToken()).toBe("newer-access");
  });
  expect(auth.isAuthenticated).toBe(true);
});
