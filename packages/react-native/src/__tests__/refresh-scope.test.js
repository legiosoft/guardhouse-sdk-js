// Exercise Native request construction/storage through the real Core and jose.
jest.mock("@guardhouse/core", () =>
  jest.requireActual("../../../core/dist/index.js"),
);

const { generateKeyPairSync, sign, webcrypto } = require("node:crypto");
const { GuardhouseClient } = require("@guardhouse/core");
const { AuthManager } = require("../core/AuthManager");

const authority = "https://refresh-scope.test/";
const clientId = "mobile-client";
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = {
  ...pair.publicKey.export({ format: "jwk" }),
  kid: "key",
  alg: "RS256",
};
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
const originalFetch = globalThis.fetch;
const modes = ["oauth", "oidc-current", "oidc-historical"];

function idToken() {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", kid: "key" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iss: authority,
      aud: clientId,
      sub: "user-1",
      iat: now,
      exp: now + 3600,
    }),
  ).toString("base64url");
  const input = `${header}.${payload}`;
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), pair.privateKey).toString("base64url")}`;
}

async function setup(mode, config = {}) {
  const oidc = mode !== "oauth";
  const granted = oidc ? "openid offline_access read write" : "read write";
  const narrowed = oidc ? "openid offline_access read" : "read";
  const values = new Map();
  const storage = {
    getItem: async (key) => values.get(key) ?? null,
    setItem: async (key, value) => {
      values.set(key, value);
    },
    removeItem: async (key) => {
      values.delete(key);
    },
  };
  const server = {
    omitScope: false,
    responseScope: undefined,
    gate: undefined,
  };
  const requests = [];
  globalThis.fetch = jest.fn(async (url, options = {}) => {
    let body;
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      body = {
        issuer: authority,
        jwks_uri: authority + "jwks",
        id_token_signing_alg_values_supported: ["RS256"],
      };
    } else if (String(url).endsWith("/jwks")) body = { keys: [jwk] };
    else if (String(url).endsWith("/connect/userinfo"))
      body = { sub: "user-1" };
    else if (String(url).endsWith("/connect/token")) {
      const params = new URLSearchParams(options.body);
      requests.push(params);
      if (server.gate) await server.gate;
      body = {
        access_token: `access-${requests.length}`,
        refresh_token: `refresh-${requests.length}`,
        token_type: "Bearer",
        expires_in: 3600,
        // Without an explicit request, the server uses the original grant.
        ...(!server.omitScope
          ? { scope: server.responseScope ?? params.get("scope") ?? granted }
          : {}),
        ...(mode === "oidc-current" ? { id_token: idToken() } : {}),
      };
    } else throw new Error("Unexpected request: " + url);
    return new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    });
  });
  const createManager = () =>
    new AuthManager({
      authority,
      clientId,
      redirectUri: "scope-test://callback",
      // The actual grant, not a broader config default, must bound refreshes.
      defaultScope: granted + " admin",
      defaultAudience: "urn:default-api",
      defaultEphemeralSession: true,
      userInfoOnLogin: true,
      registrationEndpoint: authority + "account/signup",
      requiredAcrValues: [],
      requiredAmrValues: [],
      coreClient: new GuardhouseClient({ authority, clientId, ...config }),
      refreshTokenStorage: storage,
      sessionStorage: storage,
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    });
  const manager = createManager();
  await manager.persistTokenResponse(
    {
      access_token: "initial-access",
      refresh_token: "initial-refresh",
      token_type: "Bearer",
      expires_in: 3600,
      scope: granted,
      ...(oidc ? { id_token: idToken() } : {}),
    },
    granted,
  );
  globalThis.fetch.mockClear();
  return {
    manager,
    createManager,
    values,
    server,
    requests,
    granted,
    narrowed,
  };
}

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
  globalThis.fetch = originalFetch;
});

describe.each(modes)("Native refresh scope (%s)", (mode) => {
  it.each([false, true])(
    "narrows over HTTP, persists and keeps that scope on cold/automatic refresh (omitted response scope: %s)",
    async (omitScope) => {
      const { manager, createManager, server, requests, narrowed } =
        await setup(mode);
      server.omitScope = omitScope;
      const audience = omitScope ? undefined : "urn:other-api";
      const result = await manager.refreshToken({
        scope: `  ${narrowed.split(" ").join("\t  ")}  `,
        audience,
      });
      expect(requests[0].get("scope")).toBe(narrowed);
      expect(requests[0].get("audience")).toBe(audience ?? "urn:default-api");
      expect(requests[0].get("refresh_token")).toBe("initial-refresh");
      expect(result.session.scope).toBe(narrowed);
      if (mode === "oidc-historical")
        expect(result.session.idToken).toBeUndefined();
      const cold = createManager();
      expect((await cold.restoreSession()).session.scope).toBe(narrowed);
      expect((await cold.refreshToken()).session.scope).toBe(narrowed);
      expect(requests[1].get("scope")).toBe(narrowed);
      expect(requests[1].get("refresh_token")).toBe("refresh-1");
      expect(await cold.getAccessToken({ minValiditySeconds: 7200 })).toBe(
        "access-3",
      );
      expect(requests[2].get("scope")).toBe(narrowed);
      expect(requests[2].get("refresh_token")).toBe("refresh-2");
    },
  );

  it.each([undefined, "", " \t "])(
    "uses the saved grant for an omitted/blank override (%s)",
    async (scope) => {
      const { manager, requests, granted } = await setup(mode);
      expect((await manager.refreshToken({ scope })).session.scope).toBe(
        granted,
      );
      expect(requests[0].get("scope")).toBe(granted);
    },
  );

  it("rejects requested escalation before HTTP and preserves the session", async () => {
    const { manager, values, granted } = await setup(mode);
    const snapshot = [...values];
    await expect(
      manager.refreshToken({ scope: granted + " admin" }),
    ).rejects.toMatchObject({ code: "TOKEN_RESPONSE_ERROR" });
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect([...values]).toEqual(snapshot);
  });

  it("rejects a server response broader than requested without persisting it", async () => {
    const { manager, server, values, granted, narrowed } = await setup(mode);
    server.responseScope = granted;
    const snapshot = [...values];
    await expect(
      manager.refreshToken({ scope: narrowed }),
    ).rejects.toMatchObject({ details: { code: "SCOPE_ESCALATION_DETECTED" } });
    expect([...values]).toEqual(snapshot);
  });
});

it.each([false, true])(
  "preserves allowScopeNarrowing for server-selected narrower scopes (%s)",
  async (allowScopeNarrowing) => {
    const { manager, server, createManager, requests } = await setup("oauth", {
      allowScopeNarrowing,
    });
    server.responseScope = "read";
    const result = manager.refreshToken({ scope: "read write" });
    if (!allowScopeNarrowing) {
      await expect(result).rejects.toMatchObject({
        details: { code: "SCOPE_NARROWING_DETECTED" },
      });
    } else {
      expect((await result).session.scope).toBe("read");
      server.responseScope = undefined;
      expect((await createManager().refreshToken()).session.scope).toBe("read");
      expect(requests[1].get("scope")).toBe("read");
    }
  },
);

it.each([{ scope: "read" }, { audience: "urn:different-api" }])(
  "does not join a refresh with a different request context (%j)",
  async (override) => {
    const { manager, server, requests, granted } = await setup("oauth");
    let release;
    server.gate = new Promise((resolve) => {
      release = resolve;
    });
    const first = manager.refreshToken({ scope: granted });
    const conflict = manager.refreshToken({ scope: granted, ...override });
    release();
    await expect(conflict).rejects.toMatchObject({
      code: "REFRESH_OPERATION_CONFLICT",
    });
    expect((await first).session.scope).toBe(granted);
    expect(requests).toHaveLength(1);
    expect((await manager.refreshToken({ scope: "read" })).session.scope).toBe(
      "read",
    );
  },
);

it("joins identical scope sets and audiences without rotating twice", async () => {
  const { manager, server, requests } = await setup("oauth");
  let release;
  server.gate = new Promise((resolve) => {
    release = resolve;
  });
  const first = manager.refreshToken({
    scope: "read write",
    audience: "urn:default-api",
  });
  const second = manager.refreshToken({ scope: " write\tread read " });
  release();
  const results = await Promise.all([first, second]);
  expect(results[0]).toBe(results[1]);
  expect(requests).toHaveLength(1);
});
