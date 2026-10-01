// Real bundled Core/jose, with only native UI, storage and HTTP replaced.
jest.mock("@guardhouse/core", () =>
  jest.requireActual("../../../core/dist/index.js"),
);

const {
  generateKeyPairSync,
  sign,
  randomBytes,
  createHash,
  webcrypto,
} = require("node:crypto");
const { GuardhouseClient } = require("../core/GuardhouseClient");
const { generatePKCE, setCryptoAdapter } = require("@guardhouse/core");

const authority = "https://native-crypto.test/";
const clientId = "mobile-client";
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const otherPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = {
  ...pair.publicKey.export({ format: "jwk" }),
  kid: "key",
  alg: "RS256",
};
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
const originalFetch = globalThis.fetch;
const cryptoAdapter = {
  name: "PKCE-only test adapter",
  randomBytes: async (length) => new Uint8Array(randomBytes(length)),
  sha256: async (data) =>
    new Uint8Array(createHash("sha256").update(data).digest()),
};
let nonce, wrongSignature, omitIdToken, storage, browser;

function setCrypto(value) {
  Object.defineProperty(globalThis, "crypto", { configurable: true, value });
}
function token() {
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
      ...(nonce ? { nonce } : {}),
    }),
  ).toString("base64url");
  const input = `${header}.${payload}`;
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), wrongSignature ? otherPair.privateKey : pair.privateKey).toString("base64url")}`;
}
function client(overrides = {}) {
  return new GuardhouseClient({
    authority,
    clientId,
    redirectUri: "crypto-test://callback",
    scope: "openid profile offline_access",
    cryptoAdapter,
    sessionStorage: storage,
    refreshTokenStorage: storage,
    browser,
    ...overrides,
  });
}
beforeEach(() => {
  setCrypto(webcrypto);
  nonce = undefined;
  wrongSignature = false;
  omitIdToken = false;
  const values = new Map();
  storage = {
    values,
    getItem: jest.fn(async (key) => values.get(key) ?? null),
    setItem: jest.fn(async (key, value) => {
      values.set(key, value);
    }),
    removeItem: jest.fn(async (key) => {
      values.delete(key);
    }),
  };
  browser = {
    openAuthSession: jest.fn(async (url, redirectUri) => {
      const params = new URL(url).searchParams;
      nonce = params.get("nonce");
      return {
        url: `${redirectUri}?${new URLSearchParams({ code: "code", state: params.get("state"), iss: authority })}`,
      };
    }),
  };
  globalThis.fetch = jest.fn(async (url, options = {}) => {
    let body;
    if (String(url).endsWith("/.well-known/openid-configuration")) {
      body = {
        issuer: authority,
        jwks_uri: authority + "jwks",
        authorization_endpoint: authority + "connect/authorize",
        id_token_signing_alg_values_supported: ["RS256"],
        authorization_response_iss_parameter_supported: true,
      };
    } else if (String(url).endsWith("/jwks")) body = { keys: [jwk] };
    else if (String(url).endsWith("/connect/userinfo"))
      body = { sub: "user-1" };
    else if (String(url).endsWith("/connect/token")) {
      if (
        new URLSearchParams(options.body).get("grant_type") === "refresh_token"
      )
        nonce = undefined;
      body = {
        access_token: "access",
        refresh_token: "rotated-refresh",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile offline_access",
        ...(!omitIdToken ? { id_token: token() } : {}),
      };
    } else throw new Error("Unexpected request: " + url);
    return new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    });
  });
});
afterEach(() => {
  if (originalCrypto)
    Object.defineProperty(globalThis, "crypto", originalCrypto);
  else delete globalThis.crypto;
  globalThis.fetch = originalFetch;
});

it.each(["absent", "digest-only", "no-import", "no-verify", "no-digest"])(
  "rejects an incomplete OIDC runtime before network or storage access (%s)",
  async (mode) => {
    const subtle = {
      digest: webcrypto.subtle.digest.bind(webcrypto.subtle),
      importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
      verify: webcrypto.subtle.verify.bind(webcrypto.subtle),
    };
    if (mode === "digest-only" || mode === "no-import") delete subtle.importKey;
    if (mode === "digest-only" || mode === "no-verify") delete subtle.verify;
    if (mode === "no-digest") delete subtle.digest;
    setCrypto(mode === "absent" ? undefined : { subtle });
    setCryptoAdapter(cryptoAdapter);
    await expect(generatePKCE()).resolves.toHaveProperty("codeChallenge");
    expect(() => client()).toThrow(
      expect.objectContaining({ code: "CONFIG_ERROR" }),
    );
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(storage.getItem).not.toHaveBeenCalled();
  },
);

it("keeps OAuth-only PKCE usable without Web Crypto", async () => {
  setCrypto(undefined);
  expect(() => client({ scope: "api.read" })).not.toThrow();
  await expect(generatePKCE()).resolves.toHaveProperty("codeChallenge");
});

it.each(["loginWithBrowser", "registerWithBrowser", "loginWithPasskey"])(
  "checks an OIDC scope override before interaction in %s",
  async (method) => {
    const passkey = { get: jest.fn() };
    const sdk = client({ scope: "api.read", passkey });
    setCrypto(undefined);
    await expect(sdk[method]({ scope: "openid" })).rejects.toMatchObject({
      code: "CONFIG_ERROR",
    });
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(browser.openAuthSession).not.toHaveBeenCalled();
    expect(passkey.get).not.toHaveBeenCalled();
  },
);

it("verifies signatures through login, refresh and cold restoration with Web Crypto installed", async () => {
  const sdk = client();
  expect((await sdk.loginWithBrowser()).user.sub).toBe("user-1");
  expect((await sdk.refreshToken()).session.idToken).toBeDefined();
  expect((await client().restoreSession()).user.sub).toBe("user-1");
  omitIdToken = true;
  expect((await sdk.refreshToken()).session.idToken).toBeUndefined();
  expect((await client().restoreSession()).user.sub).toBe("user-1");
});

it("uses an installed Web Crypto provider without a custom PKCE adapter", async () => {
  const sdk = client({ cryptoAdapter: undefined });
  expect((await sdk.loginWithBrowser()).user.sub).toBe("user-1");
});

it("rejects a bad signature without persisting an authenticated session", async () => {
  wrongSignature = true;
  await expect(client().loginWithBrowser()).rejects.toMatchObject({
    details: { code: "ID_TOKEN_VALIDATION_FAILED" },
  });
  expect(storage.values.size).toBe(0);
});

it.each(["restoreSession", "getSession", "getAccessToken", "refreshToken"])(
  "preserves stored credentials when crypto is unavailable during %s and allows retry",
  async (method) => {
    await client().loginWithBrowser();
    const cold = client();
    const snapshot = [...storage.values.entries()];
    globalThis.fetch.mockClear();
    setCrypto(undefined);
    await expect(cold[method]()).rejects.toMatchObject({
      code: "CONFIG_ERROR",
    });
    expect([...storage.values.entries()]).toEqual(snapshot);
    expect(globalThis.fetch).not.toHaveBeenCalled();
    setCrypto(webcrypto);
    expect(await cold[method]()).not.toBeNull();
  },
);
