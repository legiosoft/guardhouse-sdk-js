import {
  JtiReplayCache,
  OidcIdTokenVerifier,
  type IdTokenValidationContext,
  type OidcIdentityEvidence,
} from "../token";
import { verifyHistoricalIdTokenIdentity } from "../token/id-token-verifier";
import { GuardhouseClient } from "../client";
import { isTransientAuthError } from "../config";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
describe("session restoration availability failures", () => {
  let fixture: SigningFixture;
  const authority = "https://auth.example.com/";
  let outage: { endpoint: string; mode: string | number } | null;
  beforeAll(async () => {
    fixture = await createSigningFixture("restore-key");
  });
  beforeEach(() => {
    outage = null;
    jest.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (outage && url.endsWith(outage.endpoint)) {
        if (outage.mode === "offline")
          throw new TypeError("Network unavailable");
        if (outage.mode === "malformed") return new Response("{");
        return new Response("unavailable", { status: Number(outage.mode) });
      }
      if (url.endsWith("/.well-known/openid-configuration"))
        return jsonResponse({
          issuer: authority,
          jwks_uri: authority + "jwks",
          id_token_signing_alg_values_supported: ["RS256"],
        });
      if (url.endsWith("/jwks"))
        return jsonResponse({ keys: [fixture.publicJwk] });
      throw new Error("Unexpected test request");
    });
  });
  afterEach(() => jest.restoreAllMocks());

  async function persistedClient(warm: boolean) {
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
    const client = new GuardhouseClient({
      authority,
      clientId: "client-id",
      storage,
      discoveryCacheTtlMs: 0,
    });
    const raw = await signIdToken(fixture, { iss: authority });
    const verified = await client.verifyIdToken(raw, SESSION_CONTEXT);
    const serialized = JSON.stringify({
      version: 3,
      kind: "oidc",
      issuer: authority,
      clientId: "client-id",
      accessToken: "access",
      tokenType: "Bearer",
      expiresAt: Date.now() + 3_600_000,
      hasRefreshToken: true,
      idToken: raw,
      identity: verified.identity,
    });
    const key =
      "guardhouse:session:v3:" + encodeURIComponent(authority) + ":client-id";
    values.set(key, serialized);
    if (warm) expect(await client.getSessionState()).not.toBeNull();
    return { client, values, key, serialized };
  }

  it.each(
    [false, true].flatMap((warm) =>
      ["/.well-known/openid-configuration", "/jwks"].flatMap((endpoint) =>
        ["offline", 503].map((mode) => [warm, endpoint, mode] as const),
      ),
    ),
  )(
    "preserves Core storage across failure and retry (warm=%s, %s, %s)",
    async (warm, endpoint, mode) => {
      const { client, values, key, serialized } = await persistedClient(warm);
      outage = { endpoint, mode };
      await expect(client.getSessionState()).rejects.toMatchObject({
        code: "OIDC_METADATA_REQUEST_FAILED",
      });
      expect(values.get(key)).toBe(serialized);
      outage = null;
      await expect(client.getSessionState()).resolves.toMatchObject({
        accessToken: "access",
        hasRefreshToken: true,
      });
      expect(values.get(key)).toBe(serialized);
    },
  );

  it.each([
    ["/.well-known/openid-configuration", "malformed"],
    ["/jwks", "malformed"],
    ["/jwks", 404],
  ] as const)(
    "still clears invalid metadata (%s, %s)",
    async (endpoint, mode) => {
      const { client, values } = await persistedClient(false);
      outage = { endpoint, mode };
      await expect(client.getSessionState()).resolves.toBeNull();
      expect(values.size).toBe(0);
    },
  );

  it("preserves a newer stored record when an older check loses the network", async () => {
    const { client, values, key, serialized } = await persistedClient(false);
    const newer = JSON.stringify({
      ...JSON.parse(serialized),
      accessToken: "newer-access",
    });
    jest.spyOn(client, "verifyIdToken").mockImplementationOnce(async () => {
      values.set(key, newer);
      const { GuardhouseError } = await import("../config");
      throw new GuardhouseError("Offline", "NETWORK_ERROR");
    });
    await expect(client.getSessionState()).rejects.toMatchObject({
      code: "NETWORK_ERROR",
    });
    expect(values.get(key)).toBe(newer);
    await expect(client.getSessionState()).resolves.toMatchObject({
      accessToken: "newer-access",
    });
  });

  it("can retry a key rotation immediately after forced JWKS reload is unavailable", async () => {
    const rotated = await createSigningFixture("restore-key");
    let keys = [fixture.publicJwk];
    let unavailable = false;
    const fetcher = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      if (String(input).endsWith("/.well-known/openid-configuration"))
        return jsonResponse({
          issuer: "https://auth.example.com",
          jwks_uri: authority + "jwks",
          id_token_signing_alg_values_supported: ["RS256"],
        });
      if (unavailable) return new Response("unavailable", { status: 503 });
      return jsonResponse({ keys });
    });
    const verifier = createVerifier(fetcher);
    await verifier.verify(await signIdToken(fixture), SESSION_CONTEXT);
    const token = await signIdToken(rotated);
    unavailable = true;
    await expect(verifier.verify(token, SESSION_CONTEXT)).rejects.toMatchObject(
      {
        code: "OIDC_METADATA_REQUEST_FAILED",
        statusCode: 503,
      },
    );
    unavailable = false;
    keys = [rotated.publicJwk];
    await expect(
      verifier.verify(token, SESSION_CONTEXT),
    ).resolves.toMatchObject({ identity: { subject: "user-1" } });
  });

  it("classifies a JWKS deadline as availability failure, including a stalled body", async () => {
    const fetcher = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      if (String(input).endsWith("/.well-known/openid-configuration"))
        return jsonResponse({
          issuer: "https://auth.example.com",
          jwks_uri: authority + "jwks",
          id_token_signing_alg_values_supported: ["RS256"],
        });
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("{"));
          },
        }),
      );
    });
    const verifier = createVerifier(fetcher, { metadataRequestTimeoutMs: 5 });
    let failure: unknown;
    try {
      await verifier.verify(await signIdToken(fixture), SESSION_CONTEXT);
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      code: "OIDC_METADATA_REQUEST_FAILED",
      retryable: true,
    });
    expect(isTransientAuthError(failure)).toBe(true);
  });
});

interface SigningFixture {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: Record<string, unknown>;
}

const SESSION_CONTEXT = { purpose: "session" } as const;
const REFRESH_CLAIM_CASES = [
  ["both omitted", false, false],
  ["nonce omitted", false, true],
  ["auth_time omitted", true, false],
  ["both repeated", true, true],
] as const;

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

async function createSigningFixture(kid: string): Promise<SigningFixture> {
  const pair = (await globalThis.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
  };
  const publicJwk = (await globalThis.crypto.subtle.exportKey(
    "jwk",
    pair.publicKey,
  )) as unknown as Record<string, unknown>;
  publicJwk["kid"] = kid;
  publicJwk["alg"] = "RS256";
  publicJwk["use"] = "sig";
  publicJwk["key_ops"] = ["verify"];
  return { kid, privateKey: pair.privateKey, publicJwk };
}

async function signIdToken(
  fixture: SigningFixture,
  overrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: fixture.kid,
    ...headerOverrides,
  };
  const payload = {
    iss: "https://auth.example.com",
    aud: "client-id",
    sub: "user-1",
    iat: now,
    exp: now + 3600,
    ...overrides,
  };
  const input = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = await globalThis.crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    fixture.privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${Buffer.from(signature).toString("base64url")}`;
}

function createMetadataFetch(
  jwks: Record<string, unknown>[][],
  advertisedAlgorithms: string[] = ["RS256"],
): jest.MockedFunction<typeof fetch> {
  let jwksIndex = 0;
  return jest.fn(async (input: Parameters<typeof fetch>[0]) => {
    const url = String(input);
    if (url.endsWith("/.well-known/openid-configuration")) {
      return jsonResponse({
        issuer: "https://auth.example.com",
        jwks_uri: "https://auth.example.com/.well-known/jwks",
        id_token_signing_alg_values_supported: advertisedAlgorithms,
      });
    }
    const keys = jwks[Math.min(jwksIndex, jwks.length - 1)] ?? [];
    jwksIndex += 1;
    return jsonResponse({ keys });
  });
}

function createVerifier(
  fetcher: jest.MockedFunction<typeof fetch>,
  options: {
    metadataRequestTimeoutMs?: number;
    clockSkewToleranceSeconds?: number;
  } = {},
): OidcIdTokenVerifier {
  return new OidcIdTokenVerifier({
    authority: "https://auth.example.com",
    clientId: "client-id",
    fetcher,
    ...options,
  });
}

describe("OidcIdTokenVerifier", () => {
  afterEach(() => jest.restoreAllMocks());

  it("verifies a valid RS256 token and required identity claims", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const token = await signIdToken(fixture, {
      nonce: "nonce-1",
      auth_time: now,
      jti: "login-1",
    });
    const signingJwk = { ...fixture.publicJwk };
    delete signingJwk["alg"];
    delete signingJwk["use"];
    delete signingJwk["key_ops"];
    const fetcher = createMetadataFetch([[signingJwk]]);

    const result = await createVerifier(fetcher).verify(token, {
      purpose: "authorization_code",
      nonce: "nonce-1",
      maxAgeSeconds: 300,
      replayCache: new JtiReplayCache(),
    });

    expect(result.payload.sub).toBe("user-1");
    expect(result.identity).toEqual({
      issuer: "https://auth.example.com",
      clientId: "client-id",
      subject: "user-1",
      audiences: ["client-id"],
      authorizedParty: null,
      issuedAt: expect.any(Number),
      expiresAt: expect.any(Number),
      nonce: "nonce-1",
      authTime: now,
      acr: null,
      amr: [],
      sessionId: null,
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.payload)).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("snapshots purpose and assurance arrays before asynchronous verification", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, { nonce: "request-nonce" });
    let releaseDiscovery!: (response: Response) => void;
    const deferredDiscovery = new Promise<Response>((resolve) => {
      releaseDiscovery = resolve;
    });
    const fetcher = jest.fn((input: Parameters<typeof fetch>[0]) => {
      if (String(input).endsWith("/.well-known/openid-configuration")) {
        return deferredDiscovery;
      }
      return Promise.resolve(jsonResponse({ keys: [fixture.publicJwk] }));
    }) as jest.MockedFunction<typeof fetch>;
    const requiredAmrValues = ["passkey"];
    const context: {
      purpose: "authorization_code" | "session";
      nonce: string;
      requiredAmrValues: string[];
    } = {
      purpose: "authorization_code",
      nonce: "request-nonce",
      requiredAmrValues,
    };

    const verification = createVerifier(fetcher).verify(
      token,
      context as IdTokenValidationContext,
    );
    context.purpose = "session";
    context.nonce = "attacker-changed-nonce";
    requiredAmrValues.length = 0;
    releaseDiscovery(
      jsonResponse({
        issuer: "https://auth.example.com",
        jwks_uri: "https://auth.example.com/.well-known/jwks",
        id_token_signing_alg_values_supported: ["RS256"],
      }),
    );

    await expect(verification).rejects.toThrow(
      "amr does not contain every required authentication method",
    );
  });

  it("awaits asynchronous replay caches and requires an exact true result", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      nonce: "request-nonce",
      jti: "login-1",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const asynchronousCache = {
      consume: jest.fn(async () => true),
    };

    await expect(
      verifier.verify(token, {
        purpose: "authorization_code",
        nonce: "request-nonce",
        replayCache: asynchronousCache,
      }),
    ).resolves.toBeDefined();
    expect(asynchronousCache.consume).toHaveBeenCalledTimes(1);

    const malformedCache = {
      consume: jest.fn(
        () => Promise.resolve("true") as unknown as Promise<boolean>,
      ),
    };
    await expect(
      verifier.verify(token, {
        purpose: "authorization_code",
        nonce: "request-nonce",
        replayCache: malformedCache,
      }),
    ).rejects.toThrow("replay was detected or cache is full");
  });

  it("fails closed when an asynchronous replay cache rejects", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      nonce: "request-nonce",
      jti: "login-1",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher).verify(token, {
        purpose: "authorization_code",
        nonce: "request-nonce",
        replayCache: {
          consume: async () => {
            throw new Error("cache unavailable");
          },
        },
      }),
    ).rejects.toThrow("replay protection failed");
  });

  it("rechecks expiration after an asynchronous replay-cache operation", async () => {
    const fixture = await createSigningFixture("key-1");
    const nowSeconds = 2_000_000_000;
    const nowSpy = jest.spyOn(Date, "now").mockReturnValue(nowSeconds * 1000);
    const token = await signIdToken(fixture, {
      iat: nowSeconds - 10,
      exp: nowSeconds + 1,
      nonce: "request-nonce",
      jti: "one-use-id-token",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher, { clockSkewToleranceSeconds: 0 }).verify(token, {
        purpose: "authorization_code",
        nonce: "request-nonce",
        replayCache: {
          consume: async () => {
            nowSpy.mockReturnValue((nowSeconds + 1) * 1000);
            await Promise.resolve();
            return true;
          },
        },
      }),
    ).rejects.toThrow("expired token");
  });

  it("rechecks max_age after an asynchronous replay-cache operation", async () => {
    const fixture = await createSigningFixture("key-1");
    const nowSeconds = 2_000_000_000;
    const nowSpy = jest.spyOn(Date, "now").mockReturnValue(nowSeconds * 1000);
    const token = await signIdToken(fixture, {
      iat: nowSeconds - 10,
      exp: nowSeconds + 3600,
      auth_time: nowSeconds - 60,
      nonce: "request-nonce",
      jti: "max-age-id-token",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher, { clockSkewToleranceSeconds: 0 }).verify(token, {
        purpose: "authorization_code",
        nonce: "request-nonce",
        maxAgeSeconds: 60,
        replayCache: {
          consume: async () => {
            nowSpy.mockReturnValue((nowSeconds + 1) * 1000);
            await Promise.resolve();
            return true;
          },
        },
      }),
    ).rejects.toThrow("auth_time exceeds maxAgeSeconds");
  });

  it("deeply copies and freezes every exposed verified claim", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      roles: ["reader"],
      scopes: ["openid"],
      profile: "https://example.com/users/user-1",
      custom_claim: { nested: ["value"] },
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verified = await createVerifier(fetcher).verify(
      token,
      SESSION_CONTEXT,
    );
    const custom = verified.payload["custom_claim"] as {
      nested: readonly string[];
    };

    expect(Object.isFrozen(verified.payload.roles)).toBe(true);
    expect(Object.isFrozen(verified.payload.scopes)).toBe(true);
    expect(verified.payload.profile).toBe("https://example.com/users/user-1");
    expect(Object.isFrozen(custom)).toBe(true);
    expect(Object.isFrozen(custom.nested)).toBe(true);
    expect(() =>
      (verified.payload.roles as unknown as string[]).push("admin"),
    ).toThrow();
    expect(verified.payload.roles).toEqual(["reader"]);
  });

  it.each([
    ["roles", { roles: "admin" }],
    ["scopes", { scopes: ["openid", 1] }],
    ["profile", { profile: {} }],
    ["cnf.jkt", { cnf: { jkt: 42 } }],
    ["name", { name: 42 }],
    ["nbf", { nbf: "tomorrow" }],
  ])("rejects a malformed concretely typed %s claim", async (_name, claim) => {
    const fixture = await createSigningFixture("key-1");
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher).verify(
        await signIdToken(fixture, claim),
        SESSION_CONTEXT,
      ),
    ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
  });

  it("caps clock skew and rejects tokens expired far beyond that cap", async () => {
    const fixture = await createSigningFixture("key-1");
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    expect(() =>
      createVerifier(fetcher, { clockSkewToleranceSeconds: 301 }),
    ).toThrow("clockSkewToleranceSeconds must be between 0 and 300");

    const now = Math.floor(Date.now() / 1000);
    const expired = await signIdToken(fixture, {
      iat: now - 7200,
      exp: now - 3600,
    });
    await expect(
      createVerifier(fetcher, { clockSkewToleranceSeconds: 300 }).verify(
        expired,
        SESSION_CONTEXT,
      ),
    ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
  });

  it("preserves an explicitly configured trailing-slash issuer", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      iss: "https://auth.example.com/",
    });
    const fetcher = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return jsonResponse({
          issuer: "https://auth.example.com/",
          jwks_uri: "https://auth.example.com/.well-known/jwks",
          id_token_signing_alg_values_supported: ["RS256"],
        });
      }
      return jsonResponse({ keys: [fixture.publicJwk] });
    });
    const verifier = new OidcIdTokenVerifier({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      fetcher,
    });

    await expect(
      verifier.verify(token, SESSION_CONTEXT),
    ).resolves.toMatchObject({
      payload: { iss: "https://auth.example.com/", sub: "user-1" },
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("supports path-based OIDC issuers", async () => {
    const fixture = await createSigningFixture("tenant-key");
    const issuer = "https://auth.example.com/tenant-a";
    const token = await signIdToken(fixture, { iss: issuer });
    const fetcher = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      if (url === `${issuer}/.well-known/openid-configuration`) {
        return jsonResponse({
          issuer,
          jwks_uri: `${issuer}/jwks`,
          id_token_signing_alg_values_supported: ["RS256"],
        });
      }
      return jsonResponse({ keys: [fixture.publicJwk] });
    }) as jest.MockedFunction<typeof fetch>;
    const verifier = new OidcIdTokenVerifier({
      authority: issuer,
      clientId: "client-id",
      fetcher,
    });

    await expect(
      verifier.verify(token, SESSION_CONTEXT),
    ).resolves.toMatchObject({
      payload: { iss: issuer, sub: "user-1" },
    });
    expect(fetcher.mock.calls.map(([input]) => String(input))).toEqual([
      `${issuer}/.well-known/openid-configuration`,
      `${issuer}/jwks`,
    ]);
  });

  it("uses the global receiver for browser-native fetch implementations", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const fetcher = jest.fn(function (
      this: unknown,
      input: Parameters<typeof fetch>[0],
    ) {
      if (this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }

      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        return Promise.resolve(
          jsonResponse({
            issuer: "https://auth.example.com",
            jwks_uri: "https://auth.example.com/.well-known/jwks",
            id_token_signing_alg_values_supported: ["RS256"],
          }),
        );
      }

      return Promise.resolve(jsonResponse({ keys: [fixture.publicJwk] }));
    }) as jest.MockedFunction<typeof fetch>;

    await expect(
      createVerifier(fetcher).verify(token, SESSION_CONTEXT),
    ).resolves.toMatchObject({
      payload: { sub: "user-1" },
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("rejects tampering without refreshing a cold JWKS", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const parts = token.split(".");
    const tamperedPayload = encodeJson({
      iss: "https://auth.example.com",
      aud: "client-id",
      sub: "attacker",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher).verify(tampered, SESSION_CONTEXT),
    ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("rejects algorithms outside the closed asymmetric set before fetching", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {}, { alg: "HS256" });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher).verify(token, SESSION_CONTEXT),
    ).rejects.toMatchObject({
      code: "ID_TOKEN_VALIDATION_FAILED",
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each(["at+jwt", "application/at+jwt", "jwt", "text/JWT"])(
    "rejects explicit non-ID-token typ %s before fetching",
    async (typ) => {
      const fixture = await createSigningFixture("key-1");
      const token = await signIdToken(fixture, {}, { typ });
      const fetcher = createMetadataFetch([[fixture.publicJwk]]);

      await expect(
        createVerifier(fetcher).verify(token, SESSION_CONTEXT),
      ).rejects.toThrow("typ must be absent, JWT, or application/JWT");
      expect(fetcher).not.toHaveBeenCalled();
    },
  );

  it.each([undefined, "JWT", "application/JWT"])(
    "accepts an absent or ID-token typ %s",
    async (typ) => {
      const fixture = await createSigningFixture("key-1");
      const token = await signIdToken(fixture, {}, { typ });
      const fetcher = createMetadataFetch([[fixture.publicJwk]]);

      await expect(
        createVerifier(fetcher).verify(token, SESSION_CONTEXT),
      ).resolves.toMatchObject({ identity: { subject: "user-1" } });
    },
  );

  it("uses exact ACR and AMR requirements without heuristic equivalence", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      acr: "urn:guardhouse:loa:phishing-resistant",
      amr: ["hwk", "mfa"],
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);

    await expect(
      verifier.verify(token, {
        purpose: "session",
        requiredAcrValues: ["urn:guardhouse:loa:phishing-resistant"],
        requiredAmrValues: ["hwk", "mfa"],
      }),
    ).resolves.toMatchObject({ identity: { amr: ["hwk", "mfa"] } });
    await expect(
      verifier.verify(token, {
        purpose: "session",
        requiredAmrValues: ["webauthn"],
      }),
    ).rejects.toThrow("amr does not contain every required");
  });

  it("enforces exact subject and auth_time continuity during refresh", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const original = await signIdToken(fixture, { auth_time: now });
    const changed = await signIdToken(fixture, { auth_time: now - 1 });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const previous = await verifier.verify(original, SESSION_CONTEXT);

    await expect(
      verifier.verify(await signIdToken(fixture), {
        purpose: "refresh",
        previousIdentity: previous.identity,
      }),
    ).resolves.toMatchObject({ identity: { authTime: null } });

    await expect(
      verifier.verify(changed, {
        purpose: "refresh",
        previousIdentity: previous.identity,
      }),
    ).rejects.toThrow("refresh identity continuity check failed");
  });

  it("leaves an omitted refresh nonce absent and rejects replacement or introduction", async () => {
    const fixture = await createSigningFixture("key-1");
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const previous = await verifier.verify(
      await signIdToken(fixture, { nonce: "original-nonce" }),
      SESSION_CONTEXT,
    );

    await expect(
      verifier.verify(await signIdToken(fixture), {
        purpose: "refresh",
        previousIdentity: previous.identity,
      }),
    ).resolves.toMatchObject({ identity: { nonce: null } });
    await expect(
      verifier.verify(await signIdToken(fixture, { nonce: "new-nonce" }), {
        purpose: "refresh",
        previousIdentity: previous.identity,
      }),
    ).rejects.toThrow("refresh identity continuity check failed");

    const withoutNonce = await verifier.verify(
      await signIdToken(fixture),
      SESSION_CONTEXT,
    );
    await expect(
      verifier.verify(await signIdToken(fixture, { nonce: "new-nonce" }), {
        purpose: "refresh",
        previousIdentity: withoutNonce.identity,
      }),
    ).rejects.toThrow("refresh identity continuity check failed");
  });

  it("rejects auth_time introduction during refresh continuity validation", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const previous = await verifier.verify(
      await signIdToken(fixture),
      SESSION_CONTEXT,
    );

    await expect(
      verifier.verify(await signIdToken(fixture, { auth_time: now }), {
        purpose: "refresh",
        previousIdentity: previous.identity,
      }),
    ).rejects.toThrow("refresh identity continuity check failed");
  });

  it.each(REFRESH_CLAIM_CASES)(
    "returns the same signed identity for refresh and restore with %s",
    async (_name, keepNonce, keepAuthTime) => {
      const fixture = await createSigningFixture("key-1");
      const verifier = createVerifier(
        createMetadataFetch([[fixture.publicJwk]]),
      );
      const authTime = Math.floor(Date.now() / 1000) - 60;
      const original = await verifier.verify(
        await signIdToken(fixture, {
          nonce: "original-nonce",
          auth_time: authTime,
        }),
        { purpose: "authorization_code", nonce: "original-nonce" },
      );
      const raw = await signIdToken(fixture, {
        ...(keepNonce ? { nonce: "original-nonce" } : {}),
        ...(keepAuthTime ? { auth_time: authTime } : {}),
      });
      const refreshed = await verifier.verify(raw, {
        purpose: "refresh",
        previousIdentity: original.identity,
      });
      const restored = await verifier.verify(raw, SESSION_CONTEXT);

      expect(refreshed.identity).toEqual(restored.identity);
      expect(JSON.parse(JSON.stringify(refreshed.identity))).toEqual(
        restored.identity,
      );
      expect(refreshed.identity).toMatchObject({
        nonce: keepNonce ? "original-nonce" : null,
        authTime: keepAuthTime ? authTime : null,
      });
      expect(Object.isFrozen(refreshed.identity)).toBe(true);

      // The public snapshot must stay literal without losing the original
      // continuity constraints when another verified refresh omits the claims.
      const next = await verifier.verify(await signIdToken(fixture), {
        purpose: "refresh",
        previousIdentity: refreshed.identity,
      });
      await expect(
        verifier.verify(
          await signIdToken(fixture, {
            nonce: "original-nonce",
            auth_time: authTime,
          }),
          { purpose: "refresh", previousIdentity: next.identity },
        ),
      ).resolves.toMatchObject({
        identity: { nonce: "original-nonce", authTime },
      });
      for (const changed of [
        { nonce: "another-nonce" },
        { auth_time: authTime - 1 },
        { sub: "another-user" },
      ]) {
        await expect(
          verifier.verify(await signIdToken(fixture, changed), {
            purpose: "refresh",
            previousIdentity: next.identity,
          }),
        ).rejects.toThrow("refresh identity continuity check failed");
      }
    },
  );

  it.each(REFRESH_CLAIM_CASES)(
    "restores a real refreshed Core session with %s",
    async (_name, keepNonce, keepAuthTime) => {
      const fixture = await createSigningFixture("key-1");
      // Use the exact same issuer in configuration, discovery and signed tokens.
      const authority = "https://auth.example.com/";
      const authTime = Math.floor(Date.now() / 1000) - 60;
      const original = await signIdToken(fixture, {
        iss: authority,
        nonce: "original-nonce",
        auth_time: authTime,
      });
      const replacement = await signIdToken(fixture, {
        iss: authority,
        ...(keepNonce ? { nonce: "original-nonce" } : {}),
        ...(keepAuthTime ? { auth_time: authTime } : {}),
      });
      jest.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
        const url = String(input);
        if (url.endsWith("/.well-known/openid-configuration")) {
          return jsonResponse({
            issuer: authority,
            jwks_uri: `${authority}jwks`,
            id_token_signing_alg_values_supported: ["RS256"],
          });
        }
        if (url.endsWith("/jwks")) {
          return jsonResponse({ keys: [fixture.publicJwk] });
        }
        if (url.endsWith("/connect/token")) {
          return jsonResponse({
            access_token: "new-access",
            refresh_token: "rotated-refresh",
            token_type: "Bearer",
            expires_in: 3600,
            id_token: replacement,
            scope: "openid profile",
          });
        }
        throw new Error(`Unexpected test request: ${url}`);
      });
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
      const config = { authority, clientId: "client-id", storage };
      const client = new GuardhouseClient(config);
      const result = await client.refreshOidcSession("initial-refresh", {
        previousIdToken: original,
        grantedScope: "openid profile",
      });
      const expected = {
        kind: "oidc",
        idToken: replacement,
        accessToken: "new-access",
        hasRefreshToken: true,
        identity: result.identity,
      };

      expect(await client.getSessionState()).toMatchObject(expected);
      expect(
        await new GuardhouseClient(config).getSessionState(),
      ).toMatchObject(expected);
      expect(values.size).toBe(1);
    },
  );

  it("rejects structurally forged identity evidence before token verification", async () => {
    const fixture = await createSigningFixture("key-1");
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const genuine = await verifier.verify(
      await signIdToken(fixture),
      SESSION_CONTEXT,
    );
    const forgedIdentity = { ...genuine.identity } as Record<
      PropertyKey,
      unknown
    >;
    for (const symbol of Object.getOwnPropertySymbols(genuine.identity)) {
      const descriptor = Object.getOwnPropertyDescriptor(
        genuine.identity,
        symbol,
      );
      if (descriptor) Object.defineProperty(forgedIdentity, symbol, descriptor);
    }
    fetcher.mockClear();

    await expect(
      verifier.verify(await signIdToken(fixture), {
        purpose: "refresh",
        previousIdentity: forgedIdentity as unknown as OidcIdentityEvidence,
      }),
    ).rejects.toMatchObject({ code: "OIDC_CONFIGURATION_ERROR" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("accepts only explicitly allowlisted additional ID-token audiences", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      aud: ["api-a", "client-id"],
      azp: "client-id",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher).verify(token, {
        purpose: "session",
        allowedAdditionalIdTokenAudiences: ["api-a"],
      }),
    ).resolves.toMatchObject({
      identity: { audiences: ["api-a", "client-id"] },
    });
  });

  it("rejects auth_time later than token issuance", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const token = await signIdToken(fixture, {
      iat: now - 300,
      auth_time: now,
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      createVerifier(fetcher).verify(token, SESSION_CONTEXT),
    ).rejects.toThrow("auth_time must not be later than iat");
  });

  it("re-verifies an expired stored token only as historical identity", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const token = await signIdToken(fixture, {
      iat: now - 7200,
      exp: now - 3600,
      nonce: "original-nonce",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);

    await expect(
      verifyHistoricalIdTokenIdentity(token, {
        authority: "https://auth.example.com",
        clientId: "client-id",
        fetcher,
      }),
    ).resolves.toMatchObject({
      issuer: "https://auth.example.com",
      clientId: "client-id",
      subject: "user-1",
      nonce: "original-nonce",
      expiresAt: now - 3600,
    });
  });

  it("rejects a never-valid historical token before refresh network I/O", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const previousIdToken = await signIdToken(fixture, {
      iss: "https://auth.example.com/",
      iat: now - 7200,
      exp: now - 3600,
      nbf: now + 3600,
    });
    let tokenRequestCount = 0;
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input: Parameters<typeof fetch>[0]) => {
        const url = String(input);
        if (url.endsWith("/.well-known/openid-configuration")) {
          return jsonResponse({
            issuer: "https://auth.example.com/",
            jwks_uri: "https://auth.example.com/.well-known/jwks",
            id_token_signing_alg_values_supported: ["RS256"],
          });
        }
        if (url.endsWith("/.well-known/jwks")) {
          return jsonResponse({ keys: [fixture.publicJwk] });
        }
        tokenRequestCount += 1;
        return jsonResponse({
          access_token: "access-token",
          token_type: "Bearer",
          expires_in: 300,
        });
      });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    await expect(
      client.refreshOidcSession("refresh-token", { previousIdToken }),
    ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
    expect(tokenRequestCount).toBe(0);
  });

  it("does not restore an expired ID token as a current Core session", async () => {
    const fixture = await createSigningFixture("key-1");
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signIdToken(fixture, {
      iss: "https://auth.example.com/",
      iat: now - 7200,
      exp: now - 3600,
    });
    const sessionKey = `guardhouse:session:v3:${encodeURIComponent(
      "https://auth.example.com/",
    )}:${encodeURIComponent("client-id")}`;
    const records = new Map<string, string>([
      [
        sessionKey,
        JSON.stringify({
          version: 3,
          kind: "oidc",
          issuer: "https://auth.example.com/",
          clientId: "client-id",
          accessToken: "access-token",
          tokenType: "Bearer",
          expiresAt: Date.now() + 300_000,
          hasRefreshToken: true,
          idToken,
          identity: {
            issuer: "https://auth.example.com/",
            clientId: "client-id",
            subject: "user-1",
            audiences: ["client-id"],
            authorizedParty: null,
            issuedAt: now - 7200,
            expiresAt: now - 3600,
            nonce: null,
            authTime: null,
            acr: null,
            amr: [],
            sessionId: null,
          },
        }),
      ],
    ]);
    const removeItem = jest.fn(async (key: string) => {
      records.delete(key);
    });
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input: Parameters<typeof fetch>[0]) => {
        if (String(input).endsWith("/.well-known/openid-configuration")) {
          return jsonResponse({
            issuer: "https://auth.example.com/",
            jwks_uri: "https://auth.example.com/.well-known/jwks",
            id_token_signing_alg_values_supported: ["RS256"],
          });
        }
        return jsonResponse({ keys: [fixture.publicJwk] });
      });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      storage: {
        getItem: async (key) => records.get(key) ?? null,
        setItem: async (key, value) => {
          records.set(key, value);
        },
        removeItem,
      },
    });

    await expect(client.getSessionState()).resolves.toBeNull();
    expect(records.has(sessionKey)).toBe(false);
    expect(removeItem).toHaveBeenCalledWith(sessionKey);
  });

  it("rejects replayed authorization-code ID tokens when replay is enabled", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {
      nonce: "request-nonce",
      jti: "login-1",
    });
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const replayCache = new JtiReplayCache();
    const context = {
      purpose: "authorization_code" as const,
      nonce: "request-nonce",
      replayCache,
    };

    await expect(verifier.verify(token, context)).resolves.toBeDefined();
    await expect(verifier.verify(token, context)).rejects.toThrow(
      "replay was detected or cache is full",
    );
  });

  it("fails closed on mandatory identity claim violations", async () => {
    const fixture = await createSigningFixture("key-1");
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);
    const now = Math.floor(Date.now() / 1000);
    const cases: Array<{
      overrides: Record<string, unknown>;
      context?: IdTokenValidationContext;
    }> = [
      { overrides: { iss: "https://evil.example.com" } },
      { overrides: { aud: "another-client" } },
      { overrides: { aud: ["client-id", "other"], azp: "client-id" } },
      { overrides: { sub: undefined } },
      { overrides: { iat: undefined } },
      { overrides: { exp: undefined } },
      { overrides: { exp: now - 120 } },
      {
        overrides: { nonce: undefined },
        context: {
          purpose: "authorization_code",
          nonce: "expected-nonce",
        },
      },
      {
        overrides: { nonce: "wrong-nonce" },
        context: {
          purpose: "authorization_code",
          nonce: "expected-nonce",
        },
      },
    ];

    for (const testCase of cases) {
      const token = await signIdToken(fixture, testCase.overrides);
      await expect(
        verifier.verify(token, testCase.context ?? SESSION_CONTEXT),
      ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
    }
  });

  it("honors discovery signing algorithm metadata", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture, {}, { alg: "ES256" });
    const fetcher = createMetadataFetch([[fixture.publicJwk]], ["RS256"]);

    await expect(
      createVerifier(fetcher).verify(token, SESSION_CONTEXT),
    ).rejects.toThrow("not advertised");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("rejects discovery that omits mandatory ID-token signing algorithms", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const fetcher = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      if (String(input).endsWith("/.well-known/openid-configuration")) {
        return jsonResponse({
          issuer: "https://auth.example.com",
          jwks_uri: "https://auth.example.com/.well-known/jwks",
        });
      }
      return jsonResponse({ keys: [fixture.publicJwk] });
    }) as jest.MockedFunction<typeof fetch>;

    await expect(
      createVerifier(fetcher).verify(token, SESSION_CONTEXT),
    ).rejects.toMatchObject({ code: "OIDC_DISCOVERY_FAILED" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("enforces exact assurance on historical identity before refreshing", async () => {
    const fixture = await createSigningFixture("key-1");
    const previousIdToken = await signIdToken(fixture, {
      iss: "https://auth.example.com/",
      acr: "urn:guardhouse:acr:password",
      amr: ["pwd"],
    });
    let tokenRequestCount = 0;
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input: Parameters<typeof fetch>[0]) => {
        const url = String(input);
        if (url.endsWith("/.well-known/openid-configuration")) {
          return jsonResponse({
            issuer: "https://auth.example.com/",
            jwks_uri: "https://auth.example.com/.well-known/jwks",
            id_token_signing_alg_values_supported: ["RS256"],
          });
        }
        if (url.endsWith("/.well-known/jwks")) {
          return jsonResponse({ keys: [fixture.publicJwk] });
        }
        tokenRequestCount += 1;
        return jsonResponse({
          access_token: "access-token",
          token_type: "Bearer",
          expires_in: 300,
        });
      });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    await expect(
      client.refreshOidcSession("refresh-token", {
        previousIdToken,
        requiredAcrValues: ["urn:guardhouse:acr:phishing-resistant"],
        requiredAmrValues: ["hwk"],
      }),
    ).rejects.toMatchObject({ code: "ID_TOKEN_VALIDATION_FAILED" });
    expect(tokenRequestCount).toBe(0);
  });

  it("single-flights cached discovery and JWKS refresh for concurrent same-kid rotation", async () => {
    const oldFixture = await createSigningFixture("rotating-key");
    const newFixture = await createSigningFixture("rotating-key");
    const oldToken = await signIdToken(oldFixture);
    const newToken = await signIdToken(newFixture);
    const fetcher = createMetadataFetch([
      [oldFixture.publicJwk],
      [newFixture.publicJwk],
    ]);
    const verifier = createVerifier(fetcher);

    await expect(
      verifier.verify(oldToken, SESSION_CONTEXT),
    ).resolves.toMatchObject({
      payload: { sub: "user-1" },
    });
    const rotatedResults = await Promise.all([
      verifier.verify(newToken, SESSION_CONTEXT),
      verifier.verify(newToken, SESSION_CONTEXT),
    ]);
    expect(rotatedResults).toHaveLength(2);
    expect(rotatedResults[0].payload.sub).toBe("user-1");
    expect(rotatedResults[1].payload.sub).toBe("user-1");
    // Discovery remains cached; jose reloads only the remote JWKS.
    expect(fetcher).toHaveBeenCalledTimes(3);

    const parts = newToken.split(".");
    const forged = `${parts[0]}.${encodeJson({
      iss: "https://auth.example.com",
      aud: "client-id",
      sub: "attacker",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.${parts[2]}`;
    await expect(
      verifier.verify(forged, SESSION_CONTEXT),
    ).rejects.toMatchObject({
      code: "ID_TOKEN_VALIDATION_FAILED",
    });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it("reloads cached JWKS when rotation introduces a new kid", async () => {
    const oldFixture = await createSigningFixture("old-key");
    const newFixture = await createSigningFixture("new-key");
    const fetcher = createMetadataFetch([
      [oldFixture.publicJwk],
      [newFixture.publicJwk],
    ]);
    const verifier = createVerifier(fetcher);

    await expect(
      verifier.verify(await signIdToken(oldFixture), SESSION_CONTEXT),
    ).resolves.toMatchObject({ payload: { sub: "user-1" } });
    await expect(
      verifier.verify(await signIdToken(newFixture), SESSION_CONTEXT),
    ).resolves.toMatchObject({ payload: { sub: "user-1" } });
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it.each(["RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"] as const)(
    "verifies %s using the maintained JOSE algorithm implementation",
    async (algorithm) => {
      const { privateKey, publicKey } = await generateKeyPair(algorithm);
      const publicJwk = await exportJWK(publicKey);
      Object.assign(publicJwk, {
        kid: `${algorithm}-key`,
        alg: algorithm,
        use: "sig",
      });
      const token = await new SignJWT({ sub: "user-1" })
        .setProtectedHeader({ alg: algorithm, kid: `${algorithm}-key` })
        .setIssuer("https://auth.example.com")
        .setAudience("client-id")
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);
      const fetcher = createMetadataFetch(
        [[publicJwk as Record<string, unknown>]],
        Array.from(new Set(["RS256", algorithm])),
      );

      await expect(
        createVerifier(fetcher).verify(token, SESSION_CONTEXT),
      ).resolves.toMatchObject({
        payload: { sub: "user-1" },
        header: { alg: algorithm },
      });
    },
  );

  it("deduplicates concurrent discovery and JWKS requests", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const fetcher = createMetadataFetch([[fixture.publicJwk]]);
    const verifier = createVerifier(fetcher);

    await Promise.all([
      verifier.verify(token, SESSION_CONTEXT),
      verifier.verify(token, SESSION_CONTEXT),
    ]);

    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("times out a metadata request that never resolves", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const fetcher = jest.fn(() => new Promise<Response>(() => undefined));

    await expect(
      createVerifier(fetcher as unknown as jest.MockedFunction<typeof fetch>, {
        metadataRequestTimeoutMs: 5,
      }).verify(token, SESSION_CONTEXT),
    ).rejects.toMatchObject({ code: "OIDC_METADATA_REQUEST_FAILED" });
  });

  it("keeps the metadata deadline active while reading the response body", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const fetcher = jest.fn(async () => {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("{"));
        },
      });
      return new Response(body, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as jest.MockedFunction<typeof fetch>;

    await expect(
      createVerifier(fetcher, { metadataRequestTimeoutMs: 5 }).verify(
        token,
        SESSION_CONTEXT,
      ),
    ).rejects.toMatchObject({ code: "OIDC_METADATA_REQUEST_FAILED" });
  });

  it("stops reading a chunked metadata response at the size limit", async () => {
    const fixture = await createSigningFixture("key-1");
    const token = await signIdToken(fixture);
    const oversizedChunk = new Uint8Array(1024 * 1024 + 1);
    const fetcher = jest.fn(async (input: Parameters<typeof fetch>[0]) => {
      void input;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(oversizedChunk);
          controller.close();
        },
      });
      return new Response(body, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as jest.MockedFunction<typeof fetch>;

    await expect(
      createVerifier(fetcher).verify(token, SESSION_CONTEXT),
    ).rejects.toMatchObject({
      code: "OIDC_METADATA_REQUEST_FAILED",
      message: "OIDC discovery response is too large",
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
