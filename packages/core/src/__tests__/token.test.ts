import {
  decodeJWT,
  getTokenExpiresIn,
  isTokenExpired,
  JtiReplayCache,
  validateJwkMetadataForToken,
  validateOidcHashClaims,
} from "../token";
import { base64UrlDecode } from "../token/base64";
import type { UntrustedDecodedJWT } from "../token/types";

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function createJWT(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = { alg: "RS256", typ: "JWT" },
): string {
  return `${encodeJson(header)}.${encodeJson(payload)}.${Buffer.from("signature").toString("base64url")}`;
}

function decodedWithExpiration(exp: unknown): UntrustedDecodedJWT {
  return {
    header: { alg: "RS256" },
    payload: { exp } as UntrustedDecodedJWT["payload"],
  };
}

describe("untrusted JWT decoding", () => {
  afterEach(() => jest.restoreAllMocks());

  it("decodes UTF-8 values without implying verification", () => {
    const decoded = decodeJWT(createJWT({ sub: "user-1", name: "Jöhn 😀" }));
    expect(decoded.payload.name).toBe("Jöhn 😀");
  });

  it("rejects invalid Base64URL input and unsigned tokens", () => {
    expect(base64UrlDecode("")).toBe("");
    expect(() => base64UrlDecode("abc=")).toThrow("Invalid Base64URL input");
    expect(() =>
      decodeJWT(`${encodeJson({ alg: "none" })}.${encodeJson({})}.x`),
    ).toThrow('algorithm "none"');
    expect(() =>
      decodeJWT(`${encodeJson({ alg: "RS256" })}.${encodeJson({})}.`),
    ).toThrow("signature part");
  });

  it("rejects attacker-controlled unsafe keys and excessive nesting", () => {
    const unsafePayload = Buffer.from(
      '{"__proto__":{"polluted":true}}',
    ).toString("base64url");
    expect(() =>
      decodeJWT(`${encodeJson({ alg: "RS256" })}.${unsafePayload}.c2ln`),
    ).toThrow("Malformed JWT payload");
    expect(() =>
      decodeJWT(createJWT({ a: { b: { c: { d: "too deep" } } } })),
    ).toThrow("maximum nesting depth");
  });

  it("does not expose malformed token JSON in errors or logs", () => {
    const secretPayload = "TOP-SECRET-CLAIM";
    const encodedPayload = Buffer.from(secretPayload, "utf8").toString(
      "base64url",
    );
    const token = `${encodeJson({ alg: "RS256" })}.${encodedPayload}.c2ln`;
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    let caught: unknown;
    try {
      decodeJWT(token);
    } catch (error) {
      caught = error;
    }

    expect(caught).toMatchObject({
      message: "Failed to decode JWT: JWT JSON is malformed",
    });
    expect(String(caught)).not.toContain(secretPayload);
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(secretPayload);
  });
});

describe("fail-closed expiration helpers", () => {
  it.each([undefined, null, "123", Number.NaN, Number.POSITIVE_INFINITY])(
    "treats malformed exp %p as expired with no remaining lifetime",
    (exp) => {
      const decoded = decodedWithExpiration(exp);
      expect(isTokenExpired(decoded, 0)).toBe(true);
      expect(getTokenExpiresIn(decoded, 0)).toBe(0);
    },
  );

  it("treats the exact expiration boundary as expired", () => {
    const now = Math.floor(Date.now() / 1000);
    expect(isTokenExpired(decodedWithExpiration(now), 0)).toBe(true);
    expect(getTokenExpiresIn(decodedWithExpiration(now), 0)).toBe(0);
  });

  it("rejects invalid clock skew configuration", () => {
    expect(() => isTokenExpired(decodedWithExpiration(1), -1)).toThrow(
      "non-negative",
    );
    expect(() =>
      getTokenExpiresIn(decodedWithExpiration(1), Number.NaN),
    ).toThrow("non-negative");
  });
});

describe("issuer-scoped ID-token replay cache", () => {
  it("rejects a repeated issuer+jti while allowing another issuer", () => {
    const cache = new JtiReplayCache();
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const entry = { issuer: "https://issuer.example", jti: "id-1", expiresAt };

    expect(cache.consume(entry)).toBe(true);
    expect(cache.consume(entry)).toBe(false);
    expect(
      cache.consume({ ...entry, issuer: "https://other-issuer.example" }),
    ).toBe(true);
  });

  it("fails closed at capacity without evicting a live replay marker", () => {
    const cache = new JtiReplayCache({
      maxTrackedJti: 1,
      clockSkewToleranceSeconds: 0,
    });
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const first = { issuer: "https://issuer.example", jti: "id-1", expiresAt };

    expect(cache.consume(first)).toBe(true);
    expect(cache.consume({ ...first, jti: "id-2" })).toBe(false);
    expect(cache.consume(first)).toBe(false);
  });

  it("releases capacity only after the signed token expiration", () => {
    const now = 2_000_000_000;
    const nowSpy = jest.spyOn(Date, "now").mockReturnValue(now * 1000);
    const cache = new JtiReplayCache({
      maxTrackedJti: 1,
      clockSkewToleranceSeconds: 0,
    });

    expect(
      cache.consume({
        issuer: "https://issuer.example",
        jti: "id-1",
        expiresAt: now + 1,
      }),
    ).toBe(true);
    nowSpy.mockReturnValue((now + 1) * 1000);
    expect(
      cache.consume({
        issuer: "https://issuer.example",
        jti: "id-2",
        expiresAt: now + 60,
      }),
    ).toBe(true);
    nowSpy.mockRestore();
  });

  it("retains replay markers through the configured clock skew", () => {
    const now = 2_000_000_000;
    const nowSpy = jest.spyOn(Date, "now").mockReturnValue(now * 1000);
    const cache = new JtiReplayCache({
      maxTrackedJti: 1,
      clockSkewToleranceSeconds: 30,
    });
    const first = {
      issuer: "https://issuer.example",
      jti: "id-1",
      expiresAt: now + 1,
    };

    expect(cache.consume(first)).toBe(true);
    nowSpy.mockReturnValue((now + 30) * 1000);
    expect(cache.consume({ ...first, jti: "id-2", expiresAt: now + 60 })).toBe(
      false,
    );
    nowSpy.mockReturnValue((now + 31) * 1000);
    expect(cache.consume({ ...first, jti: "id-2", expiresAt: now + 60 })).toBe(
      true,
    );
    nowSpy.mockRestore();
  });

  it("rejects unbounded replay-cache clock skew", () => {
    expect(
      () => new JtiReplayCache({ clockSkewToleranceSeconds: 301 }),
    ).toThrow("between 0 and 300");
  });
});

describe("focused token metadata and hash validation", () => {
  it("requires signing-purpose JWK metadata", () => {
    expect(
      validateJwkMetadataForToken(
        {
          kid: "key-1",
          kty: "RSA",
          use: "sig",
          alg: "RS256",
          key_ops: ["verify"],
        },
        { tokenAlgorithm: "RS256", expectedKid: "key-1" },
      ).valid,
    ).toBe(true);
    expect(
      validateJwkMetadataForToken(
        { kid: "key-1", kty: "RSA" },
        { tokenAlgorithm: "RS256", expectedKid: "key-1" },
      ).valid,
    ).toBe(false);
  });

  it("rejects a mismatched OIDC token hash", async () => {
    const decoded = decodeJWT(createJWT({ at_hash: "wrong" }));
    await expect(
      validateOidcHashClaims(decoded, {
        idTokenAlg: "RS256",
        accessToken: "access-token",
        requireAtHash: true,
      }),
    ).resolves.toMatchObject({ valid: false, atHashValid: false });
  });
});
