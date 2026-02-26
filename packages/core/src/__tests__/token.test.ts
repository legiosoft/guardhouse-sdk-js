import {
  decodeJWT,
  getTokenExpiresIn,
  isTokenExpired,
  JtiReplayCache,
  validateJwkMetadataForToken,
  validateOidcHashClaims,
  validateToken,
} from "../token";
import { base64UrlDecode } from "../token/base64";

function base64UrlEncodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function base64UrlEncodeRaw(value: string): string {
  return Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function createJWT(payload: Record<string, unknown>): string {
  return createJWTWithHeader(payload, {
    alg: "RS256",
    typ: "JWT",
  });
}

function createJWTWithHeader(
  payload: Record<string, unknown>,
  headerOverrides: Record<string, unknown>,
): string {
  const header = {
    ...headerOverrides,
  };

  const signature = Buffer.from("signature", "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${base64UrlEncodeJson(header)}.${base64UrlEncodeJson(payload)}.${signature}`;
}

function createOidcHash(value: string, algorithm: string): string {
  const hashBitLength = algorithm.endsWith("384")
    ? 384
    : algorithm.endsWith("512") || algorithm === "EdDSA"
      ? 512
      : 256;
  const hash = require("crypto")
    .createHash(`sha${hashBitLength}`)
    .update(value, "utf8")
    .digest();

  return hash
    .subarray(0, hash.length / 2)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

describe("token utilities", () => {
  let jtiReplayCache: JtiReplayCache;

  beforeEach(() => {
    jtiReplayCache = new JtiReplayCache();
  });

  it("decodes UTF-8 payload values", () => {
    const token = createJWT({
      sub: "user-1",
      name: "Jöhn 😀",
    });

    const decoded = decodeJWT(token);
    expect(decoded.payload.name).toBe("Jöhn 😀");
  });

  it("decodes empty Base64URL strings safely", () => {
    expect(base64UrlDecode("")).toBe("");
  });

  it("rejects invalid Base64URL characters before decoding", () => {
    expect(() => base64UrlDecode("abc=")).toThrow("Invalid Base64URL input");
    expect(() => base64UrlDecode("abc+")).toThrow("Invalid Base64URL input");
  });

  it("marks token invalid when signature verification is not confirmed", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
    });

    expect(result.valid).toBe(false);
    expect(result.signatureVerified).toBe(false);
    expect(result.errors).toContain(
      "JWT signature has not been cryptographically verified",
    );
  });

  it("requires a mandatory non-empty subject claim", () => {
    const token = createJWT({
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "Token is missing mandatory subject (sub) claim.",
    );
  });

  it("rejects missing nonce when one is expected", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      nonce: "expected-nonce",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.nonceValid).toBe(false);
    expect(result.errors).toContain("Token is missing required nonce claim");
  });

  it("passes validation with matching claims and signatureVerified=true", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: ["client-id", "secondary"],
      azp: "client-id",
      nonce: "expected-nonce",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      nonce: "expected-nonce",
      signatureVerified: true,
    });

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("accepts verification proof objects and rejects mismatched proof metadata", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        kid: "kid-1",
      },
    );

    const decoded = decodeJWT(token);
    const validResult = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      verifiedSignature: {
        verified: true,
        algorithm: "RS256",
        kid: "kid-1",
      },
    });

    expect(validResult.valid).toBe(true);

    const invalidResult = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      verifiedSignature: {
        verified: true,
        algorithm: "RS512",
        kid: "kid-1",
      },
    });

    expect(invalidResult.valid).toBe(false);
    expect(
      invalidResult.errors.some((error) =>
        error.includes("verifiedSignature algorithm"),
      ),
    ).toBe(true);
  });

  it("verifies azp against clientId when provided", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: ["client-id", "secondary"],
      azp: "different-client",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      clientId: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.azpValid).toBe(false);
    expect(
      result.errors.some((error) =>
        error.includes('Token azp "different-client"'),
      ),
    ).toBe(true);
  });

  it("requires azp when multiple audiences are present", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: ["client-id", "secondary"],
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.azpValid).toBe(false);
    expect(result.errors).toContain(
      "azp claim is REQUIRED when multiple audiences are present (OIDC Core 3.1.3.7).",
    );
  });

  it("accepts expected audience regardless of array position", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: ["secondary", "client-id"],
      azp: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(true);
    expect(result.audienceValid).toBe(true);
  });

  it("rejects malformed audience arrays", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: ["client-id", 42],
      azp: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.audienceValid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("aud claim must be")),
    ).toBe(true);
  });

  it("rejects whitespace-only audience strings", () => {
    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: "   ",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.audienceValid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("aud claim must be")),
    ).toBe(true);
  });

  it("rejects untrusted jku origins", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        jku: "https://evil.example/.well-known/jwks.json",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      trustedJkuOrigins: ["https://auth.example.com"],
    });

    expect(result.valid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("trustedJkuOrigins")),
    ).toBe(true);
  });

  it("accepts trusted jku origins", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        jku: "https://auth.example.com/.well-known/jwks.json",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      trustedJkuOrigins: ["https://auth.example.com"],
    });

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects algorithm/key-type mismatches", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "HS256",
        typ: "JWT",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      expectedKeyType: "RSA",
    });

    expect(result.valid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("not compatible")),
    ).toBe(true);
  });

  it("rejects symmetric JWT algorithms by default", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "HS256",
        typ: "JWT",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(result.errors.some((error) => error.includes("not allowed"))).toBe(
      true,
    );
  });

  it("rejects unsupported JWT critical headers", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        crit: ["exp", "custom_ext"],
        custom_ext: true,
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      supportedCriticalHeaders: ["exp"],
    });

    expect(result.valid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("unsupported parameter")),
    ).toBe(true);
  });

  it("rejects b64 critical header parameters as unsupported", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        crit: ["b64"],
        b64: false,
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
    });

    expect(result.valid).toBe(false);
    expect(
      result.errors.some(
        (error) =>
          error.includes("unsupported parameter") && error.includes("b64"),
      ),
    ).toBe(true);
  });

  it("rejects JWTs missing signature part", () => {
    const header = Buffer.from(
      JSON.stringify({ alg: "RS256", typ: "JWT" }),
      "utf8",
    )
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const payload = Buffer.from(JSON.stringify({ sub: "user-1" }), "utf8")
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    expect(() => decodeJWT(`${header}.${payload}.`)).toThrow(
      "must contain a signature part",
    );
  });

  it("rejects padded Base64URL segments", () => {
    const validToken = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });
    const [headerPart, payloadPart, signaturePart] = validToken.split(".");

    expect(() =>
      decodeJWT(`${headerPart}=.${payloadPart}.${signaturePart}`),
    ).toThrow("invalid Base64URL");
  });

  it("rejects tokens with missing or unsafe JWT alg", () => {
    const tokenWithNone = createJWTWithHeader(
      {
        sub: "user-1",
      },
      {
        alg: "none",
        typ: "JWT",
      },
    );

    expect(() => decodeJWT(tokenWithNone)).toThrow(
      'JWT algorithm "none" is not supported for security reasons',
    );

    const tokenWithoutAlg = `${base64UrlEncodeJson({ typ: "JWT" })}.${base64UrlEncodeJson({ sub: "user-1" })}.${base64UrlEncodeRaw("sig")}`;

    expect(() => decodeJWT(tokenWithoutAlg)).toThrow(
      'JWT algorithm "none" is not supported for security reasons',
    );
  });

  it("rejects malformed JWT structures with unsafe object keys", () => {
    const tokenWithUnsafePayload = `${base64UrlEncodeJson({ alg: "RS256", typ: "JWT" })}.${base64UrlEncodeRaw('{"sub":"user-1","__proto__":{"polluted":true}}')}.${base64UrlEncodeRaw("sig")}`;

    expect(() => decodeJWT(tokenWithUnsafePayload)).toThrow(
      "Malformed JWT payload",
    );
  });

  it("requires parsed JWT header and payload to be JSON objects", () => {
    const tokenWithStringHeader = `${base64UrlEncodeRaw('"header"')}.${base64UrlEncodeJson({ sub: "user-1" })}.${base64UrlEncodeRaw("sig")}`;

    expect(() => decodeJWT(tokenWithStringHeader)).toThrow(
      "Malformed JWT header",
    );

    const tokenWithStringPayload = `${base64UrlEncodeJson({ alg: "RS256", typ: "JWT" })}.${base64UrlEncodeRaw('"payload"')}.${base64UrlEncodeRaw("sig")}`;

    expect(() => decodeJWT(tokenWithStringPayload)).toThrow(
      "Malformed JWT payload",
    );
  });

  it("rejects JWT payloads that exceed nesting depth limits", () => {
    const token = createJWT({
      sub: "user-1",
      nested: {
        level1: {
          level2: {
            level3: {
              value: "too-deep",
            },
          },
        },
      },
    });

    expect(() => decodeJWT(token)).toThrow("maximum nesting depth");
  });

  it("rejects oversized JWT payloads", () => {
    const hugePayload = "a".repeat(9000);
    const token = `${hugePayload}.${hugePayload}.${hugePayload}`;

    expect(() => decodeJWT(token)).toThrow("maximum supported length");
  });

  it("enforces required ACR values", () => {
    const token = createJWT({
      sub: "user-1",
      acr: "loa1",
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      requiredAcrValues: ["loa3"],
    });

    expect(result.valid).toBe(false);
    expect(result.acrValid).toBe(false);
  });

  it("enforces max_age with auth_time claim", () => {
    const token = createJWT({
      sub: "user-1",
      auth_time: Math.floor(Date.now() / 1000) - 500,
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      maxAgeSeconds: 60,
    });

    expect(result.valid).toBe(false);
    expect(result.authTimeValid).toBe(false);
  });

  it("rejects iat values that are too far in the future", () => {
    const token = createJWT({
      sub: "user-1",
      iat: Math.floor(Date.now() / 1000) + 120,
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      clockSkewTolerance: 30,
    });

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Token issued-at time is in the future.");
  });

  it("rejects tokens with excessive nested claim keys", () => {
    const profile: Record<string, string> = {};
    for (let index = 0; index < 101; index += 1) {
      profile[`claim_${index}`] = `value_${index}`;
    }

    const token = createJWT({
      sub: "user-1",
      iss: "https://auth.example.com",
      aud: "client-id",
      profile,
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      allowUntrustedNestedClaims: true,
    });

    expect(result.valid).toBe(false);
    expect(result.nestedClaimsTrusted).toBe(false);
    expect(
      result.errors.some((error) =>
        error.includes("maximum supported key count"),
      ),
    ).toBe(true);
  });

  it("rejects replayed jti when uniqueness is enforced", () => {
    const token = createJWT({
      sub: "user-1",
      jti: "jti-123",
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const first = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      enforceUniqueJti: true,
      jtiReplayCache,
    });
    expect(first.valid).toBe(true);

    const second = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      enforceUniqueJti: true,
      jtiReplayCache,
    });
    expect(second.valid).toBe(false);
    expect(second.jtiValid).toBe(false);
  });

  it("requires phishing-resistant MFA AMR when configured", () => {
    const token = createJWT({
      sub: "user-1",
      amr: ["pwd"],
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      requirePhishingResistantMfa: true,
    });

    expect(result.valid).toBe(false);
    expect(result.amrValid).toBe(false);
  });

  it("accepts enterprise phishing-resistant AMR values", () => {
    const token = createJWT({
      sub: "user-1",
      amr: ["mfa"],
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      requirePhishingResistantMfa: true,
    });

    expect(result.valid).toBe(true);
    expect(result.amrValid).toBe(true);
  });

  it("enforces cnf.jkt token binding when required", () => {
    const token = createJWT({
      sub: "user-1",
      cnf: { jkt: "thumbprint-1" },
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      requiredCnfJkt: "thumbprint-2",
    });

    expect(result.valid).toBe(false);
    expect(result.cnfValid).toBe(false);
  });

  it("validates at_hash and c_hash claims", async () => {
    const algorithm = "RS256";
    const accessToken = "access-token-123";
    const authorizationCode = "auth-code-123";
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        at_hash: createOidcHash(accessToken, algorithm),
        c_hash: createOidcHash(authorizationCode, algorithm),
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: algorithm,
        typ: "JWT",
      },
    );

    const decoded = decodeJWT(token);
    await expect(
      validateOidcHashClaims(decoded, {
        idTokenAlg: decoded.header.alg,
        accessToken,
        authorizationCode,
        requireAtHash: true,
        requireCHash: true,
      }),
    ).resolves.toMatchObject({
      valid: true,
      atHashValid: true,
      cHashValid: true,
    });
  });

  it("treats idTokenAlg case-insensitively for hash validation", async () => {
    const algorithm = "RS256";
    const accessToken = "access-token-123";
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        at_hash: createOidcHash(accessToken, algorithm),
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: algorithm,
        typ: "JWT",
      },
    );

    const decoded = decodeJWT(token);
    await expect(
      validateOidcHashClaims(decoded, {
        idTokenAlg: "rs256",
        accessToken,
        requireAtHash: true,
      }),
    ).resolves.toMatchObject({
      valid: true,
      atHashValid: true,
    });
  });

  it("rejects invalid at_hash values", async () => {
    const token = createJWT({
      sub: "user-1",
      at_hash: "invalid",
      iss: "https://auth.example.com",
      aud: "client-id",
      exp: Math.floor(Date.now() / 1000) + 300,
    });

    const decoded = decodeJWT(token);
    await expect(
      validateOidcHashClaims(decoded, {
        idTokenAlg: decoded.header.alg,
        accessToken: "access-token-123",
        requireAtHash: true,
      }),
    ).resolves.toMatchObject({
      valid: false,
      atHashValid: false,
    });
  });

  it("rejects at_hash values with mismatched byte lengths", async () => {
    const accessToken = "access-token-123";
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        at_hash: createOidcHash(accessToken, "RS512"),
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
      },
    );

    const decoded = decodeJWT(token);
    const result = await validateOidcHashClaims(decoded, {
      idTokenAlg: decoded.header.alg,
      accessToken,
      requireAtHash: true,
    });

    expect(result.valid).toBe(false);
    expect(result.atHashValid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("length mismatch")),
    ).toBe(true);
  });

  it("supports EdDSA through allowedAlgorithms", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "EdDSA",
        typ: "JWT",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      allowedAlgorithms: ["EdDSA"],
      expectedKeyType: "OKP",
    });

    expect(result.valid).toBe(true);
  });

  it("validates JWK metadata for signature use and algorithm binding", () => {
    const result = validateJwkMetadataForToken(
      {
        kid: "kid-1",
        kty: "RSA",
        use: "enc",
        alg: "RS512",
        key_ops: ["encrypt"],
      },
      {
        tokenAlgorithm: "RS256",
        expectedKid: "kid-1",
      },
    );

    expect(result.valid).toBe(false);
    expect(result.useValid).toBe(false);
    expect(result.algValid).toBe(false);
    expect(result.keyOpsValid).toBe(false);
  });

  it("rejects JWK metadata when both use and key_ops are missing", () => {
    const result = validateJwkMetadataForToken(
      {
        kid: "kid-1",
        kty: "RSA",
        alg: "RS256",
      },
      {
        tokenAlgorithm: "RS256",
      },
    );

    expect(result.valid).toBe(false);
    expect(result.useValid).toBe(false);
    expect(result.keyOpsValid).toBe(false);
    expect(
      result.errors.some((error) =>
        error.includes("missing both 'use' and 'key_ops'"),
      ),
    ).toBe(true);
  });

  it("supports RSA-PSS algorithms and enforces case-sensitive JWK alg", () => {
    const pssResult = validateJwkMetadataForToken(
      {
        kid: "kid-1",
        kty: "RSA",
        use: "sig",
        alg: "PS256",
        key_ops: ["verify"],
      },
      {
        tokenAlgorithm: "PS256",
      },
    );

    expect(pssResult.valid).toBe(true);

    const lowercaseAlgResult = validateJwkMetadataForToken(
      {
        kid: "kid-1",
        kty: "RSA",
        use: "sig",
        alg: "ps256",
        key_ops: ["verify"],
      },
      {
        tokenAlgorithm: "PS256",
      },
    );

    expect(lowercaseAlgResult.valid).toBe(false);
    expect(lowercaseAlgResult.algValid).toBe(false);
  });

  it("fails token validation when resolved JWK metadata is unsafe", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        kid: "kid-unsafe",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      resolvedJwk: {
        kid: "kid-unsafe",
        kty: "RSA",
        use: "enc",
        alg: "RS256",
        key_ops: ["encrypt"],
      },
    });

    expect(result.valid).toBe(false);
    expect(result.jwkMetadataValid).toBe(false);
    expect(
      result.errors.some((error) => error.includes("JWK metadata validation")),
    ).toBe(true);
  });

  it("accepts token when resolved JWK metadata is trusted", () => {
    const token = createJWTWithHeader(
      {
        sub: "user-1",
        iss: "https://auth.example.com",
        aud: "client-id",
        exp: Math.floor(Date.now() / 1000) + 300,
      },
      {
        alg: "RS256",
        typ: "JWT",
        kid: "kid-safe",
      },
    );

    const decoded = decodeJWT(token);
    const result = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      resolvedJwk: {
        kid: "kid-safe",
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        key_ops: ["verify"],
      },
    });

    expect(result.valid).toBe(true);
    expect(result.jwkMetadataValid).toBe(true);
  });

  it("throws for negative clock skew in isTokenExpired", () => {
    const token = createJWT({
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const decoded = decodeJWT(token);

    expect(() => isTokenExpired(decoded, -1)).toThrow(
      "clockSkewTolerance must be a non-negative number",
    );
  });

  it("treats exp at boundary as expired", () => {
    const nowSpy = jest.spyOn(Date, "now");

    try {
      nowSpy.mockReturnValue(1_000_000);
      const currentEpochSeconds = Math.floor(Date.now() / 1000);
      const token = createJWT({
        sub: "user-1",
        exp: currentEpochSeconds,
      });
      const decoded = decodeJWT(token);

      expect(isTokenExpired(decoded, 0)).toBe(true);

      const validation = validateToken(decoded, {
        signatureVerified: true,
        clockSkewTolerance: 0,
      });

      expect(validation.valid).toBe(false);
      expect(validation.expired).toBe(true);
      expect(validation.errors).toContain("Token has expired");
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("throws for negative clock skew in getTokenExpiresIn", () => {
    const token = createJWT({
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const decoded = decodeJWT(token);

    expect(() => getTokenExpiresIn(decoded, -1)).toThrow(
      "clockSkewTolerance must be a non-negative number",
    );
  });
});
