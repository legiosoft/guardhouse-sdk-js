import {
  decodeJWT,
  getTokenExpiresIn,
  isTokenExpired,
  resetJtiReplayCache,
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
  beforeEach(() => {
    resetJtiReplayCache();
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
    });
    expect(first.valid).toBe(true);

    const second = validateToken(decoded, {
      issuer: "https://auth.example.com",
      audience: "client-id",
      signatureVerified: true,
      enforceUniqueJti: true,
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
