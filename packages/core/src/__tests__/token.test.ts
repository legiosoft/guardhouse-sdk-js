import {
  decodeJWT,
  getTokenExpiresIn,
  isTokenExpired,
  validateToken,
} from "../token";

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

describe("token utilities", () => {
  it("decodes UTF-8 payload values", () => {
    const token = createJWT({
      sub: "user-1",
      name: "Jöhn 😀",
    });

    const decoded = decodeJWT(token);
    expect(decoded.payload.name).toBe("Jöhn 😀");
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

  it("rejects oversized JWT payloads", () => {
    const hugePayload = "a".repeat(9000);
    const token = `${hugePayload}.${hugePayload}.${hugePayload}`;

    expect(() => decodeJWT(token)).toThrow("maximum supported length");
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
