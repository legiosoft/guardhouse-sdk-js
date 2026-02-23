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
  const header = {
    alg: "RS256",
    typ: "JWT",
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
