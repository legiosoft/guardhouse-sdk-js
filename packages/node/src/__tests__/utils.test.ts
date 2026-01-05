import {
  base64UrlEncode,
  base64UrlDecode,
  getTokenHash,
  sleep,
  sanitizeToken,
  validateHttpsUrl,
  validateTrustedAuthority,
  maskSecret,
  generateCorrelationId,
  validateJwksContentType,
  validateMaxTokenAge,
  parseErrorResponse,
  safeMerge,
  buildClaimsFromIntrospection,
  createWWWAuthenticateHeader,
  stripStackTrace,
} from "../utils";
import { GuardhouseConstants } from "../constants";

describe("Utils", () => {
  describe("base64UrlEncode", () => {
    it("should encode buffer to base64url", () => {
      const buffer = Buffer.from("test data");
      const encoded = base64UrlEncode(buffer);
      expect(encoded).toBeDefined();
      expect(typeof encoded).toBe("string");
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("should encode Uint8Array to base64url", () => {
      const array = new Uint8Array([116, 101, 115, 116]);
      const encoded = base64UrlEncode(array);
      expect(encoded).toBeDefined();
      expect(typeof encoded).toBe("string");
    });
  });

  describe("base64UrlDecode", () => {
    it("should decode base64url string to buffer", () => {
      const buffer = Buffer.from("test");
      const encoded = base64UrlEncode(buffer);
      const decoded = base64UrlDecode(encoded);
      expect(decoded.toString()).toBe("test");
    });

    it("should handle base64url with padding characters", () => {
      const encoded = "dGVzdA";
      const decoded = base64UrlDecode(encoded);
      expect(decoded.toString()).toBe("test");
    });
  });

  describe("getTokenHash", () => {
    it("should generate consistent hash for same token", () => {
      const token = "test-token";
      const hash1 = getTokenHash(token);
      const hash2 = getTokenHash(token);
      expect(hash1).toBe(hash2);
      expect(hash1).toBeDefined();
      expect(typeof hash1).toBe("string");
    });

    it("should generate different hashes for different tokens", () => {
      const hash1 = getTokenHash("token1");
      const hash2 = getTokenHash("token2");
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("sleep", () => {
    it("should resolve after specified milliseconds", async () => {
      const start = Date.now();
      await sleep(100);
      const end = Date.now();
      expect(end - start).toBeGreaterThanOrEqual(100);
      expect(end - start).toBeLessThan(200);
    });
  });

  describe("sanitizeToken", () => {
    it("should trim whitespace from token", () => {
      const token = "  test-token  ";
      const sanitized = sanitizeToken(token);
      expect(sanitized).toBe("test-token");
    });

    it("should return token as-is if no whitespace", () => {
      const token = "test-token";
      const sanitized = sanitizeToken(token);
      expect(sanitized).toBe("test-token");
    });
  });

  describe("validateHttpsUrl", () => {
    it("should accept valid HTTPS URLs", () => {
      expect(() => {
        validateHttpsUrl("https://example.com", "Test URL");
      }).not.toThrow();
    });

    it("should reject HTTP URLs", () => {
      expect(() => {
        validateHttpsUrl("http://example.com", "Test URL");
      }).toThrow("URL must use HTTPS");
    });

    it("should reject invalid URLs", () => {
      expect(() => {
        validateHttpsUrl("not-a-url", "Test URL");
      }).toThrow();
    });
  });

  describe("validateTrustedAuthority", () => {
    it("should accept matching hostnames", () => {
      expect(() => {
        validateTrustedAuthority(
          "https://example.com/.well-known/jwks",
          "https://example.com",
        );
      }).not.toThrow();
    });

    it("should reject mismatched hostnames", () => {
      expect(() => {
        validateTrustedAuthority(
          "https://evil.com/.well-known/jwks",
          "https://example.com",
        );
      }).toThrow("does not match configured authority");
    });
  });

  describe("maskSecret", () => {
    it("should mask short secrets", () => {
      const secret = "short";
      const masked = maskSecret(secret);
      expect(masked).toBe("********");
    });

    it("should mask long secrets showing first and last 4 chars", () => {
      const secret = "my-very-long-secret-key-here";
      const masked = maskSecret(secret);
      expect(masked).toBe("my-v****here");
    });

    it("should handle exactly 8 character secrets", () => {
      const secret = "12345678";
      const masked = maskSecret(secret);
      expect(masked).toBe("********");
    });
  });

  describe("generateCorrelationId", () => {
    it("should generate unique correlation IDs", () => {
      const id1 = generateCorrelationId();
      const id2 = generateCorrelationId();
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^gh_\d+_[a-f0-9]{16}$/);
    });
  });

  describe("validateJwksContentType", () => {
    it("should accept application/json", () => {
      expect(() => {
        validateJwksContentType(GuardhouseConstants.ContentTypes.Json);
      }).not.toThrow();
    });

    it("should accept application/jwk-set+json", () => {
      expect(() => {
        validateJwksContentType(GuardhouseConstants.ContentTypes.JwkSet);
      }).not.toThrow();
    });

    it("should reject invalid content types", () => {
      expect(() => {
        validateJwksContentType("text/plain");
      }).toThrow("Invalid JWKS response Content-Type");
    });
  });

  describe("validateMaxTokenAge", () => {
    it("should accept tokens within max age", () => {
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 3600;
      const maxAge = 86400;
      expect(() => {
        validateMaxTokenAge(exp, maxAge);
      }).not.toThrow();
    });

    it("should reject tokens exceeding max age", () => {
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 86400 + 1;
      const maxAge = 86400;
      expect(() => {
        validateMaxTokenAge(exp, maxAge);
      }).toThrow("exceeds maximum allowed age");
    });
  });

  describe("parseErrorResponse", () => {
    it("should parse valid JSON error response", () => {
      const response = JSON.stringify({
        error: "invalid_grant",
        error_description: "Invalid credentials",
      });
      const parsed = parseErrorResponse(response);
      expect(parsed).toContain("invalid_grant");
      expect(parsed).toContain("Invalid credentials");
    });

    it("should parse error without description", () => {
      const response = JSON.stringify({ error: "access_denied" });
      const parsed = parseErrorResponse(response);
      expect(parsed).toContain("access_denied");
    });

    it("should return generic message for invalid JSON", () => {
      const parsed = parseErrorResponse("not valid json");
      expect(parsed).toBe("Authentication failed");
    });

    it("should return generic message for missing error field", () => {
      const parsed = parseErrorResponse(JSON.stringify({ message: "test" }));
      expect(parsed).toBe("Authentication failed");
    });
  });

  describe("safeMerge", () => {
    it("should merge source into target", () => {
      const target = { a: 1, b: 2 };
      const source = { b: 3, c: 4 };
      const result = safeMerge(target, source);
      expect(result).toEqual({ a: 1, b: 3, c: 4 });
    });

    it("should not mutate original target", () => {
      const target = { a: 1 };
      const source = { b: 2 };
      const result = safeMerge(target, source);
      expect(target).toEqual({ a: 1 });
      expect(result).toEqual({ a: 1, b: 2 });
    });

    it("should handle empty source", () => {
      const target = { a: 1 };
      const source = {};
      const result = safeMerge(target, source);
      expect(result).toEqual({ a: 1 });
    });
  });

  describe("buildClaimsFromIntrospection", () => {
    it("should build claims from introspection result", () => {
      const introspectionResult = {
        sub: "user-123",
        username: "testuser",
        email: "test@example.com",
        scope: "read write",
        client_id: "client-123",
        aud: "api-audience",
        iss: "https://auth.example.com",
        jti: "token-123",
        exp: 1234567890,
        iat: 1234560000,
        nbf: 1234560000,
        role: "admin",
      };

      const claims = buildClaimsFromIntrospection(introspectionResult);

      expect(claims.sub).toBe("user-123");
      expect(claims.username).toBe("testuser");
      expect(claims.name).toBe("testuser");
      expect(claims.email).toBe("test@example.com");
      expect(claims.scopes).toEqual(["read", "write"]);
      expect(claims.clientId).toBe("client-123");
      expect(claims.aud).toEqual(["api-audience"]);
      expect(claims.roles).toEqual(["admin"]);
    });

    it("should handle array roles", () => {
      const introspectionResult = {
        sub: "user-123",
        role: ["admin", "user"],
      };

      const claims = buildClaimsFromIntrospection(introspectionResult);

      expect(claims.roles).toEqual(["admin", "user"]);
    });

    it("should handle space-separated roles string", () => {
      const introspectionResult = {
        sub: "user-123",
        roles: "admin user moderator",
      };

      const claims = buildClaimsFromIntrospection(introspectionResult);

      expect(claims.roles).toEqual(["admin", "user", "moderator"]);
    });

    it("should return empty arrays when no roles or scopes", () => {
      const introspectionResult = {
        sub: "user-123",
      };

      const claims = buildClaimsFromIntrospection(introspectionResult);

      expect(claims.roles).toBeUndefined();
      expect(claims.scopes).toBeUndefined();
    });
  });

  describe("createWWWAuthenticateHeader", () => {
    it("should create basic WWW-Authenticate header", () => {
      const header = createWWWAuthenticateHeader("test-realm");
      expect(header).toBe('Bearer realm="test-realm"');
    });

    it("should create header with error", () => {
      const header = createWWWAuthenticateHeader("test-realm", "invalid_token");
      expect(header).toContain('realm="test-realm"');
      expect(header).toContain('error="invalid_token"');
    });

    it("should create header with error and description", () => {
      const header = createWWWAuthenticateHeader(
        "test-realm",
        "invalid_token",
        "Token expired",
      );
      expect(header).toContain('realm="test-realm"');
      expect(header).toContain('error="invalid_token"');
      expect(header).toContain('error_description="Token expired"');
    });
  });

  describe("stripStackTrace", () => {
    it("should strip stack trace from error", () => {
      const error = new Error("Test error");
      const stripped = stripStackTrace(error);
      expect(stripped).toBe("Test error");
    });

    it("should handle error without message", () => {
      const error = new Error();
      const stripped = stripStackTrace(error);
      expect(stripped).toBeDefined();
    });
  });
});
