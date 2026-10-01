import { GuardhouseResourceService, guardhouseMiddleware } from "../middleware";
import {
  IntrospectionCredentialTransmission,
  TokenValidationMode,
  type GuardhouseResourceOptions,
} from "../types";
import { GuardhouseConstants } from "../constants";

jest.mock("jsonwebtoken");
jest.mock("jwks-rsa");

const mockJwt = require("jsonwebtoken");
const mockJwksRsa = require("jwks-rsa");

describe("GuardhouseResourceService", () => {
  let service: GuardhouseResourceService;
  const mockOptions = {
    authority: "https://auth.guardhouse.io",
    audience: "test-audience",
    validationMode: TokenValidationMode.JwtSignature,
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockJwksRsa.mockReturnValue({
      getSigningKey: jest.fn((_kid, callback) => {
        callback(null, {
          getPublicKey: jest.fn(() => "mock_public_key"),
        });
      }),
    });

    service = new GuardhouseResourceService(mockOptions);
  });

  describe("constructor", () => {
    it("should initialize with JWT signature validation mode", () => {
      expect(service).toBeDefined();
    });

    it("should not initialize JWKS client for introspection mode", () => {
      const introspectionService = new GuardhouseResourceService({
        ...mockOptions,
        validationMode: TokenValidationMode.Introspection,
      });
      expect(introspectionService).toBeDefined();
    });

    it("rejects legacy form-data introspection credentials before a request", () => {
      const legacyOptions = {
        ...mockOptions,
        validationMode: TokenValidationMode.Introspection,
        introspectionClientId: "introspection-client",
        introspectionClientSecret: "introspection-secret",
        introspectionCredentialTransmission: "form_data",
      } as unknown as GuardhouseResourceOptions;

      expect(() => new GuardhouseResourceService(legacyOptions)).toThrow(
        'only "basic_auth" is supported',
      );
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it.each([
      [["read write"]],
      [[" read"]],
      [["read\\write"]],
      [[""]],
      [["read", 42]],
    ])("rejects malformed requiredScopes %p", (requiredScopes) => {
      expect(
        () =>
          new GuardhouseResourceService({
            ...mockOptions,
            requiredScopes,
          } as unknown as GuardhouseResourceOptions),
      ).toThrow("OAuth scope tokens");
    });
  });

  describe("introspection", () => {
    it("uses Core v2 introspection with HTTP Basic credentials", async () => {
      const introspectionService = new GuardhouseResourceService({
        ...mockOptions,
        validationMode: TokenValidationMode.Introspection,
        introspectionClientId: "introspection-client",
        introspectionClientSecret: "introspection-secret",
        introspectionCredentialTransmission:
          IntrospectionCredentialTransmission.BasicAuth,
      });

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          active: true,
          sub: "user-123",
          scope: "read write",
          aud: "test-audience",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
        text: async () => "",
      } as Response);

      const user = await introspectionService.validateToken("opaque-token");

      expect(user.sub).toBe("user-123");
      expect(user.scopes).toEqual(["read", "write"]);
      const [, request] = (global.fetch as jest.Mock).mock.calls[0];
      const headers = request.headers as Headers;
      expect(headers.get("Authorization")).toBe(
        `Basic ${Buffer.from(
          "introspection-client:introspection-secret",
        ).toString("base64")}`,
      );
      expect(request.body).toContain("token=opaque-token");
      expect(request.body).not.toContain("client_secret");
      expect(request.body).not.toContain("client_id");
    });

    it("enforces every required scope on fresh and cached introspection", async () => {
      const introspectionService = new GuardhouseResourceService({
        ...mockOptions,
        validationMode: TokenValidationMode.Introspection,
        introspectionClientId: "introspection-client",
        introspectionClientSecret: "introspection-secret",
        introspectionCacheTtlSeconds: 60,
        requiredScopes: ["read", "write", "read"],
      });

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          active: true,
          sub: "user-123",
          scope: "read",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
        text: async () => "",
      } as Response);

      await expect(
        introspectionService.validateToken("partially-scoped-token"),
      ).rejects.toThrow("Token missing required scopes: write");
      await expect(
        introspectionService.validateToken("partially-scoped-token"),
      ).rejects.toThrow("Token missing required scopes: write");
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it("rejects introspection responses without required scope data", async () => {
      const introspectionService = new GuardhouseResourceService({
        ...mockOptions,
        validationMode: TokenValidationMode.Introspection,
        introspectionClientId: "introspection-client",
        introspectionClientSecret: "introspection-secret",
        requiredScopes: ["read"],
      });

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          active: true,
          sub: "user-123",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
        text: async () => "",
      } as Response);

      await expect(
        introspectionService.validateToken("unscoped-token"),
      ).rejects.toThrow("Token missing required scopes: read");
    });

    it("accepts introspection only when all exact scopes are present", async () => {
      const introspectionService = new GuardhouseResourceService({
        ...mockOptions,
        validationMode: TokenValidationMode.Introspection,
        introspectionClientId: "introspection-client",
        introspectionClientSecret: "introspection-secret",
        requiredScopes: ["read", "write"],
      });

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          active: true,
          sub: "user-123",
          scope: "write read extra",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
        text: async () => "",
      } as Response);

      await expect(
        introspectionService.validateToken("fully-scoped-token"),
      ).resolves.toMatchObject({ scopes: ["write", "read", "extra"] });
    });
  });

  describe("validateToken", () => {
    it("should validate valid JWT token", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();
      const user = await service.validateToken(token);

      expect(user.sub).toBe("user-123");
      expect(user.iss).toBe("https://auth.guardhouse.io");
      expect(user.aud).toContain("test-audience");
    });

    it("should reject token with invalid algorithm", async () => {
      const token = createMockJwtToken({ alg: "none" });

      await expect(service.validateToken(token)).rejects.toThrow(
        "Invalid algorithm",
      );
    });

    it("should reject expired token", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) - 3600,
        iat: Math.floor(Date.now() / 1000) - 7200,
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();

      await expect(service.validateToken(token)).rejects.toThrow(
        "Token has expired",
      );
    });

    it("should reject token with invalid issuer", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://evil.com",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();

      await expect(service.validateToken(token)).rejects.toThrow(
        "Invalid issuer",
      );
    });

    it("should reject token with invalid audience", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "wrong-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();

      await expect(service.validateToken(token)).rejects.toThrow(
        "Invalid audience",
      );
    });

    it("should reject token missing subject", async () => {
      const mockPayload = {
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();

      await expect(service.validateToken(token)).rejects.toThrow(
        "missing required 'sub' claim",
      );
    });

    it("should accept token with single role", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        role: "admin",
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();
      const user = await service.validateToken(token);

      expect(user.roles).toEqual(["admin"]);
    });

    it("should accept token with array roles", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        roles: ["admin", "user"],
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();
      const user = await service.validateToken(token);

      expect(user.roles).toEqual(["admin", "user"]);
    });

    it("should accept token with space-separated roles", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        roles: "admin user moderator",
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();
      const user = await service.validateToken(token);

      expect(user.roles).toEqual(["admin", "user", "moderator"]);
    });

    it("should parse scopes from token", async () => {
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        scope: "read write admin",
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();
      const user = await service.validateToken(token);

      expect(user.scopes).toEqual(["read", "write", "admin"]);
    });

    it("rejects a JWT without required scope data", async () => {
      const scopedService = new GuardhouseResourceService({
        ...mockOptions,
        requiredScopes: ["read"],
      });
      mockJwt.verify.mockReturnValue({
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      await expect(
        scopedService.validateToken(createMockJwtToken()),
      ).rejects.toThrow("Token missing required scopes: read");
    });

    it("rejects a JWT with missing or differently-cased required scopes", async () => {
      const scopedService = new GuardhouseResourceService({
        ...mockOptions,
        requiredScopes: ["read", "write"],
      });
      mockJwt.verify.mockReturnValue({
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        scope: "read Write",
      });

      await expect(
        scopedService.validateToken(createMockJwtToken()),
      ).rejects.toThrow("Token missing required scopes: write");
    });

    it("accepts a JWT only when every exact required scope is present", async () => {
      const scopedService = new GuardhouseResourceService({
        ...mockOptions,
        requiredScopes: ["read", "write", "read"],
      });
      mockJwt.verify.mockReturnValue({
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: Math.floor(Date.now() / 1000) + 3600,
        scope: "extra write read",
      });

      await expect(
        scopedService.validateToken(createMockJwtToken()),
      ).resolves.toMatchObject({ scopes: ["extra", "write", "read"] });
    });

    it("should reject token exceeding max age", async () => {
      const now = Math.floor(Date.now() / 1000);
      const mockPayload = {
        sub: "user-123",
        iss: "https://auth.guardhouse.io",
        aud: "test-audience",
        exp: now + GuardhouseConstants.Defaults.MaxTokenAgeSeconds + 1,
        iat: now,
      };

      mockJwt.verify.mockReturnValue(mockPayload);

      const token = createMockJwtToken();

      await expect(service.validateToken(token)).rejects.toThrow(
        "exceeds maximum allowed age",
      );
    });
  });
});

describe("guardhouseMiddleware", () => {
  let middleware: any;
  const mockOptions = {
    authority: "https://auth.guardhouse.io",
    audience: "test-audience",
  };

  beforeEach(() => {
    jest.clearAllMocks();

    mockJwksRsa.mockReturnValue({
      getSigningKey: jest.fn((_kid, callback) => {
        callback(null, {
          getPublicKey: jest.fn(() => "mock_public_key"),
        });
      }),
    });

    mockJwt.verify.mockReturnValue({
      sub: "user-123",
      iss: "https://auth.guardhouse.io",
      aud: "test-audience",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    });

    middleware = guardhouseMiddleware(mockOptions);
  });

  it("should add user to request for valid token", async () => {
    const mockReq = {
      headers: {
        authorization: `Bearer ${createMockJwtToken()}`,
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockReq.user).toBeDefined();
    expect(mockReq.user.sub).toBe("user-123");
    expect(mockNext).toHaveBeenCalled();
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  it("should return 401 for missing authorization header", async () => {
    const mockReq = {
      headers: {},
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.setHeader).toHaveBeenCalledWith(
      GuardhouseConstants.Headers.WwwAuthenticate,
      expect.any(String),
    );
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should return 401 for invalid token", async () => {
    mockJwt.verify.mockImplementation(() => {
      throw new Error("Invalid token");
    });

    const mockReq = {
      headers: {
        authorization: `Bearer ${createMockJwtToken()}`,
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should return 401 for malformed authorization header", async () => {
    const mockReq = {
      headers: {
        authorization: "InvalidFormat token",
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should return 400 for multiple authorization headers", async () => {
    const mockReq = {
      headers: {
        authorization: ["Bearer token1", "Bearer token2"],
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should return 400 for token exceeding max length", async () => {
    const longToken = "a".repeat(
      GuardhouseConstants.Defaults.MaxTokenLengthBytes + 1,
    );

    const mockReq = {
      headers: {
        authorization: `Bearer ${longToken}`,
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("should add correlation ID to request", async () => {
    const mockReq = {
      headers: {
        authorization: `Bearer ${createMockJwtToken()}`,
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockReq.correlationId).toBeDefined();
    expect(typeof mockReq.correlationId).toBe("string");
  });

  it("should handle case-insensitive authorization header", async () => {
    const mockReq = {
      headers: {
        Authorization: `Bearer ${createMockJwtToken()}`,
      },
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis(),
    };
    const mockNext = jest.fn();

    await middleware(mockReq, mockRes, mockNext);

    expect(mockReq.user).toBeDefined();
    expect(mockNext).toHaveBeenCalled();
  });
});

function createMockJwtToken(overrides = {}): string {
  const {
    alg = "RS256",
    typ = "JWT",
    kid = "mock-key-id",
    ...payloadOverrides
  } = overrides as Record<string, unknown>;

  const header = Buffer.from(JSON.stringify({ alg, typ, kid })).toString(
    "base64",
  );
  const payload = Buffer.from(
    JSON.stringify({
      sub: "user-123",
      iss: "https://auth.guardhouse.io",
      aud: "test-audience",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      ...payloadOverrides,
    }),
  ).toString("base64");
  const signature = "mock-signature";
  return `${header}.${payload}.${signature}`;
}
