import { GuardhouseResourceService, guardhouseMiddleware } from "../middleware";
import { TokenValidationMode } from "../types";
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
