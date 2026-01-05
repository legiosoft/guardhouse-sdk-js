import { GuardhouseConstants } from "../constants";

describe("GuardhouseConstants", () => {
  describe("Endpoints", () => {
    it("should have all required endpoints", () => {
      expect(GuardhouseConstants.Endpoints).toBeDefined();
      expect(GuardhouseConstants.Endpoints.WellKnownOpenIdConfiguration).toBe(
        ".well-known/openid-configuration",
      );
      expect(GuardhouseConstants.Endpoints.WellKnownJwks).toBe(
        ".well-known/jwks.json",
      );
      expect(GuardhouseConstants.Endpoints.ConnectToken).toBe("connect/token");
      expect(GuardhouseConstants.Endpoints.ConnectIntrospect).toBe(
        "connect/introspect",
      );
      expect(GuardhouseConstants.Endpoints.ConnectAuthorize).toBe(
        "connect/authorize",
      );
    });
  });

  describe("Algorithms", () => {
    it("should have all required algorithms", () => {
      expect(GuardhouseConstants.Algorithms).toBeDefined();
      expect(GuardhouseConstants.Algorithms.RS256).toBe("RS256");
      expect(GuardhouseConstants.Algorithms.RS384).toBe("RS384");
      expect(GuardhouseConstants.Algorithms.RS512).toBe("RS512");
      expect(GuardhouseConstants.Algorithms.ES256).toBe("ES256");
      expect(GuardhouseConstants.Algorithms.ES384).toBe("ES384");
      expect(GuardhouseConstants.Algorithms.ES512).toBe("ES512");
      expect(GuardhouseConstants.Algorithms.PS256).toBe("PS256");
      expect(GuardhouseConstants.Algorithms.PS384).toBe("PS384");
      expect(GuardhouseConstants.Algorithms.PS512).toBe("PS512");
      expect(GuardhouseConstants.Algorithms.None).toBe("none");
    });
  });

  describe("TokenTypes", () => {
    it("should have all required token types", () => {
      expect(GuardhouseConstants.TokenTypes).toBeDefined();
      expect(GuardhouseConstants.TokenTypes.Jwt).toBe("JWT");
      expect(GuardhouseConstants.TokenTypes.AtJwt).toBe("at+jwt");
    });
  });

  describe("Headers", () => {
    it("should have all required headers", () => {
      expect(GuardhouseConstants.Headers).toBeDefined();
      expect(GuardhouseConstants.Headers.Authorization).toBe("Authorization");
      expect(GuardhouseConstants.Headers.BearerPrefix).toBe("Bearer ");
      expect(GuardhouseConstants.Headers.WwwAuthenticate).toBe(
        "WWW-Authenticate",
      );
      expect(GuardhouseConstants.Headers.ContentType).toBe("Content-Type");
    });
  });

  describe("JwtClaims", () => {
    it("should have all required JWT claims", () => {
      expect(GuardhouseConstants.JwtClaims).toBeDefined();
      expect(GuardhouseConstants.JwtClaims.Type).toBe("typ");
      expect(GuardhouseConstants.JwtClaims.Algorithm).toBe("alg");
      expect(GuardhouseConstants.JwtClaims.KeyId).toBe("kid");
      expect(GuardhouseConstants.JwtClaims.Issuer).toBe("iss");
      expect(GuardhouseConstants.JwtClaims.Audience).toBe("aud");
      expect(GuardhouseConstants.JwtClaims.Subject).toBe("sub");
      expect(GuardhouseConstants.JwtClaims.Expiration).toBe("exp");
      expect(GuardhouseConstants.JwtClaims.IssuedAt).toBe("iat");
      expect(GuardhouseConstants.JwtClaims.NotBefore).toBe("nbf");
      expect(GuardhouseConstants.JwtClaims.JwtId).toBe("jti");
      expect(GuardhouseConstants.JwtClaims.Scope).toBe("scope");
      expect(GuardhouseConstants.JwtClaims.ClientId).toBe("client_id");
      expect(GuardhouseConstants.JwtClaims.TokenType).toBe("token_type");
      expect(GuardhouseConstants.JwtClaims.AuthorizedParty).toBe("azp");
    });
  });

  describe("Defaults", () => {
    it("should have all required defaults", () => {
      expect(GuardhouseConstants.Defaults).toBeDefined();
      expect(GuardhouseConstants.Defaults.JwksCacheDurationHours).toBe(24);
      expect(GuardhouseConstants.Defaults.JwksRefreshIntervalMinutes).toBe(5);
      expect(GuardhouseConstants.Defaults.CacheExpirationBufferSeconds).toBe(
        60,
      );
      expect(GuardhouseConstants.Defaults.RequestTimeoutSeconds).toBe(30);
      expect(GuardhouseConstants.Defaults.MaxRetryAttempts).toBe(3);
      expect(GuardhouseConstants.Defaults.ClockSkewMinutes).toBe(5);
      expect(GuardhouseConstants.Defaults.DefaultScope).toBe("api");
      expect(GuardhouseConstants.Defaults.IntrospectionCacheTtlSeconds).toBe(5);
      expect(GuardhouseConstants.Defaults.MaxTokenLengthBytes).toBe(8192);
      expect(GuardhouseConstants.Defaults.MaxTokenAgeSeconds).toBe(31536000);
    });
  });

  describe("Validation", () => {
    it("should have all validation flags set to true", () => {
      expect(GuardhouseConstants.Validation).toBeDefined();
      expect(GuardhouseConstants.Validation.ValidateIssuer).toBe(true);
      expect(GuardhouseConstants.Validation.ValidateAudience).toBe(true);
      expect(GuardhouseConstants.Validation.ValidateLifetime).toBe(true);
      expect(GuardhouseConstants.Validation.ValidateIssuerSigningKey).toBe(
        true,
      );
    });
  });

  describe("ContentTypes", () => {
    it("should have all required content types", () => {
      expect(GuardhouseConstants.ContentTypes).toBeDefined();
      expect(GuardhouseConstants.ContentTypes.Json).toBe("application/json");
      expect(GuardhouseConstants.ContentTypes.JwkSet).toBe(
        "application/jwk-set+json",
      );
    });
  });

  describe("Schemes", () => {
    it("should have all required schemes", () => {
      expect(GuardhouseConstants.Schemes).toBeDefined();
      expect(GuardhouseConstants.Schemes.Https).toBe("https:");
      expect(GuardhouseConstants.Schemes.Http).toBe("http:");
    });
  });

  describe("ErrorMessages", () => {
    it("should have all required error messages", () => {
      expect(GuardhouseConstants.ErrorMessages).toBeDefined();
      expect(GuardhouseConstants.ErrorMessages.GenericUnauthorized).toBe(
        "Unauthorized",
      );
      expect(GuardhouseConstants.ErrorMessages.InvalidToken).toBe(
        "Invalid or expired token",
      );
      expect(GuardhouseConstants.ErrorMessages.MissingAuthorization).toBe(
        "Authorization header is required",
      );
    });
  });
});
